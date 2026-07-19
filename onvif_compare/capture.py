"""Capture backends for the ONVIF PullPoint Forensic Comparator.

Two modes
---------
``RemoteCapture``
    SSHes to the UDM Pro (or any Linux host), starts ``tcpdump``, downloads
    the PCAP via SFTP, and deletes the remote file.  This is the primary
    supported mode.

``LocalCapture``
    Runs ``tcpdump`` on the local machine.  Useful for lab setups where the
    analysis machine is on the same segment as the camera.

Both classes implement the ``CaptureBackend`` protocol so the analysis engine
never needs to know which mode is active.

Interface discovery
-------------------
If ``--interface`` is omitted the backend SSHes in and runs ``ip -brief link``
to list available interfaces.  If exactly one bridge (``br*``) is found it is
selected automatically.  If multiple bridges exist the tool prints them and
exits with a clear error.

tcpdump check
-------------
Before starting a capture the backend runs ``which tcpdump`` on the target
host.  If tcpdump is absent it raises ``CaptureError`` with an actionable
message.

Run isolation
-------------
Each capture run uses a UUID-based remote directory so concurrent runs and
stale files from abandoned captures never collide:

    /tmp/onvif-compare-<uuid>/capture.pcap
    /tmp/onvif-compare-<uuid>/tcpdump.pid
    /tmp/onvif-compare-<uuid>/tcpdump.log
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class CaptureError(Exception):
    """Raised when a capture cannot be started or completed."""


# ---------------------------------------------------------------------------
# Protocol / base class
# ---------------------------------------------------------------------------


class CaptureBackend(ABC):
    """Abstract base for capture backends.

    Subclasses must implement ``start()``, ``stop()``, and ``download()``.
    The analysis engine calls them in that order.
    """

    @abstractmethod
    def start(self) -> None:
        """Start the capture.  Must not block."""

    @abstractmethod
    def stop(self) -> None:
        """Stop the capture gracefully."""

    @abstractmethod
    def download(self, local_path: Path) -> None:
        """Download (or move) the PCAP to *local_path*."""

    def __enter__(self) -> "CaptureBackend":
        self.start()
        return self

    def __exit__(self, *_) -> None:
        self.stop()


# ---------------------------------------------------------------------------
# Remote capture (SSH → UDM Pro)
# ---------------------------------------------------------------------------


@dataclass
class RemoteCaptureConfig:
    """Configuration for ``RemoteCapture``."""

    ssh_host: str
    ssh_port: int
    ssh_user: str
    camera_ip: str
    camera_port: int
    interface: Optional[str]          # None → auto-discover
    ssh_password: Optional[str] = None
    ssh_key: Optional[str] = None
    keep_remote: bool = False
    # Remote paths are derived from a per-run UUID in RemoteCapture.__init__
    # and stored here so download() can reference them after stop().
    remote_dir: str = ""
    remote_pcap_path: str = ""
    remote_pid_path: str = ""
    remote_log_path: str = ""


class RemoteCapture(CaptureBackend):
    """Capture traffic on a remote host via SSH + tcpdump.

    Parameters
    ----------
    config:
        ``RemoteCaptureConfig`` instance.

    Usage::

        with RemoteCapture(config) as cap:
            time.sleep(60)
        cap.download(Path("capture.pcap"))
    """

    def __init__(self, config: RemoteCaptureConfig) -> None:
        self._cfg = config
        # Assign UUID-based remote paths so concurrent runs never collide.
        run_id = uuid.uuid4().hex[:12]
        remote_dir = f"/tmp/onvif-compare-{run_id}"
        self._cfg.remote_dir = remote_dir
        self._cfg.remote_pcap_path = f"{remote_dir}/capture.pcap"
        self._cfg.remote_pid_path = f"{remote_dir}/tcpdump.pid"
        self._cfg.remote_log_path = f"{remote_dir}/tcpdump.log"
        self._client = None
        self._pid: Optional[int] = None
        self._interface: Optional[str] = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Connect via SSH, discover interface if needed, start tcpdump."""
        self._client = self._connect()
        self._check_tcpdump()
        self._interface = self._cfg.interface or self._discover_interface()
        self._pid = self._start_tcpdump()
        log.info(
            "Remote tcpdump started on %s:%s (PID %s, interface %s)",
            self._cfg.ssh_host,
            self._cfg.ssh_port,
            self._pid,
            self._interface,
        )

    def stop(self) -> None:
        """Send SIGINT to tcpdump and wait for it to flush."""
        if self._pid and self._client:
            self._remote_cmd(
                f"kill -INT {self._pid} 2>/dev/null || true; sleep 2",
                check=False,
            )
            log.info("Remote tcpdump stopped (PID %s)", self._pid)

    def download(self, local_path: Path) -> None:
        """Download the PCAP via SFTP and optionally delete the remote copy."""
        if self._client is None:
            raise CaptureError("SSH client is not connected")

        import paramiko  # imported here so the module loads without paramiko

        sftp = self._client.open_sftp()
        try:
            sftp.get(self._cfg.remote_pcap_path, str(local_path))
            log.info("PCAP downloaded to %s", local_path)
        finally:
            sftp.close()

        if not self._cfg.keep_remote:
            self._remote_cmd(
                f"rm -rf {self._cfg.remote_dir}",
                check=False,
            )

        if self._client:
            self._client.close()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _connect(self):
        try:
            import paramiko
        except ImportError as exc:
            raise CaptureError(
                "paramiko is required for remote capture.\n"
                "Install it with:  pip install paramiko"
            ) from exc

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = dict(
            hostname=self._cfg.ssh_host,
            port=self._cfg.ssh_port,
            username=self._cfg.ssh_user,
            timeout=15,
            banner_timeout=15,
            auth_timeout=15,
            allow_agent=True,
            look_for_keys=self._cfg.ssh_password is None and self._cfg.ssh_key is None,
        )
        if self._cfg.ssh_password:
            kwargs["password"] = self._cfg.ssh_password
            kwargs["look_for_keys"] = False
        if self._cfg.ssh_key:
            kwargs["key_filename"] = self._cfg.ssh_key

        try:
            client.connect(**kwargs)
        except Exception as exc:
            raise CaptureError(f"SSH connection failed: {exc}") from exc

        return client

    def _remote_cmd(self, command: str, *, check: bool = True) -> str:
        _, stdout, stderr = self._client.exec_command(command)
        code = stdout.channel.recv_exit_status()
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        if check and code != 0:
            raise CaptureError(
                f"Remote command failed (exit {code}): {command}\n{out}\n{err}"
            )
        return out

    def _check_tcpdump(self) -> None:
        out = self._remote_cmd("which tcpdump 2>/dev/null || echo MISSING", check=False)
        if "MISSING" in out or not out.strip():
            raise CaptureError(
                "tcpdump not found on the remote host.\n"
                "Please install tcpdump or use --capture local."
            )

    def _discover_interface(self) -> str:
        """Run ``ip -brief link`` and auto-select a bridge interface."""
        out = self._remote_cmd("ip -brief link 2>/dev/null || ip link", check=False)
        interfaces = _parse_ip_brief(out)
        bridges = [i for i in interfaces if i.startswith("br")]

        if not bridges:
            raise CaptureError(
                "No bridge interfaces found on the remote host.\n"
                f"Available interfaces: {', '.join(interfaces) or 'none'}\n"
                "Specify --interface explicitly."
            )
        if len(bridges) == 1:
            log.info("Auto-selected interface: %s", bridges[0])
            return bridges[0]

        raise CaptureError(
            f"Multiple bridge interfaces found on {self._cfg.ssh_host}:\n"
            + "".join(f"  {b}\n" for b in sorted(bridges))
            + "\nAdd --interface <name> to your command, e.g.:\n"
            + f"  --interface {sorted(bridges)[0]}"
        )

    def _start_tcpdump(self) -> int:
        cfg = self._cfg
        capture_filter = (
            f"host {cfg.camera_ip} and tcp port {cfg.camera_port}"
        )
        command = (
            f"mkdir -p {cfg.remote_dir}; "
            f"nohup tcpdump -U -i {self._interface} -nn -s0 "
            f"-w {cfg.remote_pcap_path} "
            f"'{capture_filter}' "
            f">{cfg.remote_log_path} 2>&1 & "
            f"echo $! > {cfg.remote_pid_path}; cat {cfg.remote_pid_path}"
        )
        out = self._remote_cmd(command)
        try:
            return int(out.strip())
        except ValueError as exc:
            raise CaptureError(
                f"Could not parse tcpdump PID from: {out!r}"
            ) from exc


# ---------------------------------------------------------------------------
# Local capture
# ---------------------------------------------------------------------------


@dataclass
class LocalCaptureConfig:
    """Configuration for ``LocalCapture``."""

    camera_ip: str
    camera_port: int
    interface: Optional[str]          # None → auto-discover via ip link
    local_pcap_path: str = "/tmp/onvif_compare_local.pcap"


class LocalCapture(CaptureBackend):
    """Capture traffic on the local machine using a subprocess tcpdump.

    Useful for lab setups where the analysis machine is on the same network
    segment as the camera.
    """

    def __init__(self, config: LocalCaptureConfig) -> None:
        self._cfg = config
        self._proc: Optional[subprocess.Popen] = None
        self._interface: Optional[str] = None

    def start(self) -> None:
        self._check_tcpdump()
        self._interface = self._cfg.interface or self._discover_interface()
        self._proc = self._start_tcpdump()
        log.info(
            "Local tcpdump started (PID %s, interface %s)",
            self._proc.pid,
            self._interface,
        )

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.send_signal(2)  # SIGINT
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            log.info("Local tcpdump stopped")

    def download(self, local_path: Path) -> None:
        """Move the local PCAP to *local_path*."""
        src = Path(self._cfg.local_pcap_path)
        if not src.exists():
            raise CaptureError(f"Local PCAP not found: {src}")
        src.rename(local_path)
        log.info("PCAP moved to %s", local_path)

    def _check_tcpdump(self) -> None:
        if not shutil.which("tcpdump"):
            raise CaptureError(
                "tcpdump not found on this machine.\n"
                "Install it (e.g. sudo apt install tcpdump) or use --capture remote."
            )

    def _discover_interface(self) -> str:
        """List local interfaces and auto-select a bridge."""
        try:
            result = subprocess.run(
                ["ip", "-brief", "link"],
                capture_output=True, text=True, timeout=5,
            )
            interfaces = _parse_ip_brief(result.stdout)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            interfaces = []

        bridges = [i for i in interfaces if i.startswith("br")]
        if not bridges:
            raise CaptureError(
                "No bridge interfaces found locally.\n"
                f"Available: {', '.join(interfaces) or 'none'}\n"
                "Specify --interface explicitly."
            )
        if len(bridges) == 1:
            return bridges[0]
        raise CaptureError(
            f"Multiple bridge interfaces: {', '.join(bridges)}\n"
            "Specify --interface explicitly."
        )

    def _start_tcpdump(self) -> subprocess.Popen:
        cfg = self._cfg
        capture_filter = f"host {cfg.camera_ip} and tcp port {cfg.camera_port}"
        cmd = [
            "tcpdump",
            "-U", "-i", self._interface,
            "-nn", "-s0",
            "-w", cfg.local_pcap_path,
            capture_filter,
        ]
        return subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _parse_ip_brief(output: str) -> List[str]:
    """Extract interface names from ``ip -brief link`` output.

    Each line looks like::

        lo               UNKNOWN        127.0.0.1/8
        eth0             UP             192.168.1.5/24
        br554            UP             10.54.4.1/24

    Returns the list of interface names, excluding ``lo``.
    """
    names: List[str] = []
    for line in output.splitlines():
        parts = line.split()
        if not parts:
            continue
        name = parts[0].split("@")[0]  # strip @ifname suffix on some kernels
        if name and name != "lo":
            names.append(name)
    return names


def build_remote_capture(
    *,
    ssh_host: str,
    ssh_port: int = 22,
    ssh_user: str = "root",
    ssh_password: Optional[str] = None,
    ssh_key: Optional[str] = None,
    camera_ip: str,
    camera_port: int = 8000,
    interface: Optional[str] = None,
    keep_remote: bool = False,
) -> RemoteCapture:
    """Convenience factory for ``RemoteCapture``."""
    return RemoteCapture(RemoteCaptureConfig(
        ssh_host=ssh_host,
        ssh_port=ssh_port,
        ssh_user=ssh_user,
        ssh_password=ssh_password,
        ssh_key=ssh_key,
        camera_ip=camera_ip,
        camera_port=camera_port,
        interface=interface,
        keep_remote=keep_remote,
    ))


def build_local_capture(
    *,
    camera_ip: str,
    camera_port: int = 8000,
    interface: Optional[str] = None,
    local_pcap_path: str = "/tmp/onvif_compare_local.pcap",
) -> LocalCapture:
    """Convenience factory for ``LocalCapture``."""
    return LocalCapture(LocalCaptureConfig(
        camera_ip=camera_ip,
        camera_port=camera_port,
        interface=interface,
        local_pcap_path=local_pcap_path,
    ))
