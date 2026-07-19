"""Entry point for the ONVIF PullPoint Forensic Comparator.

Subcommands
-----------
capture
    SSH to the UDM Pro (or run locally), start tcpdump, subscribe to the
    camera's PullPoint independently, wait for the requested duration,
    download the PCAP, analyse it, and write the evidence bundle.

analyse
    Offline analysis of an existing PCAP.  No camera connection required.
    Requires --pcap, --camera-ip, and --protect-ip.

report
    Regenerate report.md and report.html from an existing evidence.json.
    Useful for re-running the report renderer after a code change.
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import sys
import time
from pathlib import Path
from typing import List, Optional

from . import __version__
from .capture import CaptureError, build_local_capture, build_remote_capture
from .models import (
    CaptureMetadata,
    EvidenceBundle,
    EventSource,
    MotionEvent,
    SoapFault,
    SubscriptionEvent,
)
from .onvif_client import OnvifSubscriber, SubscriberConfig
from .pcap import extract_transactions, reconstruct_streams
from .report import ReportWriter, bundle_to_json
from .timeline import build_observations, build_timeline, correlate
from .util import format_utc, local_ip_for, sha256_file, utc_now

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="onvif-compare",
        description="ONVIF PullPoint Forensic Comparator v" + __version__,
    )
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: WARNING)",
    )

    sub = p.add_subparsers(dest="command", required=True)

    # ------------------------------------------------------------------
    # capture
    # ------------------------------------------------------------------
    cap = sub.add_parser("capture", help="Capture and analyse live traffic")

    cap.add_argument("--camera-ip", required=True, help="ONVIF camera IP address")
    cap.add_argument("--camera-port", type=int, default=8000, help="ONVIF port (default: 8000)")
    cap.add_argument("--camera-user", default="admin", help="ONVIF username (default: admin)")
    cap.add_argument("--camera-password", help="ONVIF password (prompted if omitted)")

    cap.add_argument("--protect-ip", default="10.54.4.1", help="UniFi Protect IP (default: 10.54.4.1)")

    cap.add_argument(
        "--capture",
        choices=["remote", "local"],
        default="remote",
        help="Capture mode: remote (SSH to UDM Pro) or local (default: remote)",
    )

    # Remote capture options
    cap.add_argument("--ssh-host", help="SSH host for remote capture (required for --capture remote)")
    cap.add_argument("--ssh-port", type=int, default=22, help="SSH port (default: 22)")
    cap.add_argument("--ssh-user", default="root", help="SSH username (default: root)")
    cap.add_argument("--ssh-key", help="Path to SSH private key")
    cap.add_argument("--ssh-password", action="store_true", help="Prompt for SSH password")
    cap.add_argument("--keep-remote", action="store_true", help="Do not delete remote PCAP after download")

    cap.add_argument("--interface", help="Network interface for tcpdump (auto-detected if omitted)")
    cap.add_argument("--duration", type=int, default=60, help="Capture duration in seconds (default: 60)")
    cap.add_argument("--correlation-window", type=int, default=1000, help="Correlation window in ms (default: 1000)")
    cap.add_argument("--output-dir", type=Path, help="Evidence output directory (auto-named if omitted)")

    # ------------------------------------------------------------------
    # analyse
    # ------------------------------------------------------------------
    ana = sub.add_parser("analyse", help="Analyse an existing PCAP (no camera required)")

    ana.add_argument("--pcap", required=True, type=Path, help="Path to PCAP file")
    ana.add_argument("--camera-ip", required=True, help="ONVIF camera IP address")
    ana.add_argument("--protect-ip", required=True, help="UniFi Protect IP address")
    ana.add_argument("--local-ip", help="Local subscriber IP (if known)")
    ana.add_argument("--correlation-window", type=int, default=1000, help="Correlation window in ms (default: 1000)")
    ana.add_argument("--output-dir", type=Path, help="Evidence output directory (auto-named if omitted)")

    # ------------------------------------------------------------------
    # report
    # ------------------------------------------------------------------
    rep = sub.add_parser("report", help="Regenerate report from evidence.json")
    rep.add_argument("--evidence", required=True, type=Path, help="Path to evidence.json")
    rep.add_argument("--output-dir", type=Path, help="Output directory (defaults to evidence.json directory)")

    return p


# ---------------------------------------------------------------------------
# Subcommand implementations
# ---------------------------------------------------------------------------


def _cmd_capture(args: argparse.Namespace) -> int:
    camera_password = args.camera_password or getpass.getpass("Camera ONVIF password: ")

    ssh_password: Optional[str] = None
    if args.capture == "remote":
        if not args.ssh_host:
            print("ERROR: --ssh-host is required for --capture remote", file=sys.stderr)
            return 1
        if args.ssh_password:
            ssh_password = getpass.getpass(f"SSH password for {args.ssh_user}@{args.ssh_host}: ")

    local_ip = local_ip_for(args.camera_ip, args.camera_port)
    if local_ip == args.protect_ip:
        print(
            "ERROR: Local client and Protect share the same source IP.\n"
            "Run this tool from a different host.",
            file=sys.stderr,
        )
        return 1

    output_dir = args.output_dir or Path(f"evidence_{time.strftime('%Y%m%d_%H%M%S')}")
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    pcap_path = output_dir / "capture.pcap"

    # Build capture backend
    if args.capture == "remote":
        backend = build_remote_capture(
            ssh_host=args.ssh_host,
            ssh_port=args.ssh_port,
            ssh_user=args.ssh_user,
            ssh_password=ssh_password,
            ssh_key=args.ssh_key,
            camera_ip=args.camera_ip,
            camera_port=args.camera_port,
            interface=args.interface,
            keep_remote=args.keep_remote,
        )
        capture_host = args.ssh_host
    else:
        backend = build_local_capture(
            camera_ip=args.camera_ip,
            camera_port=args.camera_port,
            interface=args.interface,
        )
        capture_host = local_ip

    # Build ONVIF subscriber
    sub_config = SubscriberConfig(
        camera_ip=args.camera_ip,
        camera_port=args.camera_port,
        username=args.camera_user,
        password=camera_password,
        source=EventSource.LOCAL,
    )
    subscriber = OnvifSubscriber(sub_config)

    start_utc = utc_now()
    print(f"\nStarting capture ({args.duration} s). Walk in front of the camera.")
    print("Wait for at least one IsMotion=true event in the log.\n")

    capture_started = False
    try:
        backend.start()
        capture_started = True
    except CaptureError as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        return 1

    subscriber_ok = True
    try:
        subscriber.start(args.duration)
        time.sleep(args.duration)
        subscriber.stop()
    except KeyboardInterrupt:
        print("\nCapture interrupted by user.", file=sys.stderr)
        subscriber.stop()
    except RuntimeError as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        subscriber.stop()
        subscriber_ok = False
    finally:
        backend.stop()

    if not subscriber_ok:
        return 1

    try:
        backend.download(pcap_path)
    except Exception as exc:
        print(f"\nERROR: Could not download PCAP: {exc}", file=sys.stderr)
        return 1

    end_utc = utc_now()

    # Determine capture interface
    capture_interface = args.interface or "auto"
    if hasattr(backend, "_interface") and backend._interface:
        capture_interface = backend._interface

    pcap_sha256 = sha256_file(pcap_path) if pcap_path.exists() else ""

    metadata = CaptureMetadata(
        camera_ip=args.camera_ip,
        camera_port=args.camera_port,
        camera_user=args.camera_user,
        protect_ip=args.protect_ip,
        capture_interface=capture_interface,
        capture_host=capture_host,
        capture_mode=args.capture,
        pcap_path=str(pcap_path),
        pcap_sha256=pcap_sha256,
        start_utc=start_utc,
        end_utc=end_utc,
        duration_seconds=args.duration,
        tool_version=__version__,
    )

    bundle = _analyse_pcap(
        pcap_path=pcap_path,
        camera_ip=args.camera_ip,
        protect_ip=args.protect_ip,
        local_ip=local_ip,
        local_events=subscriber.events,
        metadata=metadata,
        correlation_window_ms=args.correlation_window,
    )

    writer = ReportWriter(output_dir)
    writer.write(bundle)
    writer.print_summary(bundle)
    return 0


def _cmd_analyse(args: argparse.Namespace) -> int:
    pcap_path = args.pcap.expanduser().resolve()
    if not pcap_path.exists():
        print(f"ERROR: PCAP file not found: {pcap_path}", file=sys.stderr)
        return 1

    output_dir = args.output_dir or pcap_path.parent / f"evidence_{time.strftime('%Y%m%d_%H%M%S')}"
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    pcap_sha256 = sha256_file(pcap_path)
    now = utc_now()

    metadata = CaptureMetadata(
        camera_ip=args.camera_ip,
        camera_port=0,
        camera_user="",
        protect_ip=args.protect_ip,
        capture_interface="",
        capture_host="",
        capture_mode="offline",
        pcap_path=str(pcap_path),
        pcap_sha256=pcap_sha256,
        start_utc=now,
        end_utc=now,
        duration_seconds=0,
        tool_version=__version__,
    )

    bundle = _analyse_pcap(
        pcap_path=pcap_path,
        camera_ip=args.camera_ip,
        protect_ip=args.protect_ip,
        local_ip=args.local_ip,
        local_events=[],
        metadata=metadata,
        correlation_window_ms=args.correlation_window,
    )

    writer = ReportWriter(output_dir)
    writer.write(bundle)
    writer.print_summary(bundle)
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    evidence_path = args.evidence.expanduser().resolve()
    if not evidence_path.exists():
        print(f"ERROR: evidence.json not found: {evidence_path}", file=sys.stderr)
        return 1

    output_dir = args.output_dir or evidence_path.parent
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    # Deserialise — we re-render from the JSON rather than re-parsing the PCAP
    raw = json.loads(evidence_path.read_text(encoding="utf-8"))
    print(f"Re-rendering report from {evidence_path}")
    print(f"Output: {output_dir}")
    print(
        "ERROR: Full JSON deserialisation is not yet implemented.\n"
        "Use 'analyse' with the original PCAP to regenerate the report:",
        file=sys.stderr,
    )
    pcap_hint = raw.get("metadata", {}).get("pcap_path", "<pcap path>")
    camera_hint = raw.get("metadata", {}).get("camera_ip", "<camera-ip>")
    protect_hint = raw.get("metadata", {}).get("protect_ip", "<protect-ip>")
    print(
        f"  python3 -m onvif_compare analyse \\",
        file=sys.stderr,
    )
    print(f"    --pcap {pcap_hint} \\", file=sys.stderr)
    print(f"    --camera-ip {camera_hint} \\", file=sys.stderr)
    print(f"    --protect-ip {protect_hint}", file=sys.stderr)
    return 2  # not-implemented — distinct from general error (1)


# ---------------------------------------------------------------------------
# Shared analysis pipeline
# ---------------------------------------------------------------------------


def _analyse_pcap(
    *,
    pcap_path: Path,
    camera_ip: str,
    protect_ip: str,
    local_ip: Optional[str],
    local_events: List[MotionEvent],
    metadata: CaptureMetadata,
    correlation_window_ms: int,
) -> EvidenceBundle:
    """Run the full analysis pipeline on a PCAP file."""
    print(f"Analysing {pcap_path} …")

    http_transactions = reconstruct_streams(
        str(pcap_path),
        camera_ip=camera_ip,
        protect_ip=protect_ip,
        local_ip=local_ip,
    )

    pull_transactions, soap_faults = extract_transactions(
        http_transactions,
        camera_ip=camera_ip,
        protect_ip=protect_ip,
        local_ip=local_ip,
    )

    protect_txns = [t for t in pull_transactions if t.source == EventSource.PROTECT]
    local_txns = [t for t in pull_transactions if t.source == EventSource.LOCAL]

    timeline = build_timeline(
        protect_transactions=protect_txns,
        local_transactions=local_txns,
        local_events=local_events,
        soap_faults=soap_faults,
        subscription_events=[],
    )

    correlations = correlate(timeline, window_ms=correlation_window_ms)

    bundle = EvidenceBundle(
        metadata=metadata,
        timeline=timeline,
        protect_transactions=protect_txns,
        local_transactions=local_txns,
        local_events=local_events,
        soap_faults=soap_faults,
        correlations=correlations,
        observations=[],
    )
    bundle.observations = build_observations(bundle)

    return bundle


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    print(f"ONVIF PullPoint Forensic Comparator v{__version__}")

    dispatch = {
        "capture": _cmd_capture,
        "analyse": _cmd_analyse,
        "report": _cmd_report,
    }
    try:
        return dispatch[args.command](args)
    except CaptureError as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
