"""Unit tests for ``onvif_compare.capture``.

Tests cover the pure-logic helpers and error paths.
No SSH connections.  No subprocesses.  No network access.
"""

from __future__ import annotations

import pytest

from onvif_compare.capture import (
    CaptureError,
    LocalCaptureConfig,
    RemoteCaptureConfig,
    _parse_ip_brief,
    build_local_capture,
    build_remote_capture,
)


class TestParseIpBrief:
    def test_extracts_interface_names(self):
        output = (
            "lo               UNKNOWN        127.0.0.1/8\n"
            "eth0             UP             192.168.1.5/24\n"
            "br554            UP             10.54.4.1/24\n"
        )
        names = _parse_ip_brief(output)
        assert "eth0" in names
        assert "br554" in names
        assert "lo" not in names

    def test_strips_at_suffix(self):
        output = "veth0@eth0       UP\n"
        names = _parse_ip_brief(output)
        assert "veth0" in names

    def test_empty_output(self):
        assert _parse_ip_brief("") == []

    def test_single_bridge(self):
        output = "br0   UP\n"
        names = _parse_ip_brief(output)
        assert names == ["br0"]


class TestRemoteCaptureConfig:
    def test_defaults(self):
        cfg = RemoteCaptureConfig(
            ssh_host="10.0.0.1",
            ssh_port=22,
            ssh_user="root",
            camera_ip="192.168.1.100",
            camera_port=8000,
            interface=None,
        )
        assert cfg.keep_remote is False
        assert cfg.remote_pcap_path == "/tmp/onvif_compare_capture.pcap"

    def test_factory(self):
        cap = build_remote_capture(
            ssh_host="10.0.0.1",
            camera_ip="192.168.1.100",
        )
        assert cap._cfg.ssh_host == "10.0.0.1"
        assert cap._cfg.ssh_port == 22


class TestLocalCaptureConfig:
    def test_defaults(self):
        cfg = LocalCaptureConfig(
            camera_ip="192.168.1.100",
            camera_port=8000,
            interface=None,
        )
        assert cfg.local_pcap_path == "/tmp/onvif_compare_local.pcap"

    def test_factory(self):
        cap = build_local_capture(camera_ip="192.168.1.100")
        assert cap._cfg.camera_ip == "192.168.1.100"


class TestLocalCaptureNoTcpdump:
    """Verify LocalCapture raises CaptureError when tcpdump is absent."""

    def test_start_raises_when_no_tcpdump(self, monkeypatch):
        import shutil
        monkeypatch.setattr(shutil, "which", lambda _: None)
        cap = build_local_capture(camera_ip="192.168.1.100", interface="eth0")
        with pytest.raises(CaptureError, match="tcpdump not found"):
            cap.start()
