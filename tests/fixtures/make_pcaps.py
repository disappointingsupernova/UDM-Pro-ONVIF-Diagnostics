"""Generate synthetic PCAP fixtures for pcap.py unit tests.

Run once from the project root:

    python tests/fixtures/make_pcaps.py

Produces:
    tests/fixtures/pcap/capture_good.pcap   — PullMessages with IsMotion=true
    tests/fixtures/pcap/capture_fault.pcap  — PullMessages returning SOAP fault
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running from project root
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap
from scapy.packet import Raw

CAMERA_IP = "192.168.1.100"
PROTECT_IP = "10.54.4.1"
CAMERA_PORT = 8000
PROTECT_PORT = 54321

PULL_REQUEST = (
    b"POST /onvif/events/pullpoint/sub01 HTTP/1.1\r\n"
    b"Host: 192.168.1.100:8000\r\n"
    b"Content-Type: application/soap+xml; charset=utf-8\r\n"
    b"Content-Length: 0\r\n"
    b"\r\n"
)

MOTION_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: application/soap+xml; charset=utf-8\r\n"
)

FAULT_RESPONSE_BODY = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
    b"<s:Body><s:Fault>"
    b"<s:Code><s:Value>s:Receiver</s:Value>"
    b"<s:Subcode><s:Value>ter:SubscriptionInvalid</s:Value></s:Subcode></s:Code>"
    b"<s:Reason><s:Text>Subscription expired</s:Text></s:Reason>"
    b"</s:Fault></s:Body></s:Envelope>"
)


def _motion_body() -> bytes:
    return (
        Path(__file__).parent.parent / "fixtures" / "motion_true.xml"
    ).read_bytes()


def _http_response(status: int, body: bytes) -> bytes:
    return (
        f"HTTP/1.1 {status} {'OK' if status == 200 else 'Internal Server Error'}\r\n"
        f"Content-Type: application/soap+xml; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
    ).encode() + body


def _make_tcp_exchange(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    request: bytes,
    response: bytes,
    base_seq_req: int = 1000,
    base_seq_resp: int = 2000,
    ts_req: float = 1710492061.031,
    ts_resp: float = 1710492061.132,
) -> list:
    """Build a minimal TCP exchange (SYN, request data, response data)."""
    pkts = []

    def pkt(src, dst, sport, dport, flags, seq, ack, payload=b"", ts=0.0):
        p = (
            Ether()
            / IP(src=src, dst=dst)
            / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
        )
        if payload:
            p = p / Raw(load=payload)
        p.time = ts
        return p

    # SYN
    pkts.append(pkt(src_ip, dst_ip, src_port, dst_port, "S", base_seq_req, 0, ts=ts_req - 0.01))
    # SYN-ACK
    pkts.append(pkt(dst_ip, src_ip, dst_port, src_port, "SA", base_seq_resp, base_seq_req + 1, ts=ts_req - 0.005))
    # ACK
    pkts.append(pkt(src_ip, dst_ip, src_port, dst_port, "A", base_seq_req + 1, base_seq_resp + 1, ts=ts_req))
    # Request data
    pkts.append(pkt(src_ip, dst_ip, src_port, dst_port, "PA", base_seq_req + 1, base_seq_resp + 1, request, ts=ts_req))
    # Response data
    pkts.append(pkt(dst_ip, src_ip, dst_port, src_port, "PA", base_seq_resp + 1, base_seq_req + 1 + len(request), response, ts=ts_resp))

    return pkts


def make_good_pcap(out: Path) -> None:
    body = _motion_body()
    response = _http_response(200, body)
    request = (
        b"POST /onvif/events/pullpoint/sub01 HTTP/1.1\r\n"
        b"Host: 192.168.1.100:8000\r\n"
        b"Content-Type: application/soap+xml\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
    pkts = _make_tcp_exchange(
        PROTECT_IP, CAMERA_IP, PROTECT_PORT, CAMERA_PORT,
        request, response,
    )
    wrpcap(str(out), pkts)
    print(f"Written: {out}")


def make_fault_pcap(out: Path) -> None:
    response = _http_response(500, FAULT_RESPONSE_BODY)
    request = (
        b"POST /onvif/events/pullpoint/sub01 HTTP/1.1\r\n"
        b"Host: 192.168.1.100:8000\r\n"
        b"Content-Type: application/soap+xml\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
    pkts = _make_tcp_exchange(
        PROTECT_IP, CAMERA_IP, PROTECT_PORT, CAMERA_PORT,
        request, response,
        ts_req=1710492062.000,
        ts_resp=1710492062.050,
    )
    wrpcap(str(out), pkts)
    print(f"Written: {out}")


if __name__ == "__main__":
    out_dir = Path(__file__).parent / "pcap"
    out_dir.mkdir(exist_ok=True)
    make_good_pcap(out_dir / "capture_good.pcap")
    make_fault_pcap(out_dir / "capture_fault.pcap")
    print("Done.")
