"""PCAP parser for ONVIF PullPoint traffic.

Pipeline
--------
PCAP file
  → Scapy packet reader
  → TCP stream reconstruction  (_TcpStream)
  → HTTP request/response pairing  (_pair_http)
  → SOAP envelope extraction  (soap.parse_envelope)
  → PullTransaction / SoapFault dataclasses

Design constraints
------------------
- Scapy is the only PCAP library used.  If it is unavailable the module
  raises ``ImportError`` with a clear message.
- XML is never located by regex.  The HTTP body is passed directly to
  ``lxml.etree.fromstring``.
- Every ``PullTransaction`` retains the raw request and response bodies.
- Every ``SoapFault`` retains its raw XML.
- Provenance (tcp_stream, frame_number) is recorded on every object.

HTTP chunked transfer encoding and gzip content-encoding are handled
transparently so that compressed camera responses are decoded correctly.
"""

from __future__ import annotations

import gzip
import logging
import zlib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Iterator, List, Optional, Tuple

try:
    from scapy.layers.inet import IP, TCP
    from scapy.packet import Packet
    from scapy.utils import PcapReader
except ImportError as _exc:  # pragma: no cover
    raise ImportError(
        "Scapy is required for PCAP analysis.\n"
        "Install it with:  pip install scapy"
    ) from _exc

from .models import EventSource, MotionEvent, PullTransaction, SoapFault, SoapOperation
from .soap import SoapParseError, parse_envelope

try:
    from lxml import etree as _etree
except ImportError:  # pragma: no cover
    _etree = None  # type: ignore


def _lxml_fromstring(data: bytes):
    if _etree is None:
        return None
    try:
        return _etree.fromstring(data)
    except Exception:
        return None

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal stream reconstruction
# ---------------------------------------------------------------------------


@dataclass
class _Segment:
    """One TCP segment with its metadata."""

    seq: int
    payload: bytes
    timestamp: float  # Unix epoch from PCAP
    frame_number: int


@dataclass
class _TcpStream:
    """Reassembled byte stream for one direction of a TCP connection."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    segments: List[_Segment] = field(default_factory=list)

    def ordered_payload(self) -> bytes:
        """Return payload bytes ordered by sequence number."""
        ordered = sorted(self.segments, key=lambda s: s.seq)
        return b"".join(s.payload for s in ordered)

    def first_timestamp(self) -> Optional[float]:
        if not self.segments:
            return None
        return min(s.timestamp for s in self.segments)

    def last_timestamp(self) -> Optional[float]:
        if not self.segments:
            return None
        return max(s.timestamp for s in self.segments)

    def first_frame(self) -> int:
        if not self.segments:
            return -1
        return min(s.frame_number for s in self.segments)


# ---------------------------------------------------------------------------
# HTTP parsing helpers
# ---------------------------------------------------------------------------


def _decode_chunked(body: bytes) -> bytes:
    """Decode HTTP/1.1 chunked transfer encoding."""
    result = bytearray()
    pos = 0
    while pos < len(body):
        end = body.find(b"\r\n", pos)
        if end == -1:
            break
        try:
            chunk_size = int(body[pos:end], 16)
        except ValueError:
            break
        if chunk_size == 0:
            break
        pos = end + 2
        result.extend(body[pos: pos + chunk_size])
        pos += chunk_size + 2  # skip trailing CRLF
    return bytes(result)


def _decompress(data: bytes, encoding: str) -> bytes:
    """Decompress *data* according to the Content-Encoding header value."""
    enc = encoding.lower().strip()
    if enc == "gzip":
        return gzip.decompress(data)
    if enc in ("deflate", "zlib"):
        try:
            return zlib.decompress(data)
        except zlib.error:
            return zlib.decompress(data, -15)
    return data


def _split_http(raw: bytes) -> Tuple[bytes, bytes]:
    """Split raw HTTP bytes into (headers_block, body)."""
    sep = raw.find(b"\r\n\r\n")
    if sep == -1:
        return raw, b""
    return raw[:sep], raw[sep + 4:]


def _header_value(headers_block: bytes, name: str) -> Optional[str]:
    """Return the value of an HTTP header (case-insensitive), or ``None``."""
    needle = (name.lower() + ":").encode()
    for line in headers_block.split(b"\r\n"):
        if line.lower().startswith(needle):
            return line[len(needle):].decode(errors="replace").strip()
    return None


def _http_status(headers_block: bytes) -> int:
    """Extract the numeric HTTP status code from a response header block."""
    first_line = headers_block.split(b"\r\n")[0]
    parts = first_line.split(b" ", 2)
    if len(parts) >= 2:
        try:
            return int(parts[1])
        except ValueError:
            pass
    return 0


def _extract_body(headers_block: bytes, raw_body: bytes, *, already_unchunked: bool = False) -> bytes:
    """Apply chunked decoding and content decompression to *raw_body*.

    Parameters
    ----------
    already_unchunked:
        Set to ``True`` when the caller has already decoded chunked framing
        (e.g. via ``_read_chunked_body``).  Prevents double-decoding.
    """
    if not already_unchunked:
        te = _header_value(headers_block, "Transfer-Encoding") or ""
        if "chunked" in te.lower():
            raw_body = _decode_chunked(raw_body)

    ce = _header_value(headers_block, "Content-Encoding") or ""
    if ce:
        try:
            raw_body = _decompress(raw_body, ce)
        except Exception as exc:
            log.warning("Could not decompress body (encoding=%r): %s", ce, exc)

    return raw_body


def _is_soap(body: bytes) -> bool:
    """Quick check: does *body* look like a SOAP envelope?"""
    stripped = body.lstrip()
    return stripped.startswith(b"<") and (
        b"Envelope" in stripped[:512] or b"envelope" in stripped[:512]
    )


def _is_request(headers_block: bytes) -> bool:
    """Return True if the header block is an HTTP request (not a response)."""
    first = headers_block.split(b"\r\n")[0]
    return first.startswith(b"POST") or first.startswith(b"GET")


# ---------------------------------------------------------------------------
# Stream key
# ---------------------------------------------------------------------------


def _stream_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> str:
    return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"


def _canonical_stream_key(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int
) -> Tuple[str, bool]:
    """Return a canonical (sorted) key and whether the direction is forward."""
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a <= b:
        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}", True
    return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}", False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


@dataclass
class HttpTransaction:
    """One matched HTTP request/response pair from the PCAP.

    Attributes
    ----------
    tcp_stream:
        Numeric stream index assigned during reconstruction.
    src_ip / dst_ip:
        IP addresses of the *request* direction.
    request_frame / response_frame:
        First frame numbers of the request and response segments.
    request_time / response_time:
        Timestamps from the PCAP.
    http_status:
        HTTP response status code.
    request_body / response_body:
        Decoded (unchunked, decompressed) HTTP bodies.
    raw_request_headers / raw_response_headers:
        Raw header blocks for inspection.
    """

    tcp_stream: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    request_frame: int
    response_frame: int
    request_time: datetime
    response_time: datetime
    http_status: int
    request_body: bytes
    response_body: bytes
    raw_request_headers: bytes
    raw_response_headers: bytes


def read_pcap(path: str) -> Iterator[Tuple[int, Packet, float]]:
    """Yield ``(frame_number, packet, timestamp)`` from a PCAP file."""
    with PcapReader(path) as reader:
        for i, pkt in enumerate(reader, start=1):
            ts = float(pkt.time)
            yield i, pkt, ts


def reconstruct_streams(
    path: str,
    *,
    camera_ip: str,
    protect_ip: str,
    local_ip: Optional[str] = None,
) -> List[HttpTransaction]:
    """Read *path* and return all HTTP transactions involving the camera.

    Parameters
    ----------
    path:
        Path to the PCAP file.
    camera_ip:
        IP address of the ONVIF camera.
    protect_ip:
        IP address of the UniFi Protect controller.
    local_ip:
        IP address of the local diagnostic subscriber, if known.

    Returns
    -------
    List of ``HttpTransaction`` objects, one per matched request/response pair.
    """
    # Collect TCP segments per canonical stream key
    # forward_streams[key] = segments from the request direction
    # reverse_streams[key] = segments from the response direction
    forward: Dict[str, _TcpStream] = {}
    reverse: Dict[str, _TcpStream] = {}
    stream_index: Dict[str, int] = {}
    next_index = [0]

    for frame_no, pkt, ts in read_pcap(path):
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            continue

        ip = pkt[IP]
        tcp = pkt[TCP]

        # Only care about traffic to/from the camera
        if camera_ip not in (ip.src, ip.dst):
            continue

        payload = bytes(tcp.payload)
        if not payload:
            continue

        key, is_fwd = _canonical_stream_key(ip.src, tcp.sport, ip.dst, tcp.dport)

        if key not in stream_index:
            stream_index[key] = next_index[0]
            next_index[0] += 1

        seg = _Segment(seq=tcp.seq, payload=payload, timestamp=ts, frame_number=frame_no)

        if is_fwd:
            if key not in forward:
                forward[key] = _TcpStream(ip.src, ip.dst, tcp.sport, tcp.dport)
            forward[key].segments.append(seg)
        else:
            if key not in reverse:
                reverse[key] = _TcpStream(ip.dst, ip.src, tcp.dport, tcp.sport)
            reverse[key].segments.append(seg)

    transactions: List[HttpTransaction] = []

    for key, fwd_stream in forward.items():
        rev_stream = reverse.get(key)
        if rev_stream is None:
            continue

        idx = stream_index[key]
        txns = _pair_http(fwd_stream, rev_stream, idx)
        transactions.extend(txns)

    transactions.sort(key=lambda t: t.request_time)
    return transactions


def _pair_http(
    fwd: _TcpStream,
    rev: _TcpStream,
    stream_index: int,
) -> List[HttpTransaction]:
    """Pair HTTP requests from *fwd* with responses from *rev*.

    A single TCP stream may carry multiple HTTP/1.1 pipelined requests.
    This function splits the reassembled byte streams on HTTP message
    boundaries and pairs them positionally.
    """
    req_messages = _split_http_messages(fwd.ordered_payload())
    resp_messages = _split_http_messages(rev.ordered_payload())

    results: List[HttpTransaction] = []

    for i, (req_hdrs, req_body) in enumerate(req_messages):
        if not _is_request(req_hdrs):
            continue
        if i >= len(resp_messages):
            log.debug("Stream %d: request %d has no matching response", stream_index, i)
            continue

        resp_hdrs, resp_body = resp_messages[i]

        req_ts = fwd.first_timestamp() or 0.0
        resp_ts = rev.first_timestamp() or 0.0

        results.append(HttpTransaction(
            tcp_stream=stream_index,
            src_ip=fwd.src_ip,
            dst_ip=fwd.dst_ip,
            src_port=fwd.src_port,
            dst_port=fwd.dst_port,
            request_frame=fwd.first_frame(),
            response_frame=rev.first_frame(),
            request_time=datetime.fromtimestamp(req_ts, tz=timezone.utc),
            response_time=datetime.fromtimestamp(resp_ts, tz=timezone.utc),
            http_status=_http_status(resp_hdrs),
            request_body=req_body,
            response_body=resp_body,
            raw_request_headers=req_hdrs,
            raw_response_headers=resp_hdrs,
        ))

    return results


def _split_http_messages(data: bytes) -> List[Tuple[bytes, bytes]]:
    """Split a reassembled TCP byte stream into individual HTTP messages.

    Returns a list of ``(headers_block, body)`` tuples.
    """
    messages: List[Tuple[bytes, bytes]] = []
    pos = 0

    while pos < len(data):
        sep = data.find(b"\r\n\r\n", pos)
        if sep == -1:
            break

        hdrs = data[pos:sep]
        body_start = sep + 4

        # Determine body length
        cl_str = _header_value(hdrs, "Content-Length")
        if cl_str is not None:
            try:
                cl = int(cl_str)
                raw_body = data[body_start: body_start + cl]
                body = _extract_body(hdrs, raw_body)
                messages.append((hdrs, body))
                pos = body_start + cl
                continue
            except ValueError:
                pass

        te = _header_value(hdrs, "Transfer-Encoding") or ""
        if "chunked" in te.lower():
            # _read_chunked_body returns already-decoded content.
            # Pass already_decoded=True so _extract_body skips chunked
            # decoding and only applies content-encoding (gzip etc.).
            decoded_body, consumed = _read_chunked_body(data, body_start)
            body = _extract_body(hdrs, decoded_body, already_unchunked=True)
            messages.append((hdrs, body))
            pos = body_start + consumed
            continue

        # No length information — consume the rest
        raw_body = data[body_start:]
        body = _extract_body(hdrs, raw_body)
        messages.append((hdrs, body))
        break

    return messages


def _read_chunked_body(data: bytes, start: int) -> Tuple[bytes, int]:
    """Read a chunked body starting at *start*.  Returns (decoded_body, bytes_consumed).

    Handles:
    - Chunk extensions: ``1a;extension=value``
    - Zero-size terminal chunk
    - Optional trailer headers
    - Final empty line
    """
    result = bytearray()
    pos = start
    while pos < len(data):
        end = data.find(b"\r\n", pos)
        if end == -1:
            break
        # Strip chunk extensions (everything after the first semicolon)
        size_field = data[pos:end].split(b";")[0].strip()
        try:
            chunk_size = int(size_field, 16)
        except ValueError:
            break
        pos = end + 2
        if chunk_size == 0:
            # Consume optional trailer headers until blank line
            while pos < len(data):
                line_end = data.find(b"\r\n", pos)
                if line_end == -1:
                    pos = len(data)
                    break
                if line_end == pos:  # blank line — end of trailers
                    pos = line_end + 2
                    break
                pos = line_end + 2
            break
        result.extend(data[pos: pos + chunk_size])
        pos += chunk_size + 2  # skip trailing CRLF
    return bytes(result), pos - start


def extract_transactions(
    transactions: List[HttpTransaction],
    *,
    camera_ip: str,
    protect_ip: str,
    local_ip: Optional[str] = None,
) -> Tuple[List[PullTransaction], List[SoapFault]]:
    """Convert ``HttpTransaction`` objects into ``PullTransaction`` and ``SoapFault`` objects.

    Parameters
    ----------
    transactions:
        Output of ``reconstruct_streams``.
    camera_ip:
        Used to determine traffic direction.
    protect_ip:
        Used to classify transactions as Protect or local.
    local_ip:
        Used to classify transactions as local subscriber.

    Returns
    -------
    ``(pull_transactions, soap_faults)``
    """
    pull_transactions: List[PullTransaction] = []
    soap_faults: List[SoapFault] = []

    for txn in transactions:
        if not _is_soap(txn.request_body) and not _is_soap(txn.response_body):
            continue

        # Determine source
        if txn.src_ip == protect_ip:
            source = EventSource.PROTECT
        elif local_ip and txn.src_ip == local_ip:
            source = EventSource.LOCAL
        else:
            source = EventSource.UNKNOWN

        # Parse request to identify operation
        req_operation = SoapOperation.UNKNOWN
        if _is_soap(txn.request_body):
            try:
                req_operation, _ = parse_envelope(txn.request_body)
            except SoapParseError as exc:
                log.debug("Stream %d: could not parse request: %s", txn.tcp_stream, exc)

        # Parse response
        notifications: List[MotionEvent] = []
        fault: Optional[SoapFault] = None
        resp_operation = SoapOperation.UNKNOWN

        if _is_soap(txn.response_body):
            try:
                resp_operation, parsed = parse_envelope(
                    txn.response_body,
                    http_status=txn.http_status,
                    tcp_stream=txn.tcp_stream,
                    frame_number=txn.response_frame,
                    source=source,
                )
                if resp_operation == SoapOperation.FAULT and isinstance(parsed, SoapFault):
                    fault = parsed
                    soap_faults.append(fault)
                elif isinstance(parsed, list):
                    notifications = parsed
            except SoapParseError as exc:
                log.debug("Stream %d: could not parse response: %s", txn.tcp_stream, exc)

        operation = req_operation if req_operation != SoapOperation.UNKNOWN else resp_operation

        # Extract WS-Addressing fields from the request SOAP envelope.
        # wsa:To is an element inside the SOAP header, not an HTTP header.
        sub_id: Optional[str] = None
        http_request_target: Optional[str] = None

        # Extract HTTP request target (first line: POST /path HTTP/1.1)
        first_line = txn.raw_request_headers.split(b"\r\n")[0]
        parts = first_line.split(b" ")
        if len(parts) >= 2:
            http_request_target = parts[1].decode(errors="replace")

        if _is_soap(txn.request_body):
            try:
                req_env = _lxml_fromstring(txn.request_body)
                if req_env is not None:
                    wsa_to = req_env.xpath(
                        ".//*[local-name()='Header']//*[local-name()='To']"
                    )
                    if wsa_to:
                        sub_id = (wsa_to[0].text or "").strip() or None
                if sub_id is None:
                    sub_id = http_request_target
            except Exception:
                sub_id = http_request_target

        pull_transactions.append(PullTransaction(
            tcp_stream=txn.tcp_stream,
            request_frame=txn.request_frame,
            response_frame=txn.response_frame,
            request_time=txn.request_time,
            response_time=txn.response_time,
            http_status=txn.http_status,
            operation=operation,
            notifications=notifications,
            soap_fault=fault,
            source=source,
            subscription_id=sub_id,
            request_xml_path=None,   # set by report.py when saving
            response_xml_path=None,
            raw_request=txn.request_body.decode(errors="replace"),
            raw_response=txn.response_body.decode(errors="replace"),
        ))

    return pull_transactions, soap_faults
