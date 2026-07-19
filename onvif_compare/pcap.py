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
from .util import sha256_bytes

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
    """Reassembled byte stream for one direction of a TCP connection.

    Uses overlap-aware, retransmission-safe reconstruction:
    segments are inserted into a contiguous byte buffer by sequence
    offset.  Retransmitted or overlapping bytes are deduplicated.
    Gaps (missing segments) are tracked so callers can mark affected
    HTTP messages as incomplete.
    """

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    segments: List[_Segment] = field(default_factory=list)

    # Populated by _assemble() on first call; cached thereafter.
    _assembled: Optional[bytes] = field(default=None, repr=False, compare=False)
    _base_seq: Optional[int] = field(default=None, repr=False, compare=False)
    _retransmitted_bytes: int = field(default=0, repr=False, compare=False)
    _overlapping_bytes: int = field(default=0, repr=False, compare=False)

    def ordered_payload(self) -> bytes:
        """Return the reassembled payload with retransmissions removed."""
        if self._assembled is None:
            self._assemble()
        return self._assembled  # type: ignore[return-value]

    @property
    def retransmitted_bytes(self) -> int:
        if self._assembled is None:
            self._assemble()
        return self._retransmitted_bytes

    @property
    def overlapping_bytes(self) -> int:
        if self._assembled is None:
            self._assemble()
        return self._overlapping_bytes

    def _assemble(self) -> None:
        """Reconstruct the byte stream, deduplicating retransmissions.

        Algorithm
        ---------
        1. Sort segments by sequence number.
        2. Establish the base sequence number from the first segment.
        3. Walk segments in order; for each segment compute its byte
           offset relative to the base.
        4. If the segment starts before the current write cursor
           (retransmission or overlap), skip already-written bytes and
           only append the novel tail.
        5. If the segment starts after the cursor, there is a gap;
           fill with zero bytes so offsets remain correct and record
           the gap size.
        """
        if not self.segments:
            self._assembled = b""
            return

        ordered = sorted(self.segments, key=lambda s: s.seq)
        self._base_seq = ordered[0].seq
        buf = bytearray()
        cursor = 0  # next byte offset to write
        retransmitted = 0
        overlapping = 0

        for seg in ordered:
            offset = seg.seq - self._base_seq
            # Handle 32-bit sequence number wraparound
            if offset < -2**31:
                offset += 2**32
            elif offset > 2**31:
                offset -= 2**32

            if offset < 0:
                # Segment starts before our base — skip it entirely
                retransmitted += len(seg.payload)
                continue

            if offset < cursor:
                # Retransmission or overlap: only the bytes beyond cursor are new
                novel_start = cursor - offset
                if novel_start >= len(seg.payload):
                    retransmitted += len(seg.payload)
                    continue
                overlapping += novel_start
                novel = seg.payload[novel_start:]
                buf.extend(novel)
                cursor += len(novel)
            else:
                if offset > cursor:
                    # Gap: fill with zeros so offsets stay correct
                    buf.extend(b"\x00" * (offset - cursor))
                    cursor = offset
                buf.extend(seg.payload)
                cursor += len(seg.payload)

        self._assembled = bytes(buf)
        self._retransmitted_bytes = retransmitted
        self._overlapping_bytes = overlapping

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


def _is_unframed(headers_block: bytes) -> bool:
    """Return True if this message was marked as unframed by the parser."""
    return b"X-Onvif-Compare-Unframed: true" in headers_block


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


def pcap_time_bounds(path: str) -> Tuple[Optional[float], Optional[float]]:
    """Return ``(first_packet_ts, last_packet_ts)`` from a PCAP file.

    Returns ``(None, None)`` if the file is empty or unreadable.
    """
    first: Optional[float] = None
    last: Optional[float] = None
    try:
        with PcapReader(path) as reader:
            for pkt in reader:
                ts = float(pkt.time)
                if first is None:
                    first = ts
                last = ts
    except Exception as exc:
        log.warning("Could not read PCAP time bounds from %s: %s", path, exc)
    return first, last


def reconstruct_streams(
    path: str,
    *,
    camera_ip: str,
    protect_ip: str,
    local_ip: Optional[str] = None,
) -> List[HttpTransaction]:
    """Read *path* and return all HTTP transactions involving the camera.

    Direction is determined from the known camera endpoint, not from
    lexical address ordering.  Segments flowing *to* the camera are
    requests; segments flowing *from* the camera are responses.

    Parameters
    ----------
    path:
        Path to the PCAP file.
    camera_ip:
        IP address of the ONVIF camera.  Traffic to this IP is treated as
        requests; traffic from it is treated as responses.
    protect_ip:
        IP address of the UniFi Protect controller.
    local_ip:
        IP address of the local diagnostic subscriber, if known.

    Returns
    -------
    List of ``HttpTransaction`` objects, one per matched request/response pair.
    """
    # Two independent byte streams per TCP connection:
    #   to_camera[key]   — bytes flowing toward the camera (requests)
    #   from_camera[key] — bytes flowing away from the camera (responses)
    to_camera: Dict[str, _TcpStream] = {}
    from_camera: Dict[str, _TcpStream] = {}
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

        # Canonical connection key: always (client_ip:port, camera_ip:port)
        # where client is whichever side is NOT the camera.
        if ip.dst == camera_ip:
            client_ip, client_port = ip.src, tcp.sport
            cam_port = tcp.dport
            going_to_camera = True
        else:
            client_ip, client_port = ip.dst, tcp.dport
            cam_port = tcp.sport
            going_to_camera = False

        key = f"{client_ip}:{client_port}-{camera_ip}:{cam_port}"

        if key not in stream_index:
            stream_index[key] = next_index[0]
            next_index[0] += 1

        seg = _Segment(seq=tcp.seq, payload=payload, timestamp=ts, frame_number=frame_no)

        if going_to_camera:
            if key not in to_camera:
                to_camera[key] = _TcpStream(client_ip, camera_ip, client_port, cam_port)
            to_camera[key].segments.append(seg)
        else:
            if key not in from_camera:
                from_camera[key] = _TcpStream(camera_ip, client_ip, cam_port, client_port)
            from_camera[key].segments.append(seg)

    transactions: List[HttpTransaction] = []

    for key in set(to_camera) | set(from_camera):
        req_stream = to_camera.get(key)
        resp_stream = from_camera.get(key)
        if req_stream is None or resp_stream is None:
            continue

        idx = stream_index[key]
        txns = _pair_http(req_stream, resp_stream, idx)
        transactions.extend(txns)

    transactions.sort(key=lambda t: t.request_time)
    return transactions


def _pair_http(
    req: _TcpStream,
    resp: _TcpStream,
    stream_index: int,
) -> List[HttpTransaction]:
    """Pair HTTP requests from *req* with responses from *resp*.

    Timestamps and frame numbers are derived per individual HTTP message
    from the segments that contributed to that message, not from the
    first segment of the entire TCP connection.
    """
    req_messages = _split_http_messages_with_meta(req)
    resp_messages = _split_http_messages_with_meta(resp)

    # Filter to only actual HTTP requests on the req side
    req_only = [(hdrs, body, meta) for hdrs, body, meta in req_messages if _is_request(hdrs)]

    results: List[HttpTransaction] = []
    resp_idx = 0

    for req_hdrs, req_body, req_meta in req_only:
        # Skip any 1xx informational responses before the real response
        while resp_idx < len(resp_messages):
            r_hdrs, _, _ = resp_messages[resp_idx]
            status = _http_status(r_hdrs)
            if 100 <= status <= 199:
                resp_idx += 1
            else:
                break

        if resp_idx >= len(resp_messages):
            log.debug("Stream %d: request has no matching response", stream_index)
            break

        resp_hdrs, resp_body, resp_meta = resp_messages[resp_idx]
        resp_idx += 1

        results.append(HttpTransaction(
            tcp_stream=stream_index,
            src_ip=req.src_ip,
            dst_ip=req.dst_ip,
            src_port=req.src_port,
            dst_port=req.dst_port,
            request_frame=req_meta["first_frame"],
            response_frame=resp_meta["first_frame"],
            request_time=datetime.fromtimestamp(req_meta["first_ts"], tz=timezone.utc),
            response_time=datetime.fromtimestamp(resp_meta["first_ts"], tz=timezone.utc),
            http_status=_http_status(resp_hdrs),
            request_body=req_body,
            response_body=resp_body,
            raw_request_headers=req_hdrs,
            raw_response_headers=resp_hdrs,
        ))

    return results


def _split_http_messages_with_meta(
    stream: "_TcpStream",
) -> List[Tuple[bytes, bytes, dict]]:
    """Split a TCP stream into HTTP messages, each with per-message metadata.

    Returns a list of ``(headers_block, body, meta)`` tuples where ``meta``
    contains ``first_frame``, ``last_frame``, ``first_ts``, ``last_ts``
    derived from the segments that contributed to that individual message.

    This replaces the old approach of using the first frame/timestamp of
    the entire TCP connection for every message on a persistent connection.
    """
    data = stream.ordered_payload()
    raw_messages = _split_http_messages(data)

    # Build a byte-offset → (frame_number, timestamp) lookup from segments.
    # For each byte offset in the reassembled stream, find which segment
    # contributed it by walking segments in sequence order.
    seg_map: List[Tuple[int, int, float]] = []  # (start_offset, frame_no, ts)
    if stream.segments:
        ordered_segs = sorted(stream.segments, key=lambda s: s.seq)
        base = ordered_segs[0].seq
        cursor = 0
        for seg in ordered_segs:
            offset = seg.seq - base
            if offset < 0:
                continue
            if offset > cursor:
                cursor = offset
            seg_map.append((cursor, seg.frame_number, seg.timestamp))
            cursor += len(seg.payload)

    def _meta_for_range(start: int, end: int) -> dict:
        """Return frame/timestamp metadata for bytes [start, end) in the stream."""
        frames = []
        timestamps = []
        for seg_start, frame_no, ts in seg_map:
            if seg_start < end and seg_start >= start:
                frames.append(frame_no)
                timestamps.append(ts)
        if not frames:
            # Fall back to stream-level values
            frames = [stream.first_frame()]
            timestamps = [stream.first_timestamp() or 0.0]
        return {
            "first_frame": min(frames),
            "last_frame": max(frames),
            "first_ts": min(timestamps),
            "last_ts": max(timestamps),
        }

    # Reconstruct byte offsets for each message
    results = []
    pos = 0
    for hdrs, body in raw_messages:
        # Approximate: header starts at pos, body follows
        msg_start = pos
        msg_end = pos + len(hdrs) + 4 + len(body)  # 4 = len("\r\n\r\n")
        meta = _meta_for_range(msg_start, msg_end)
        results.append((hdrs, body, meta))
        pos = msg_end

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

        # No Content-Length and no chunked encoding.
        # On a persistent (keep-alive) connection this means we cannot
        # determine where this message ends without a connection-close.
        # Consuming the rest of the stream would merge subsequent HTTP
        # messages into one body.  Mark this message as unframed and stop
        # parsing this stream — do not silently corrupt later messages.
        log.debug(
            "HTTP message at offset %d has no Content-Length and no "
            "chunked encoding; marking as unframed and stopping stream parse",
            pos,
        )
        raw_body = data[body_start:]
        body = _extract_body(hdrs, raw_body)
        messages.append((hdrs + b"\r\nX-Onvif-Compare-Unframed: true", body))
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
            if _is_unframed(txn.raw_response_headers):
                log.warning(
                    "Stream %d: response body has no Content-Length or chunked "
                    "encoding; body boundary is uncertain — treating as unframed",
                    txn.tcp_stream,
                )
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
            request_xml_path=None,
            response_xml_path=None,
            raw_request=txn.request_body.decode(errors="replace"),
            raw_response=txn.response_body.decode(errors="replace"),
            raw_request_bytes=txn.request_body,
            raw_response_bytes=txn.response_body,
            request_body_sha256=sha256_bytes(txn.request_body),
            response_body_sha256=sha256_bytes(txn.response_body),
        ))

    return pull_transactions, soap_faults
