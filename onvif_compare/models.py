"""Data models for the ONVIF PullPoint Forensic Comparator.

Every structured object in the tool is defined here as a dataclass.
No logic lives in this module — it is a pure data contract.

Provenance fields
-----------------
Every event and transaction records where it came from:

- ``source``      : ``"protect"`` | ``"local"`` | ``"camera"``
- ``tcp_stream``  : Scapy TCP stream index (from the PCAP)
- ``frame_*``     : PCAP frame numbers, for direct Wireshark lookup
- ``raw_xml``     : The original XML string, never discarded
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class EventSource(str, Enum):
    """Where an event or transaction originated."""

    PROTECT = "protect"
    LOCAL = "local"
    CAMERA = "camera"
    UNKNOWN = "unknown"


class CorrelationResult(str, Enum):
    """Outcome of correlating a local motion event with a Protect poll."""

    NOTIFICATION_PRESENT = "notification_present"
    EMPTY_RESPONSE = "empty_response"
    SOAP_FAULT = "soap_fault"
    HTTP_ERROR = "http_error"
    NO_POLL_IN_WINDOW = "no_poll_in_window"
    TIMEOUT = "timeout"


class SoapOperation(str, Enum):
    """SOAP operations recognised by the parser."""

    PULL_MESSAGES = "PullMessages"
    PULL_MESSAGES_RESPONSE = "PullMessagesResponse"
    CREATE_PULLPOINT = "CreatePullPointSubscription"
    CREATE_PULLPOINT_RESPONSE = "CreatePullPointSubscriptionResponse"
    RENEW = "Renew"
    RENEW_RESPONSE = "RenewResponse"
    UNSUBSCRIBE = "Unsubscribe"
    UNSUBSCRIBE_RESPONSE = "UnsubscribeResponse"
    NOTIFY = "Notify"
    FAULT = "Fault"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# SOAP fault
# ---------------------------------------------------------------------------


@dataclass
class SoapFault:
    """A parsed SOAP 1.2 fault envelope.

    Attributes
    ----------
    code:
        The ``env:Code/env:Value`` text, e.g. ``"env:Receiver"``.
    subcode:
        The ``env:Code/env:Subcode/env:Value`` text, if present.
    reason:
        Human-readable reason string from ``env:Reason/env:Text``.
    detail:
        Raw text content of ``env:Detail``, if present.
    http_status:
        The HTTP status code of the response that carried this fault.
    tcp_stream:
        Scapy TCP stream index.
    frame_number:
        PCAP frame number of the response packet.
    raw_xml:
        Re-serialised XML (pretty-printed by lxml).  May differ from the
        original in whitespace and namespace prefix placement.
    raw_body_bytes:
        The exact bytes of the HTTP response body as captured on the wire.
        Never modified.  Use this for chain-of-custody evidence.
    body_sha256:
        SHA-256 hex digest of ``raw_body_bytes``.
    """

    code: str
    subcode: Optional[str]
    reason: str
    detail: Optional[str]
    http_status: int
    tcp_stream: int
    frame_number: int
    raw_xml: str
    raw_body_bytes: bytes = field(default=b"")
    body_sha256: str = field(default="")


# ---------------------------------------------------------------------------
# ONVIF notification / motion event
# ---------------------------------------------------------------------------


@dataclass
class SimpleItem:
    """A single ``tt:SimpleItem`` name/value pair from a notification message."""

    name: str
    value: str


@dataclass
class MotionEvent:
    """A parsed ONVIF ``NotificationMessage`` that carries motion data.

    Attributes
    ----------
    utc:
        The ``UtcTime`` attribute from the inner ``tt:Message`` element.
        Set to the Unix epoch sentinel ``datetime(1970,1,1,utc)`` when
        the timestamp was absent or unparseable.
    operation:
        The ``PropertyOperation`` attribute (``"Initialized"``, ``"Changed"``,
        ``"Deleted"``).  Empty string if absent.
    is_motion:
        Parsed value of the ``IsMotion`` ``SimpleItem``, or ``None`` if absent.
    state:
        Parsed value of the ``State`` ``SimpleItem``, or ``None`` if absent.
    topic:
        The ``wsnt:Topic`` text.  Empty string if absent.
    source_items:
        All ``tt:SimpleItem`` elements from the ``tt:Source`` section.
    key_items:
        All ``tt:SimpleItem`` elements from the ``tt:Key`` section.
    data_items:
        All ``tt:SimpleItem`` elements from the ``tt:Data`` section.
    source:
        Which subscriber received this notification.
    tcp_stream:
        Scapy TCP stream index (``-1`` if from the live ONVIF client).
    frame_number:
        PCAP frame number (``-1`` if from the live ONVIF client).
    raw_xml:
        The re-serialised XML fragment (pretty-printed by lxml).
    raw_body_bytes:
        Exact captured bytes of the enclosing HTTP body.
    body_sha256:
        SHA-256 hex digest of ``raw_body_bytes``.
    parse_status:
        ``"ok"`` for a fully parsed notification, ``"partial"`` when
        required fields were absent or unparseable.
    parse_warnings:
        List of human-readable warnings describing what was missing or
        could not be parsed.  Empty for fully parsed notifications.
    timestamp_valid:
        ``True`` if ``utc`` was successfully parsed from the camera's
        ``UtcTime`` attribute.  ``False`` means the epoch sentinel was used.
    """

    utc: datetime
    operation: str
    is_motion: Optional[bool]
    state: Optional[bool]
    topic: str
    source_items: List[SimpleItem]
    key_items: List[SimpleItem]
    data_items: List[SimpleItem]
    source: EventSource
    tcp_stream: int
    frame_number: int
    raw_xml: str
    raw_body_bytes: bytes = field(default=b"")
    body_sha256: str = field(default="")
    parse_status: str = field(default="ok")
    parse_warnings: List[str] = field(default_factory=list)
    timestamp_valid: bool = field(default=True)


# ---------------------------------------------------------------------------
# HTTP / SOAP transaction
# ---------------------------------------------------------------------------


@dataclass
class PullTransaction:
    """One complete PullMessages HTTP request/response pair.

    Attributes
    ----------
    tcp_stream:
        Scapy TCP stream index — use this to find the stream in Wireshark.
    request_frame:
        PCAP frame number of the HTTP request.
    response_frame:
        PCAP frame number of the HTTP response.
    request_time:
        Timestamp of the request packet.
    response_time:
        Timestamp of the response packet.
    http_status:
        HTTP response status code (e.g. ``200``, ``500``).
    operation:
        The SOAP operation identified in the request body.
    notifications:
        ``MotionEvent`` objects parsed from the response body.
    soap_fault:
        Populated if the response contained a SOAP fault; ``None`` otherwise.
    source:
        Which subscriber issued this request.
    subscription_id:
        The WS-Addressing subscription reference, if extractable.
    request_xml_path:
        Path to the saved raw request XML file within the evidence bundle.
    response_xml_path:
        Path to the saved raw response XML file within the evidence bundle.
    raw_request:
        The raw HTTP request body as a string.
    raw_response:
        The raw HTTP response body as a string.
    """

    tcp_stream: int
    request_frame: int
    response_frame: int
    request_time: datetime
    response_time: datetime
    http_status: int
    operation: SoapOperation
    notifications: List[MotionEvent]
    soap_fault: Optional[SoapFault]
    source: EventSource
    subscription_id: Optional[str]
    request_xml_path: Optional[str]
    response_xml_path: Optional[str]
    raw_request: str
    raw_response: str
    raw_request_bytes: bytes = field(default=b"")
    raw_response_bytes: bytes = field(default=b"")
    request_body_sha256: str = field(default="")
    response_body_sha256: str = field(default="")


# ---------------------------------------------------------------------------
# Subscription lifecycle
# ---------------------------------------------------------------------------


@dataclass
class SubscriptionEvent:
    """Records a subscription lifecycle action (create, renew, unsubscribe).

    Attributes
    ----------
    utc:
        When the action occurred.
    operation:
        The SOAP operation (``CreatePullPointSubscription``, ``Renew``, etc.).
    subscription_id:
        The subscription reference returned by the camera, if available.
    termination_time:
        The ``TerminationTime`` returned by the camera, if present.
    source:
        Which subscriber performed the action.
    tcp_stream:
        Scapy TCP stream index.
    frame_number:
        PCAP frame number.
    raw_xml:
        The complete SOAP response envelope as a string.
    """

    utc: datetime
    operation: SoapOperation
    subscription_id: Optional[str]
    termination_time: Optional[datetime]
    source: EventSource
    tcp_stream: int
    frame_number: int
    raw_xml: str


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------


class TimelineEventKind(str, Enum):
    """Discriminator for ``TimelineEntry.kind``."""

    MOTION_EVENT = "motion_event"
    PULL_TRANSACTION = "pull_transaction"
    SOAP_FAULT = "soap_fault"
    SUBSCRIPTION = "subscription"
    HTTP_ERROR = "http_error"


@dataclass
class TimelineEntry:
    """A single entry in the master chronological event stream.

    The timeline is the single source of truth from which all reports are
    derived.

    Attributes
    ----------
    utc:
        Event timestamp in UTC.
    kind:
        Discriminator — use this to determine which payload field is set.
    source:
        Which party generated this event.
    motion_event:
        Set when ``kind == TimelineEventKind.MOTION_EVENT``.
    pull_transaction:
        Set when ``kind == TimelineEventKind.PULL_TRANSACTION``.
    soap_fault:
        Set when ``kind == TimelineEventKind.SOAP_FAULT``.
    subscription_event:
        Set when ``kind == TimelineEventKind.SUBSCRIPTION``.
    description:
        Short human-readable summary for the timeline table in the report.
    """

    utc: datetime
    kind: TimelineEventKind
    source: EventSource
    description: str
    motion_event: Optional[MotionEvent] = None
    pull_transaction: Optional[PullTransaction] = None
    soap_fault: Optional[SoapFault] = None
    subscription_event: Optional[SubscriptionEvent] = None


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------


@dataclass
class CorrelationRecord:
    """Links a local motion event to the nearest Protect PullMessages polls.

    Attributes
    ----------
    local_event:
        The local ``MotionEvent`` that triggered the correlation search.
    nearest_before:
        The closest Protect ``PullTransaction`` that occurred *before* the
        local event, within the correlation window.
    nearest_after:
        The closest Protect ``PullTransaction`` that occurred *after* the
        local event, within the correlation window.
    nearest_absolute:
        Whichever of ``nearest_before`` / ``nearest_after`` is temporally
        closer.
    delta_before_ms:
        Time difference in milliseconds for ``nearest_before`` (positive).
    delta_after_ms:
        Time difference in milliseconds for ``nearest_after`` (positive).
    result:
        Classification of the correlation outcome.
    window_ms:
        The search window that was used (milliseconds).
    """

    local_event: MotionEvent
    nearest_before: Optional[PullTransaction]
    nearest_after: Optional[PullTransaction]
    nearest_absolute: Optional[PullTransaction]
    delta_before_ms: Optional[float]
    delta_after_ms: Optional[float]
    result: CorrelationResult
    window_ms: int


# ---------------------------------------------------------------------------
# Environment / capture metadata
# ---------------------------------------------------------------------------


@dataclass
class CaptureMetadata:
    """Metadata recorded at capture time, included verbatim in the report.

    Attributes
    ----------
    camera_ip:
        IP address of the ONVIF camera.
    camera_port:
        ONVIF service port.
    camera_user:
        ONVIF authentication username.
    protect_ip:
        IP address of the UniFi Protect controller.
    capture_interface:
        Network interface on which ``tcpdump`` ran.
    capture_host:
        Hostname / IP of the machine that ran ``tcpdump``.
    capture_mode:
        ``"remote"`` (SSH to UDM Pro) or ``"local"``.
    pcap_path:
        Absolute path to the saved PCAP file.
    pcap_sha256:
        SHA-256 hex digest of the PCAP file.
    start_utc:
        Wall-clock time when the capture was started (from this machine).
    end_utc:
        Wall-clock time when the capture was stopped (from this machine).
    duration_seconds:
        Requested capture duration as passed to ``--duration``.
    observed_start_utc:
        Timestamp of the first packet in the PCAP.  ``None`` if the PCAP
        is empty or has not yet been analysed.
    observed_end_utc:
        Timestamp of the last packet in the PCAP.
    observed_duration_seconds:
        Actual evidence interval derived from packet timestamps
        (``observed_end_utc - observed_start_utc``).  May differ from
        ``duration_seconds`` if tcpdump started late or the capture was
        interrupted.
    tool_version:
        Version string of this tool.
    """

    camera_ip: str
    camera_port: int
    camera_user: str
    protect_ip: str
    capture_interface: str
    capture_host: str
    capture_mode: str
    pcap_path: str
    pcap_sha256: str
    start_utc: datetime
    end_utc: datetime
    duration_seconds: int
    tool_version: str
    observed_start_utc: Optional[datetime] = None
    observed_end_utc: Optional[datetime] = None
    observed_duration_seconds: Optional[float] = None


# ---------------------------------------------------------------------------
# Top-level evidence bundle
# ---------------------------------------------------------------------------


@dataclass
class EvidenceBundle:
    """The complete output of one capture-and-analyse run.

    This is the object serialised to ``evidence.json`` and passed to
    ``report.py`` to generate ``report.md`` and ``report.html``.

    Attributes
    ----------
    metadata:
        Capture environment details.
    timeline:
        Chronological list of all events — the single source of truth.
    protect_transactions:
        All Protect PullMessages transactions extracted from the PCAP.
    local_transactions:
        All local PullMessages transactions extracted from the PCAP.
    local_events:
        Motion events received by the independent local subscriber.
    soap_faults:
        All SOAP faults observed in the PCAP.
    correlations:
        Correlation records linking local motion events to Protect polls.
    observations:
        Ordered list of factual observation strings for the conclusion
        section.  The tool never assigns blame — it records facts.
    """

    metadata: CaptureMetadata
    timeline: List[TimelineEntry]
    protect_transactions: List[PullTransaction]
    local_transactions: List[PullTransaction]
    local_events: List[MotionEvent]
    soap_faults: List[SoapFault]
    correlations: List[CorrelationRecord]
    observations: List[str]
    extra: Dict[str, object] = field(default_factory=dict)
