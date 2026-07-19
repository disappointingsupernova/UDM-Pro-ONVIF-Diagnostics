"""SOAP envelope parser for ONVIF PullPoint traffic.

Design constraints
------------------
- Uses lxml exclusively.  No regex.  No string searching.
- Every parsed object retains its original ``raw_xml`` string.
- Raises ``SoapParseError`` on malformed input rather than returning ``None``.
- Namespace-agnostic XPath (``local-name()``) so vendor namespace variations
  do not cause silent failures.

Recognised operations
---------------------
- ``PullMessages`` / ``PullMessagesResponse``
- ``CreatePullPointSubscription`` / ``CreatePullPointSubscriptionResponse``
- ``Renew`` / ``RenewResponse``
- ``Unsubscribe`` / ``UnsubscribeResponse``
- ``Notify``
- ``s:Fault`` (SOAP 1.2)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from lxml import etree

from .models import (
    CorrelationResult,
    EventSource,
    MotionEvent,
    SimpleItem,
    SoapFault,
    SoapOperation,
    SubscriptionEvent,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Namespace map — used only for documentation; XPath uses local-name()
# ---------------------------------------------------------------------------

_NS = {
    "s":     "http://www.w3.org/2003/05/soap-envelope",
    "wsa":   "http://www.w3.org/2005/08/addressing",
    "wsnt":  "http://docs.oasis-open.org/wsn/b-2",
    "tev":   "http://www.onvif.org/ver10/events/wsdl",
    "tt":    "http://www.onvif.org/ver10/schema",
    "tns1":  "http://www.onvif.org/ver10/topics",
}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SoapParseError(Exception):
    """Raised when a SOAP envelope cannot be parsed."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _first_text(element: etree._Element, xpath: str) -> Optional[str]:
    """Return stripped text of the first XPath match, or ``None``."""
    nodes = element.xpath(xpath)
    if not nodes:
        return None
    node = nodes[0]
    text = node.text if isinstance(node, etree._Element) else str(node)
    return text.strip() if text else None


def _to_bool(value: Optional[str]) -> Optional[bool]:
    """Convert an ONVIF boolean string to ``bool``, or ``None`` if unrecognised."""
    if value is None:
        return None
    v = value.strip().lower()
    if v in ("true", "1"):
        return True
    if v in ("false", "0"):
        return False
    return None


def _parse_utc(text: Optional[str]) -> Optional[datetime]:
    """Parse an ISO-8601 UTC timestamp string into a timezone-aware datetime."""
    if not text:
        return None
    text = text.strip()
    # Replace trailing Z with +00:00 for fromisoformat compatibility on 3.8/3.9
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        log.warning("Could not parse timestamp: %r", text)
        return None


def _simple_items(parent: etree._Element) -> List[SimpleItem]:
    """Extract all ``tt:SimpleItem`` children of *parent*."""
    return [
        SimpleItem(name=el.get("Name", ""), value=el.get("Value", ""))
        for el in parent.xpath(".//*[local-name()='SimpleItem']")
    ]


def _to_xml_string(element: etree._Element) -> str:
    """Serialise *element* to a UTF-8 XML string."""
    return etree.tostring(element, encoding="unicode", pretty_print=True)


def _body_child(envelope: etree._Element) -> Optional[etree._Element]:
    """Return the first child element of ``s:Body``."""
    bodies = envelope.xpath("//*[local-name()='Body']")
    if not bodies:
        return None
    children = [c for c in bodies[0] if isinstance(c, etree._Element)]
    return children[0] if children else None


def _identify_operation(body_child: etree._Element) -> SoapOperation:
    """Determine the SOAP operation from the local name of the body element."""
    local = etree.QName(body_child).localname
    try:
        return SoapOperation(local)
    except ValueError:
        return SoapOperation.UNKNOWN


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse_envelope(
    xml_bytes: bytes,
    *,
    http_status: int = 200,
    tcp_stream: int = -1,
    frame_number: int = -1,
    source: EventSource = EventSource.UNKNOWN,
) -> Tuple[SoapOperation, Optional[object]]:
    """Parse a SOAP envelope and return ``(operation, parsed_object)``.

    Parameters
    ----------
    xml_bytes:
        Raw bytes of the SOAP envelope.
    http_status:
        HTTP status code of the response that carried this envelope.
    tcp_stream:
        Scapy TCP stream index for provenance.
    frame_number:
        PCAP frame number for provenance.
    source:
        Which party sent this envelope.

    Returns
    -------
    A tuple of ``(SoapOperation, parsed_object)`` where ``parsed_object`` is:

    - ``SoapFault`` for a SOAP fault
    - ``list[MotionEvent]`` for a ``PullMessagesResponse``
    - ``SubscriptionEvent`` for subscription lifecycle responses
    - ``None`` for request envelopes or unrecognised bodies

    Raises
    ------
    SoapParseError
        If the bytes cannot be parsed as XML or do not contain a SOAP envelope.
    """
    try:
        envelope = etree.fromstring(xml_bytes)
    except etree.XMLSyntaxError as exc:
        raise SoapParseError(f"XML parse error: {exc}") from exc

    if not envelope.xpath("//*[local-name()='Envelope']") and \
            etree.QName(envelope).localname != "Envelope":
        raise SoapParseError("Root element is not a SOAP Envelope")

    raw_xml = _to_xml_string(envelope)
    body_child = _body_child(envelope)

    if body_child is None:
        return SoapOperation.UNKNOWN, None

    operation = _identify_operation(body_child)

    if operation == SoapOperation.FAULT:
        return operation, _parse_fault(
            envelope, body_child, raw_xml, http_status, tcp_stream, frame_number
        )

    if operation == SoapOperation.PULL_MESSAGES_RESPONSE:
        return operation, _parse_pull_messages_response(
            envelope, body_child, raw_xml, tcp_stream, frame_number, source
        )

    if operation in (
        SoapOperation.CREATE_PULLPOINT_RESPONSE,
        SoapOperation.RENEW_RESPONSE,
        SoapOperation.UNSUBSCRIBE_RESPONSE,
    ):
        return operation, _parse_subscription_response(
            envelope, body_child, raw_xml, operation, tcp_stream, frame_number, source
        )

    if operation == SoapOperation.NOTIFY:
        return operation, _parse_notify(
            envelope, body_child, raw_xml, tcp_stream, frame_number, source
        )

    # Request envelopes (PullMessages, CreatePullPoint, Renew, Unsubscribe)
    # and unknown operations — return the operation only.
    return operation, None


def parse_fault(
    xml_bytes: bytes,
    *,
    http_status: int = 500,
    tcp_stream: int = -1,
    frame_number: int = -1,
) -> SoapFault:
    """Convenience wrapper — parse *xml_bytes* and assert it is a fault.

    Raises ``SoapParseError`` if the envelope is not a fault.
    """
    operation, obj = parse_envelope(
        xml_bytes,
        http_status=http_status,
        tcp_stream=tcp_stream,
        frame_number=frame_number,
    )
    if operation != SoapOperation.FAULT or not isinstance(obj, SoapFault):
        raise SoapParseError(f"Expected Fault, got {operation}")
    return obj


def parse_notifications(
    xml_bytes: bytes,
    *,
    tcp_stream: int = -1,
    frame_number: int = -1,
    source: EventSource = EventSource.UNKNOWN,
) -> List[MotionEvent]:
    """Convenience wrapper — parse *xml_bytes* and return motion events.

    Returns an empty list if the response contains no ``NotificationMessage``
    elements.  Raises ``SoapParseError`` on malformed XML.
    """
    operation, obj = parse_envelope(
        xml_bytes,
        tcp_stream=tcp_stream,
        frame_number=frame_number,
        source=source,
    )
    if operation == SoapOperation.FAULT:
        return []
    if isinstance(obj, list):
        return obj
    return []


# ---------------------------------------------------------------------------
# Private parsers
# ---------------------------------------------------------------------------


def _parse_fault(
    envelope: etree._Element,
    fault_el: etree._Element,
    raw_xml: str,
    http_status: int,
    tcp_stream: int,
    frame_number: int,
) -> SoapFault:
    code = _first_text(fault_el, ".//*[local-name()='Code']/*[local-name()='Value']") or ""
    subcode = _first_text(fault_el, ".//*[local-name()='Subcode']/*[local-name()='Value']")
    reason = _first_text(fault_el, ".//*[local-name()='Reason']/*[local-name()='Text']") or ""
    detail_nodes = fault_el.xpath(".//*[local-name()='Detail']")
    detail: Optional[str] = None
    if detail_nodes:
        detail = etree.tostring(detail_nodes[0], encoding="unicode", method="text").strip() or None

    return SoapFault(
        code=code,
        subcode=subcode,
        reason=reason,
        detail=detail,
        http_status=http_status,
        tcp_stream=tcp_stream,
        frame_number=frame_number,
        raw_xml=raw_xml,
    )


def _parse_notification_message(
    notif_el: etree._Element,
    tcp_stream: int,
    frame_number: int,
    source: EventSource,
) -> MotionEvent:
    """Parse one ``wsnt:NotificationMessage`` element into a ``MotionEvent``.

    Always returns a ``MotionEvent``.  When required fields are absent or
    unparseable the event is marked ``parse_status='partial'`` and the
    issues are recorded in ``parse_warnings``.  A malformed notification
    is evidence in itself and must not be silently discarded.
    """
    warnings: List[str] = []
    parse_status = "ok"

    topic_nodes = notif_el.xpath("./*[local-name()='Topic']")
    topic = "".join(topic_nodes[0].itertext()).strip() if topic_nodes else ""
    if not topic_nodes:
        warnings.append("NotificationMessage did not contain a Topic element")

    # The inner tt:Message element carries UtcTime and PropertyOperation.
    # Accept Message elements with or without UtcTime.
    message_nodes = notif_el.xpath(".//*[local-name()='Message'][@UtcTime]")
    if not message_nodes:
        # Try without the UtcTime requirement — prefer the innermost Message
        # (tt:Message) over the outer wsnt:Message wrapper.
        all_msg = notif_el.xpath(".//*[local-name()='Message']")
        # Filter to elements that have PropertyOperation (tt:Message)
        # or fall back to elements with child elements.
        with_op = [m for m in all_msg if m.get("PropertyOperation") is not None]
        message_nodes = with_op if with_op else [m for m in all_msg if len(m) > 0]
        if not message_nodes:
            message_nodes = all_msg  # last resort: take any Message
        if not message_nodes:
            warnings.append("NotificationMessage did not contain a Message element")
            parse_status = "partial"
            return MotionEvent(
                utc=datetime(1970, 1, 1, tzinfo=timezone.utc),
                operation="",
                is_motion=None,
                state=None,
                topic=topic,
                source_items=[],
                key_items=[],
                data_items=[],
                source=source,
                tcp_stream=tcp_stream,
                frame_number=frame_number,
                raw_xml=_to_xml_string(notif_el),
                parse_status=parse_status,
                parse_warnings=warnings,
                timestamp_valid=False,
            )
        warnings.append("Message element present but UtcTime attribute is absent")

    msg = message_nodes[0]
    utc_str = msg.get("UtcTime", "")
    utc = _parse_utc(utc_str)
    timestamp_valid = utc is not None
    if utc is None:
        log.warning("Could not parse UtcTime=%r in NotificationMessage", utc_str)
        warnings.append(f"Could not parse UtcTime={utc_str!r}; using epoch sentinel")
        parse_status = "partial"
        utc = datetime(1970, 1, 1, tzinfo=timezone.utc)

    operation = msg.get("PropertyOperation", "")
    if not operation:
        warnings.append("PropertyOperation attribute is absent")
        parse_status = "partial"

    source_el_list = msg.xpath("./*[local-name()='Source']")
    key_el_list = msg.xpath("./*[local-name()='Key']")
    data_el_list = msg.xpath("./*[local-name()='Data']")

    source_items = _simple_items(source_el_list[0]) if source_el_list else []
    key_items = _simple_items(key_el_list[0]) if key_el_list else []
    data_items = _simple_items(data_el_list[0]) if data_el_list else []

    is_motion: Optional[bool] = None
    state: Optional[bool] = None
    for item in data_items:
        if item.name == "IsMotion":
            is_motion = _to_bool(item.value)
        elif item.name == "State":
            state = _to_bool(item.value)

    return MotionEvent(
        utc=utc,
        operation=operation,
        is_motion=is_motion,
        state=state,
        topic=topic,
        source_items=source_items,
        key_items=key_items,
        data_items=data_items,
        source=source,
        tcp_stream=tcp_stream,
        frame_number=frame_number,
        raw_xml=_to_xml_string(notif_el),
        parse_status=parse_status,
        parse_warnings=warnings,
        timestamp_valid=timestamp_valid,
    )


def _parse_pull_messages_response(
    envelope: etree._Element,
    body_child: etree._Element,
    raw_xml: str,
    tcp_stream: int,
    frame_number: int,
    source: EventSource,
) -> List[MotionEvent]:
    return [
        _parse_notification_message(notif_el, tcp_stream, frame_number, source)
        for notif_el in envelope.xpath("//*[local-name()='NotificationMessage']")
    ]


def _parse_notify(
    envelope: etree._Element,
    body_child: etree._Element,
    raw_xml: str,
    tcp_stream: int,
    frame_number: int,
    source: EventSource,
) -> List[MotionEvent]:
    """Parse a ``wsnt:Notify`` envelope (push-mode, less common)."""
    return _parse_pull_messages_response(
        envelope, body_child, raw_xml, tcp_stream, frame_number, source
    )


def _parse_subscription_response(
    envelope: etree._Element,
    body_child: etree._Element,
    raw_xml: str,
    operation: SoapOperation,
    tcp_stream: int,
    frame_number: int,
    source: EventSource,
) -> SubscriptionEvent:
    # Subscription reference address
    sub_id = _first_text(
        envelope,
        ".//*[local-name()='SubscriptionReference']/*[local-name()='Address']",
    )
    if sub_id is None:
        # Some cameras put the ID in an Identifier element
        sub_id = _first_text(envelope, ".//*[local-name()='Identifier']")

    termination_str = _first_text(envelope, ".//*[local-name()='TerminationTime']")
    termination_time = _parse_utc(termination_str)

    current_str = _first_text(envelope, ".//*[local-name()='CurrentTime']")
    utc = _parse_utc(current_str)
    if utc is None:
        # No camera-provided time — use epoch sentinel rather than datetime.now()
        utc = datetime(1970, 1, 1, tzinfo=timezone.utc)

    return SubscriptionEvent(
        utc=utc,
        operation=operation,
        subscription_id=sub_id,
        termination_time=termination_time,
        source=source,
        tcp_stream=tcp_stream,
        frame_number=frame_number,
        raw_xml=raw_xml,
    )
