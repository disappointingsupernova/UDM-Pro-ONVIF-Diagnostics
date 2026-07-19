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
    NotificationDiagnosis,
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


def _collect_namespaces(element: etree._Element) -> dict:
    """Return a dict of all namespace prefix→URI pairs used in *element* and its descendants."""
    ns = {}
    for el in element.iter():
        for prefix, uri in (el.nsmap or {}).items():
            if prefix and uri:
                ns[prefix] = uri
    return ns


_KNOWN_ONVIF_TOPIC_DIALECTS = {
    "http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet",
    "http://docs.oasis-open.org/wsn/t-1/TopicExpression/Concrete",
    "http://www.onvif.org/ver10/tev/topicExpression/SimpleFilter",
}

_EXPECTED_TT_NS = "http://www.onvif.org/ver10/schema"


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
    unparseable the event is marked ``parse_status='partial'`` with a specific
    ``diagnosis`` classifying the exact structural failure.

    Diagnosis classification
    ------------------------
    COMPLIANT
        All required fields present and parseable.
    TOPIC_ABSENT
        wsnt:Topic element missing entirely.
    TOPIC_UNKNOWN_DIALECT
        Topic present but uses an unrecognised Dialect URI.
    MESSAGE_ELEMENT_ABSENT
        wsnt:Message wrapper is empty — camera sent the envelope with no payload.
    MESSAGE_ELEMENT_WRONG_NAMESPACE
        Inner message element exists but under a vendor namespace instead of
        http://www.onvif.org/ver10/schema.
    MESSAGE_ELEMENT_DEEPER_THAN_EXPECTED
        tt:Message found but not as a direct child of wsnt:Message.
    UTCTIME_ABSENT
        tt:Message present but UtcTime attribute missing.
    UTCTIME_UNPARSEABLE
        UtcTime present but not valid ISO-8601.
    PROPERTY_OPERATION_ABSENT
        PropertyOperation attribute missing from tt:Message.
    DATA_SECTION_ABSENT
        No tt:Data section in the message.
    ISMOTION_ITEM_ABSENT
        tt:Data present but no IsMotion SimpleItem.
    ISMOTION_ITEM_WRONG_NAME
        A boolean-valued SimpleItem exists but is not named IsMotion —
        possible name mismatch (e.g. Motion, motion, IsDetected).
    WRONG_NAMESPACE_ON_SIMPLEITEMS
        SimpleItem elements found under a non-standard namespace.
    """
    warnings: List[str] = []
    parse_status = "ok"
    diagnosis = NotificationDiagnosis.COMPLIANT
    actual_namespaces = _collect_namespaces(notif_el)

    # ------------------------------------------------------------------
    # 1. Topic
    # ------------------------------------------------------------------
    topic_nodes = notif_el.xpath("./*[local-name()='Topic']")
    topic = "".join(topic_nodes[0].itertext()).strip() if topic_nodes else ""

    if not topic_nodes:
        warnings.append("wsnt:Topic element is absent from NotificationMessage")
        parse_status = "partial"
        diagnosis = NotificationDiagnosis.TOPIC_ABSENT
    else:
        dialect = topic_nodes[0].get("Dialect", "")
        if dialect and dialect not in _KNOWN_ONVIF_TOPIC_DIALECTS:
            warnings.append(
                f"Topic Dialect={dialect!r} is not a recognised ONVIF dialect; "
                f"known: {sorted(_KNOWN_ONVIF_TOPIC_DIALECTS)}"
            )
            # Not a hard failure — we can still parse the rest

    # ------------------------------------------------------------------
    # 2. Find the inner tt:Message element
    # ------------------------------------------------------------------
    message_nodes = notif_el.xpath(".//*[local-name()='Message'][@UtcTime]")

    # Check immediately if the found Message is under the wrong namespace
    # (local-name() XPath is namespace-agnostic, so it matches vendor elements too)
    if message_nodes:
        msg_ns = etree.QName(message_nodes[0]).namespace
        if msg_ns and msg_ns != _EXPECTED_TT_NS:
            warnings.append(
                f"tt:Message found under namespace {msg_ns!r} "
                f"instead of {_EXPECTED_TT_NS!r} — "
                "camera is using a vendor-specific schema"
            )
            parse_status = "partial"
            if diagnosis == NotificationDiagnosis.COMPLIANT:
                diagnosis = NotificationDiagnosis.MESSAGE_ELEMENT_WRONG_NAMESPACE

    if not message_nodes:
        all_msg = notif_el.xpath(".//*[local-name()='Message']")
        with_op = [m for m in all_msg if m.get("PropertyOperation") is not None]
        candidates = with_op if with_op else [m for m in all_msg if len(m) > 0]
        if not candidates:
            candidates = all_msg

        if not candidates:
            # wsnt:Message wrapper empty?
            wsnt_msg = notif_el.xpath("./*[local-name()='Message']")
            if wsnt_msg and len(wsnt_msg[0]) == 0:
                warnings.append(
                    "wsnt:Message wrapper is present but empty — "
                    "camera sent the notification envelope with no payload"
                )
            else:
                # Look for Message under a wrong namespace
                # Exclude wsnt:Message (the wrapper element itself)
                _WSNT_NS = "http://docs.oasis-open.org/wsn/b-2"
                wrong_ns = [
                    el for el in notif_el.iter()
                    if etree.QName(el).localname == "Message"
                    and etree.QName(el).namespace not in (_EXPECTED_TT_NS, _WSNT_NS, None)
                    and el is not notif_el
                ]
                if wrong_ns:
                    actual_ns = etree.QName(wrong_ns[0]).namespace
                    warnings.append(
                        f"Message element found under namespace {actual_ns!r} "
                        f"instead of {_EXPECTED_TT_NS!r} — "
                        "camera is using a vendor-specific schema"
                    )
                    diagnosis = NotificationDiagnosis.MESSAGE_ELEMENT_WRONG_NAMESPACE
                    candidates = wrong_ns
                else:
                    warnings.append(
                        "NotificationMessage contains no inner Message element"
                    )
            if not candidates:
                parse_status = "partial"
                if diagnosis == NotificationDiagnosis.COMPLIANT:
                    diagnosis = NotificationDiagnosis.MESSAGE_ELEMENT_ABSENT
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
                    diagnosis=diagnosis,
                    actual_namespaces=actual_namespaces,
                )

        # Check if the found Message is deeper than expected
        # Skip this check if the only candidate is the wsnt:Message wrapper itself
        _WSNT_NS = "http://docs.oasis-open.org/wsn/b-2"
        is_only_wsnt_wrapper = (
            len(candidates) == 1
            and etree.QName(candidates[0]).namespace == _WSNT_NS
        )
        if not is_only_wsnt_wrapper:
            wsnt_direct = []
            for wsnt_m in notif_el.xpath("./*[local-name()='Message']"):
                wsnt_direct.extend(wsnt_m.xpath("./*[local-name()='Message']"))
            if candidates[0] not in wsnt_direct and not with_op:
                warnings.append(
                    "tt:Message found but not as a direct child of wsnt:Message — "
                    "camera nested it deeper than the ONVIF spec requires"
                )
                if diagnosis == NotificationDiagnosis.COMPLIANT:
                    diagnosis = NotificationDiagnosis.MESSAGE_ELEMENT_DEEPER_THAN_EXPECTED
        else:
            # The only 'Message' found is the wsnt:Message wrapper with no children
            warnings.append(
                "wsnt:Message wrapper is present but contains no tt:Message child"
            )
            if diagnosis == NotificationDiagnosis.COMPLIANT:
                diagnosis = NotificationDiagnosis.MESSAGE_ELEMENT_ABSENT

        warnings.append("tt:Message present but UtcTime attribute is absent")
        message_nodes = candidates

    msg = message_nodes[0]

    # ------------------------------------------------------------------
    # 3. UtcTime
    # ------------------------------------------------------------------
    utc_str = msg.get("UtcTime", "")
    utc = _parse_utc(utc_str)
    timestamp_valid = utc is not None

    if not utc_str:
        warnings.append("UtcTime attribute is absent from tt:Message")
        parse_status = "partial"
        if diagnosis == NotificationDiagnosis.COMPLIANT:
            diagnosis = NotificationDiagnosis.UTCTIME_ABSENT
        utc = datetime(1970, 1, 1, tzinfo=timezone.utc)
    elif utc is None:
        log.warning("Could not parse UtcTime=%r in NotificationMessage", utc_str)
        warnings.append(
            f"UtcTime={utc_str!r} is present but not valid ISO-8601"
        )
        parse_status = "partial"
        if diagnosis == NotificationDiagnosis.COMPLIANT:
            diagnosis = NotificationDiagnosis.UTCTIME_UNPARSEABLE
        utc = datetime(1970, 1, 1, tzinfo=timezone.utc)

    # ------------------------------------------------------------------
    # 4. PropertyOperation
    # ------------------------------------------------------------------
    operation = msg.get("PropertyOperation", "")
    if not operation:
        warnings.append(
            "PropertyOperation attribute is absent from tt:Message; "
            "cannot determine if this is Initialized/Changed/Deleted"
        )
        parse_status = "partial"
        if diagnosis == NotificationDiagnosis.COMPLIANT:
            diagnosis = NotificationDiagnosis.PROPERTY_OPERATION_ABSENT

    # ------------------------------------------------------------------
    # 5. Source / Key / Data sections
    # ------------------------------------------------------------------
    source_el_list = msg.xpath("./*[local-name()='Source']")
    key_el_list = msg.xpath("./*[local-name()='Key']")
    data_el_list = msg.xpath("./*[local-name()='Data']")

    source_items = _simple_items(source_el_list[0]) if source_el_list else []
    key_items = _simple_items(key_el_list[0]) if key_el_list else []
    data_items = _simple_items(data_el_list[0]) if data_el_list else []

    if not data_el_list:
        warnings.append(
            "tt:Data section is absent — no SimpleItem payload in this notification"
        )
        parse_status = "partial"
        if diagnosis == NotificationDiagnosis.COMPLIANT:
            diagnosis = NotificationDiagnosis.DATA_SECTION_ABSENT

    # ------------------------------------------------------------------
    # 6. IsMotion extraction with wrong-name detection
    # ------------------------------------------------------------------
    is_motion: Optional[bool] = None
    state: Optional[bool] = None
    boolean_items_with_wrong_name: List[str] = []

    for item in data_items:
        if item.name == "IsMotion":
            is_motion = _to_bool(item.value)
        elif item.name == "State":
            state = _to_bool(item.value)
        else:
            if _to_bool(item.value) is not None:
                boolean_items_with_wrong_name.append(item.name)

    if is_motion is None and data_el_list:
        if boolean_items_with_wrong_name:
            warnings.append(
                f"No IsMotion SimpleItem found, but these items have boolean values "
                f"and may be the motion indicator under a different name: "
                f"{boolean_items_with_wrong_name}. "
                f"This is a naming mismatch — the camera does not use the ONVIF-standard "
                f"'IsMotion' item name."
            )
            parse_status = "partial"
            if diagnosis == NotificationDiagnosis.COMPLIANT:
                diagnosis = NotificationDiagnosis.ISMOTION_ITEM_WRONG_NAME
        elif data_items:
            warnings.append(
                f"tt:Data present but no IsMotion SimpleItem found. "
                f"Items present: {[i.name for i in data_items]}"
            )
            parse_status = "partial"
            if diagnosis == NotificationDiagnosis.COMPLIANT:
                diagnosis = NotificationDiagnosis.ISMOTION_ITEM_ABSENT

    # ------------------------------------------------------------------
    # 7. Namespace check on SimpleItems
    # ------------------------------------------------------------------
    if data_el_list:
        all_simple = data_el_list[0].xpath(".//*[local-name()='SimpleItem']")
        wrong_ns_items = [
            el for el in all_simple
            if etree.QName(el).namespace
            and etree.QName(el).namespace != _EXPECTED_TT_NS
        ]
        if wrong_ns_items:
            actual_ns = etree.QName(wrong_ns_items[0]).namespace
            warnings.append(
                f"SimpleItem elements are under namespace {actual_ns!r} "
                f"instead of {_EXPECTED_TT_NS!r} — "
                "camera is using a vendor-specific schema for data items"
            )
            if diagnosis == NotificationDiagnosis.COMPLIANT:
                diagnosis = NotificationDiagnosis.WRONG_NAMESPACE_ON_SIMPLEITEMS

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
        diagnosis=diagnosis,
        actual_namespaces=actual_namespaces,
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
