"""Timeline builder and correlation engine.

The timeline is the single source of truth from which all reports are derived.
Every event — local motion, Protect poll, SOAP fault, subscription lifecycle —
is inserted in chronological order as a ``TimelineEntry``.

Correlation engine
------------------
For each local ``MotionEvent`` with ``operation == "Changed"``, the engine
searches the timeline for the nearest Protect ``PullTransaction`` within a
configurable window (default 1000 ms).  It records:

- ``nearest_before``  — closest poll that occurred *before* the motion event
- ``nearest_after``   — closest poll that occurred *after* the motion event
- ``nearest_absolute`` — whichever of the two is temporally closer

All three are stored in ``CorrelationRecord`` so the report can present full
timing information.  No timing information is ever hidden.

Classification
--------------
The result is classified as one of:

``NOTIFICATION_PRESENT``
    The nearest poll's response contained at least one ``NotificationMessage``.
``EMPTY_RESPONSE``
    The nearest poll returned HTTP 200 but zero notifications.
``SOAP_FAULT``
    The nearest poll returned a SOAP fault.
``HTTP_ERROR``
    The nearest poll returned a non-200, non-fault HTTP status.
``NO_POLL_IN_WINDOW``
    No Protect poll was found within the correlation window.
``TIMEOUT``
    The nearest poll had no response (response_frame == -1).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Optional

from .models import (
    CorrelationRecord,
    CorrelationResult,
    EvidenceBundle,
    EventSource,
    MotionEvent,
    PullTransaction,
    SoapFault,
    SubscriptionEvent,
    TimelineEntry,
    TimelineEventKind,
)

log = logging.getLogger(__name__)

_DEFAULT_WINDOW_MS = 1000


# ---------------------------------------------------------------------------
# Timeline construction
# ---------------------------------------------------------------------------


def build_timeline(
    *,
    protect_transactions: List[PullTransaction],
    local_transactions: List[PullTransaction],
    local_events: List[MotionEvent],
    soap_faults: List[SoapFault],
    subscription_events: List[SubscriptionEvent],
) -> List[TimelineEntry]:
    """Merge all event sources into a single chronological ``TimelineEntry`` list.

    Parameters
    ----------
    protect_transactions:
        PullMessages transactions from the PCAP attributed to Protect.
    local_transactions:
        PullMessages transactions from the PCAP attributed to the local subscriber.
    local_events:
        Motion events received by the live ONVIF subscriber.
    soap_faults:
        All SOAP faults extracted from the PCAP.
    subscription_events:
        Subscription lifecycle events (create, renew, unsubscribe).

    Returns
    -------
    List of ``TimelineEntry`` objects sorted by UTC timestamp.
    """
    entries: List[TimelineEntry] = []

    for txn in protect_transactions:
        entries.append(_entry_from_pull(txn))

    for txn in local_transactions:
        entries.append(_entry_from_pull(txn))

    for event in local_events:
        entries.append(_entry_from_motion(event))

    for fault in soap_faults:
        entries.append(_entry_from_fault(fault))

    for sub in subscription_events:
        entries.append(_entry_from_subscription(sub))

    entries.sort(key=lambda e: e.utc)
    return entries


def _entry_from_pull(txn: PullTransaction) -> TimelineEntry:
    notif_count = len(txn.notifications)
    fault_str = f" FAULT={txn.soap_fault.code}" if txn.soap_fault else ""
    desc = (
        f"{txn.source.value} PullMessages → "
        f"HTTP {txn.http_status} "
        f"{notif_count} notification(s){fault_str} "
        f"[stream {txn.tcp_stream}]"
    )
    return TimelineEntry(
        utc=txn.request_time,
        kind=TimelineEventKind.PULL_TRANSACTION,
        source=txn.source,
        description=desc,
        pull_transaction=txn,
    )


def _entry_from_motion(event: MotionEvent) -> TimelineEntry:
    desc = (
        f"{event.source.value} {event.operation} "
        f"IsMotion={event.is_motion} State={event.state} "
        f"topic={event.topic}"
    )
    return TimelineEntry(
        utc=event.utc,
        kind=TimelineEventKind.MOTION_EVENT,
        source=event.source,
        description=desc,
        motion_event=event,
    )


def _entry_from_fault(fault: SoapFault) -> TimelineEntry:
    desc = (
        f"SOAP Fault {fault.code} / {fault.subcode} — {fault.reason} "
        f"[stream {fault.tcp_stream} frame {fault.frame_number}]"
    )
    # Faults don't carry a timestamp directly; use a sentinel
    utc = datetime.now(tz=timezone.utc)
    return TimelineEntry(
        utc=utc,
        kind=TimelineEventKind.SOAP_FAULT,
        source=EventSource.CAMERA,
        description=desc,
        soap_fault=fault,
    )


def _entry_from_subscription(sub: SubscriptionEvent) -> TimelineEntry:
    desc = (
        f"{sub.source.value} {sub.operation.value} "
        f"sub_id={sub.subscription_id} "
        f"expires={sub.termination_time}"
    )
    return TimelineEntry(
        utc=sub.utc,
        kind=TimelineEventKind.SUBSCRIPTION,
        source=sub.source,
        description=desc,
        subscription_event=sub,
    )


# ---------------------------------------------------------------------------
# Correlation engine
# ---------------------------------------------------------------------------


def correlate(
    timeline: List[TimelineEntry],
    *,
    window_ms: int = _DEFAULT_WINDOW_MS,
) -> List[CorrelationRecord]:
    """Correlate local motion events with the nearest Protect PullMessages polls.

    Parameters
    ----------
    timeline:
        The sorted timeline produced by ``build_timeline()``.
    window_ms:
        Maximum search window in milliseconds (default 1000).

    Returns
    -------
    One ``CorrelationRecord`` per local ``Changed`` motion event.
    """
    protect_polls = [
        e.pull_transaction
        for e in timeline
        if e.kind == TimelineEventKind.PULL_TRANSACTION
        and e.source == EventSource.PROTECT
        and e.pull_transaction is not None
    ]

    local_motion = [
        e.motion_event
        for e in timeline
        if e.kind == TimelineEventKind.MOTION_EVENT
        and e.motion_event is not None
        and e.motion_event.operation == "Changed"
    ]

    records: List[CorrelationRecord] = []
    for event in local_motion:
        record = _correlate_one(event, protect_polls, window_ms)
        records.append(record)

    return records


def _correlate_one(
    event: MotionEvent,
    polls: List[PullTransaction],
    window_ms: int,
) -> CorrelationRecord:
    event_ts = event.utc.timestamp()
    window_s = window_ms / 1000.0

    before: Optional[PullTransaction] = None
    after: Optional[PullTransaction] = None
    delta_before: Optional[float] = None
    delta_after: Optional[float] = None

    for poll in polls:
        poll_ts = poll.request_time.timestamp()
        diff = event_ts - poll_ts  # positive = poll was before event

        if diff >= 0 and diff <= window_s:
            if delta_before is None or diff < delta_before:
                delta_before = diff
                before = poll

        elif diff < 0 and abs(diff) <= window_s:
            if delta_after is None or abs(diff) < delta_after:
                delta_after = abs(diff)
                after = poll

    # Determine absolute nearest
    nearest: Optional[PullTransaction] = None
    if before is not None and after is not None:
        nearest = before if (delta_before or 0) <= (delta_after or 0) else after
    elif before is not None:
        nearest = before
    elif after is not None:
        nearest = after

    result = _classify(nearest)

    return CorrelationRecord(
        local_event=event,
        nearest_before=before,
        nearest_after=after,
        nearest_absolute=nearest,
        delta_before_ms=delta_before * 1000 if delta_before is not None else None,
        delta_after_ms=delta_after * 1000 if delta_after is not None else None,
        result=result,
        window_ms=window_ms,
    )


def _classify(poll: Optional[PullTransaction]) -> CorrelationResult:
    if poll is None:
        return CorrelationResult.NO_POLL_IN_WINDOW
    if poll.response_frame == -1:
        return CorrelationResult.TIMEOUT
    if poll.soap_fault is not None:
        return CorrelationResult.SOAP_FAULT
    if poll.http_status != 200:
        return CorrelationResult.HTTP_ERROR
    if poll.notifications:
        return CorrelationResult.NOTIFICATION_PRESENT
    return CorrelationResult.EMPTY_RESPONSE


# ---------------------------------------------------------------------------
# Observations (evidence-based, no blame)
# ---------------------------------------------------------------------------


def build_observations(bundle: "EvidenceBundle") -> List[str]:
    """Produce an ordered list of factual observation strings.

    The tool never assigns blame.  It records what was observed.
    The engineer reading the report draws conclusions.
    """
    obs: List[str] = []

    local_changed = [
        e for e in bundle.local_events if e.operation == "Changed"
    ]
    local_true = [e for e in local_changed if e.is_motion is True]
    local_false = [e for e in local_changed if e.is_motion is False]

    protect_txns = bundle.protect_transactions
    protect_notifs = [n for t in protect_txns for n in t.notifications]
    protect_true = [e for e in protect_notifs if e.is_motion is True]

    obs.append(
        f"The independent local subscriber received "
        f"{len(local_true)} IsMotion=true and "
        f"{len(local_false)} IsMotion=false Changed events."
    )

    obs.append(
        f"Protect issued {len(protect_txns)} PullMessages request(s) "
        f"during the capture period."
    )

    empty = [t for t in protect_txns if not t.notifications and t.soap_fault is None and t.http_status == 200]
    obs.append(
        f"Of those, {len(empty)} returned HTTP 200 with zero NotificationMessage elements."
    )

    if bundle.soap_faults:
        obs.append(
            f"{len(bundle.soap_faults)} SOAP fault(s) were observed in the capture."
        )
    else:
        obs.append("No SOAP faults were observed in the capture.")

    if protect_true:
        obs.append(
            f"Protect received {len(protect_true)} IsMotion=true notification(s)."
        )
    else:
        obs.append(
            "Protect received zero IsMotion=true notifications during the capture period."
        )

    if bundle.metadata.capture_mode == "remote":
        obs.append(
            f"Traffic was captured on interface {bundle.metadata.capture_interface} "
            f"of {bundle.metadata.capture_host}."
        )

    # Capture quality warnings
    for warning in bundle.capture_quality.warnings:
        obs.append(f"CAPTURE QUALITY WARNING: {warning}")

    # --- Additional inferences from timing and subscription data ---

    # PullMessages response latency
    if protect_txns:
        latencies = [
            (t.response_time - t.request_time).total_seconds() * 1000
            for t in protect_txns
            if t.response_time and t.request_time
            and t.response_time > t.request_time
        ]
        if latencies:
            avg_ms = sum(latencies) / len(latencies)
            min_ms = min(latencies)
            obs.append(
                f"Protect PullMessages average response latency: {avg_ms:.0f} ms "
                f"(min {min_ms:.0f} ms). "
                + (
                    "Responses under 100 ms suggest the camera is not holding the "
                    "connection open (long-polling not implemented)."
                    if min_ms < 100 else
                    "Response latency is consistent with long-polling behaviour."
                )
            )

    # Subscription termination time (short lease = explains dropped subscriptions)
    from .models import SoapOperation
    sub_events = [
        e.subscription_event
        for e in bundle.timeline
        if e.subscription_event is not None
        and e.subscription_event.operation == SoapOperation.CREATE_PULLPOINT_RESPONSE
        and e.subscription_event.termination_time is not None
        and e.subscription_event.utc.year > 1970
    ]
    for sub in sub_events:
        lease_s = (
            sub.termination_time - sub.utc
        ).total_seconds() if sub.termination_time and sub.utc.year > 1970 else None
        if lease_s is not None and lease_s < 120:
            obs.append(
                f"Camera granted a PullPoint subscription lease of only {lease_s:.0f} s "
                f"(subscription ID: {sub.subscription_id}). "
                "Short leases require frequent renewal and may cause missed events "
                "if the subscriber does not renew in time."
            )

    # Partial notification diagnosis summary
    all_notifs = [n for t in protect_txns for n in t.notifications] + bundle.local_events
    partial = [n for n in all_notifs if n.parse_status == "partial"]
    if partial:
        from .models import NotificationDiagnosis
        diagnoses = {}
        for n in partial:
            d = n.diagnosis.value if n.diagnosis else "unknown"
            diagnoses[d] = diagnoses.get(d, 0) + 1
        for diag, count in sorted(diagnoses.items()):
            obs.append(
                f"{count} notification(s) received with structural issue: {diag}. "
                + _diagnosis_explanation(diag)
            )

    return obs


# Plain-English explanations for each diagnosis value
_DIAGNOSIS_EXPLANATIONS = {
    "topic_absent": (
        "The camera sent a NotificationMessage with no wsnt:Topic element. "
        "The topic is required by ONVIF to identify the event type."
    ),
    "topic_unknown_dialect": (
        "The camera used a non-standard Topic Dialect URI. "
        "Protect may not recognise the topic and could silently discard the notification."
    ),
    "message_element_absent": (
        "The wsnt:Message wrapper was empty — the camera sent the notification "
        "envelope but included no payload. This is a camera firmware bug."
    ),
    "message_element_wrong_namespace": (
        "The inner Message element was found under a vendor-specific namespace "
        "instead of http://www.onvif.org/ver10/schema. "
        "Protect's parser likely expects the standard namespace and may discard this."
    ),
    "message_element_deeper_than_expected": (
        "The tt:Message element was nested deeper than the ONVIF spec requires. "
        "A strict parser would not find it at the expected depth."
    ),
    "utctime_absent": (
        "The tt:Message element was missing the required UtcTime attribute. "
        "This is a camera non-compliance with ONVIF Event Service spec section 9.4."
    ),
    "utctime_unparseable": (
        "The UtcTime attribute was present but not valid ISO-8601. "
        "This may cause timestamp-based filtering to fail."
    ),
    "property_operation_absent": (
        "The PropertyOperation attribute (Initialized/Changed/Deleted) was absent. "
        "Protect may require this to determine whether to trigger a recording."
    ),
    "data_section_absent": (
        "No tt:Data section was present in the message. "
        "Without data items there is no IsMotion value to act on."
    ),
    "ismotion_item_absent": (
        "The tt:Data section was present but contained no IsMotion SimpleItem. "
        "The camera may be using a different topic schema that does not include IsMotion."
    ),
    "ismotion_item_wrong_name": (
        "A boolean-valued SimpleItem was found but not named 'IsMotion'. "
        "The camera is using a non-standard item name. "
        "Protect's parser looks specifically for 'IsMotion' and will not find it."
    ),
    "wrong_namespace_on_simpleitems": (
        "SimpleItem elements were found under a vendor namespace instead of "
        "http://www.onvif.org/ver10/schema. "
        "A namespace-aware parser would not match these as standard ONVIF data items."
    ),
}


def _diagnosis_explanation(diagnosis: str) -> str:
    return _DIAGNOSIS_EXPLANATIONS.get(diagnosis, "")
