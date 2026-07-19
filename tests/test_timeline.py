"""Unit tests for ``onvif_compare.timeline``.

Tests cover:
- ``build_timeline()`` — ordering and entry kinds
- ``correlate()``      — nearest_before, nearest_after, nearest_absolute,
                         delta_ms values, all CorrelationResult variants
- ``_classify()``      — each classification branch

No network access.  No PCAP files.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

import pytest

from onvif_compare.models import (
    CorrelationResult,
    EventSource,
    MotionEvent,
    PullTransaction,
    SoapFault,
    SoapOperation,
    TimelineEventKind,
)
from onvif_compare.timeline import (
    _classify,
    build_timeline,
    correlate,
)


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------


def _utc(hour: int, minute: int, second: int, ms: int = 0) -> datetime:
    return datetime(2024, 3, 15, hour, minute, second,
                    ms * 1000, tzinfo=timezone.utc)


def _motion(utc: datetime, is_motion: bool = True, operation: str = "Changed") -> MotionEvent:
    return MotionEvent(
        utc=utc,
        operation=operation,
        is_motion=is_motion,
        state=None,
        topic="tns1:VideoAnalytics/Motion",
        source_items=[],
        key_items=[],
        data_items=[],
        source=EventSource.LOCAL,
        tcp_stream=-1,
        frame_number=-1,
        raw_xml="<Message/>",
    )


def _pull(
    utc: datetime,
    http_status: int = 200,
    notifications: Optional[List[MotionEvent]] = None,
    fault: Optional[SoapFault] = None,
    source: EventSource = EventSource.PROTECT,
    response_frame: int = 99,
) -> PullTransaction:
    return PullTransaction(
        tcp_stream=1,
        request_frame=10,
        response_frame=response_frame,
        request_time=utc,
        response_time=utc,
        http_status=http_status,
        operation=SoapOperation.PULL_MESSAGES,
        notifications=notifications or [],
        soap_fault=fault,
        source=source,
        subscription_id=None,
        request_xml_path=None,
        response_xml_path=None,
        raw_request="",
        raw_response="",
    )


def _fault() -> SoapFault:
    return SoapFault(
        code="s:Receiver",
        subcode="ter:SubscriptionInvalid",
        reason="Expired",
        detail=None,
        http_status=500,
        tcp_stream=1,
        frame_number=20,
        raw_xml="<Fault/>",
    )


# ---------------------------------------------------------------------------
# build_timeline
# ---------------------------------------------------------------------------


class TestBuildTimeline:
    def test_sorted_by_utc(self):
        t1 = _utc(8, 41, 1)
        t2 = _utc(8, 41, 0)
        t3 = _utc(8, 41, 2)
        timeline = build_timeline(
            protect_transactions=[_pull(t1), _pull(t3)],
            local_transactions=[],
            local_events=[_motion(t2)],
            soap_faults=[],
            subscription_events=[],
        )
        times = [e.utc for e in timeline]
        assert times == sorted(times)

    def test_pull_transaction_kind(self):
        timeline = build_timeline(
            protect_transactions=[_pull(_utc(8, 41, 0))],
            local_transactions=[],
            local_events=[],
            soap_faults=[],
            subscription_events=[],
        )
        assert timeline[0].kind == TimelineEventKind.PULL_TRANSACTION

    def test_motion_event_kind(self):
        timeline = build_timeline(
            protect_transactions=[],
            local_transactions=[],
            local_events=[_motion(_utc(8, 41, 0))],
            soap_faults=[],
            subscription_events=[],
        )
        assert timeline[0].kind == TimelineEventKind.MOTION_EVENT

    def test_soap_fault_kind(self):
        timeline = build_timeline(
            protect_transactions=[],
            local_transactions=[],
            local_events=[],
            soap_faults=[_fault()],
            subscription_events=[],
        )
        assert timeline[0].kind == TimelineEventKind.SOAP_FAULT

    def test_empty_inputs(self):
        timeline = build_timeline(
            protect_transactions=[],
            local_transactions=[],
            local_events=[],
            soap_faults=[],
            subscription_events=[],
        )
        assert timeline == []

    def test_description_contains_source(self):
        timeline = build_timeline(
            protect_transactions=[_pull(_utc(8, 41, 0))],
            local_transactions=[],
            local_events=[],
            soap_faults=[],
            subscription_events=[],
        )
        assert "protect" in timeline[0].description

    def test_pull_transaction_payload_set(self):
        txn = _pull(_utc(8, 41, 0))
        timeline = build_timeline(
            protect_transactions=[txn],
            local_transactions=[],
            local_events=[],
            soap_faults=[],
            subscription_events=[],
        )
        assert timeline[0].pull_transaction is txn


# ---------------------------------------------------------------------------
# correlate — nearest_before / nearest_after
# ---------------------------------------------------------------------------


class TestCorrelate:
    def test_nearest_before(self):
        motion_t = _utc(8, 41, 1, 500)   # 08:41:01.500
        poll_t   = _utc(8, 41, 1, 200)   # 08:41:01.200  (300 ms before)
        timeline = build_timeline(
            protect_transactions=[_pull(poll_t)],
            local_transactions=[],
            local_events=[_motion(motion_t)],
            soap_faults=[],
            subscription_events=[],
        )
        records = correlate(timeline, window_ms=1000)
        assert len(records) == 1
        assert records[0].nearest_before is not None
        assert records[0].nearest_after is None
        assert abs(records[0].delta_before_ms - 300) < 1

    def test_nearest_after(self):
        motion_t = _utc(8, 41, 1, 0)
        poll_t   = _utc(8, 41, 1, 400)   # 400 ms after
        timeline = build_timeline(
            protect_transactions=[_pull(poll_t)],
            local_transactions=[],
            local_events=[_motion(motion_t)],
            soap_faults=[],
            subscription_events=[],
        )
        records = correlate(timeline, window_ms=1000)
        assert records[0].nearest_after is not None
        assert records[0].nearest_before is None
        assert abs(records[0].delta_after_ms - 400) < 1

    def test_nearest_absolute_prefers_closer(self):
        motion_t  = _utc(8, 41, 1, 500)
        before_t  = _utc(8, 41, 1, 200)  # 300 ms before
        after_t   = _utc(8, 41, 1, 600)  # 100 ms after
        timeline = build_timeline(
            protect_transactions=[_pull(before_t), _pull(after_t)],
            local_transactions=[],
            local_events=[_motion(motion_t)],
            soap_faults=[],
            subscription_events=[],
        )
        records = correlate(timeline, window_ms=1000)
        assert records[0].nearest_absolute is not None
        assert records[0].nearest_absolute.request_time == after_t

    def test_no_poll_in_window(self):
        motion_t = _utc(8, 41, 1, 0)
        poll_t   = _utc(8, 41, 5, 0)    # 4 s away — outside 1000 ms window
        timeline = build_timeline(
            protect_transactions=[_pull(poll_t)],
            local_transactions=[],
            local_events=[_motion(motion_t)],
            soap_faults=[],
            subscription_events=[],
        )
        records = correlate(timeline, window_ms=1000)
        assert records[0].result == CorrelationResult.NO_POLL_IN_WINDOW
        assert records[0].nearest_absolute is None

    def test_initialized_events_excluded(self):
        """Only 'Changed' events should be correlated."""
        motion_t = _utc(8, 41, 1, 0)
        poll_t   = _utc(8, 41, 1, 100)
        timeline = build_timeline(
            protect_transactions=[_pull(poll_t)],
            local_transactions=[],
            local_events=[_motion(motion_t, operation="Initialized")],
            soap_faults=[],
            subscription_events=[],
        )
        records = correlate(timeline, window_ms=1000)
        assert records == []

    def test_multiple_motion_events(self):
        t1 = _utc(8, 41, 1, 0)
        t2 = _utc(8, 41, 5, 0)
        poll1 = _pull(_utc(8, 41, 1, 100))
        poll2 = _pull(_utc(8, 41, 5, 100))
        timeline = build_timeline(
            protect_transactions=[poll1, poll2],
            local_transactions=[],
            local_events=[_motion(t1), _motion(t2)],
            soap_faults=[],
            subscription_events=[],
        )
        records = correlate(timeline, window_ms=1000)
        assert len(records) == 2

    def test_window_ms_respected(self):
        motion_t = _utc(8, 41, 1, 0)
        poll_t   = _utc(8, 41, 1, 999)  # 999 ms after — inside 1000 ms window
        timeline = build_timeline(
            protect_transactions=[_pull(poll_t)],
            local_transactions=[],
            local_events=[_motion(motion_t)],
            soap_faults=[],
            subscription_events=[],
        )
        records = correlate(timeline, window_ms=1000)
        assert records[0].nearest_after is not None

    def test_window_ms_boundary_excluded(self):
        motion_t = _utc(8, 41, 1, 0)
        poll_t   = _utc(8, 41, 2, 1)   # 1001 ms after — outside window
        timeline = build_timeline(
            protect_transactions=[_pull(poll_t)],
            local_transactions=[],
            local_events=[_motion(motion_t)],
            soap_faults=[],
            subscription_events=[],
        )
        records = correlate(timeline, window_ms=1000)
        assert records[0].result == CorrelationResult.NO_POLL_IN_WINDOW


# ---------------------------------------------------------------------------
# _classify
# ---------------------------------------------------------------------------


class TestClassify:
    def test_none_returns_no_poll(self):
        assert _classify(None) == CorrelationResult.NO_POLL_IN_WINDOW

    def test_notification_present(self):
        poll = _pull(_utc(8, 41, 0), notifications=[_motion(_utc(8, 41, 0))])
        assert _classify(poll) == CorrelationResult.NOTIFICATION_PRESENT

    def test_empty_response(self):
        poll = _pull(_utc(8, 41, 0), http_status=200, notifications=[])
        assert _classify(poll) == CorrelationResult.EMPTY_RESPONSE

    def test_soap_fault(self):
        poll = _pull(_utc(8, 41, 0), fault=_fault())
        assert _classify(poll) == CorrelationResult.SOAP_FAULT

    def test_http_error(self):
        poll = _pull(_utc(8, 41, 0), http_status=503)
        assert _classify(poll) == CorrelationResult.HTTP_ERROR

    def test_timeout(self):
        poll = _pull(_utc(8, 41, 0), response_frame=-1)
        assert _classify(poll) == CorrelationResult.TIMEOUT
