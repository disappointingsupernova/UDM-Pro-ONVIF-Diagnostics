"""Unit tests for ``onvif_compare.soap``.

All tests use synthetic XML fixtures from ``tests/fixtures/``.
No network access.  No PCAP files required.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from onvif_compare.models import (
    EventSource,
    SoapOperation,
    SubscriptionEvent,
)
from onvif_compare.soap import (
    SoapParseError,
    parse_envelope,
    parse_fault,
    parse_notifications,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


# ---------------------------------------------------------------------------
# PullMessagesResponse — IsMotion=true
# ---------------------------------------------------------------------------


class TestMotionTrue:
    def setup_method(self):
        self.xml = _load("motion_true.xml")
        self.op, self.events = parse_envelope(
            self.xml,
            http_status=200,
            tcp_stream=12,
            frame_number=100,
            source=EventSource.PROTECT,
        )

    def test_operation(self):
        assert self.op == SoapOperation.PULL_MESSAGES_RESPONSE

    def test_one_event(self):
        assert len(self.events) == 1

    def test_is_motion_true(self):
        assert self.events[0].is_motion is True

    def test_operation_changed(self):
        assert self.events[0].operation == "Changed"

    def test_utc_parsed(self):
        assert self.events[0].utc.year == 2024
        assert self.events[0].utc.second == 1

    def test_topic_present(self):
        assert "VideoAnalytics" in self.events[0].topic

    def test_source_items(self):
        names = [i.name for i in self.events[0].source_items]
        assert "VideoSourceConfigurationToken" in names
        assert "Rule" in names

    def test_data_items(self):
        names = [i.name for i in self.events[0].data_items]
        assert "IsMotion" in names
        assert "ObjectId" in names

    def test_provenance(self):
        assert self.events[0].tcp_stream == 12
        assert self.events[0].frame_number == 100
        assert self.events[0].source == EventSource.PROTECT

    def test_raw_xml_retained(self):
        assert "NotificationMessage" in self.events[0].raw_xml


# ---------------------------------------------------------------------------
# PullMessagesResponse — IsMotion=false
# ---------------------------------------------------------------------------


class TestMotionFalse:
    def setup_method(self):
        xml = _load("motion_false.xml")
        _, self.events = parse_envelope(xml, source=EventSource.LOCAL)

    def test_is_motion_false(self):
        assert self.events[0].is_motion is False

    def test_source(self):
        assert self.events[0].source == EventSource.LOCAL


# ---------------------------------------------------------------------------
# Empty PullMessagesResponse
# ---------------------------------------------------------------------------


class TestEmptyPull:
    def setup_method(self):
        xml = _load("empty_pull.xml")
        self.op, self.events = parse_envelope(xml)

    def test_operation(self):
        assert self.op == SoapOperation.PULL_MESSAGES_RESPONSE

    def test_no_events(self):
        assert self.events == []

    def test_parse_notifications_returns_empty_list(self):
        xml = _load("empty_pull.xml")
        assert parse_notifications(xml) == []


# ---------------------------------------------------------------------------
# SOAP fault
# ---------------------------------------------------------------------------


class TestSoapFault:
    def setup_method(self):
        self.xml = _load("soap_fault.xml")
        self.op, self.fault = parse_envelope(
            self.xml,
            http_status=500,
            tcp_stream=7,
            frame_number=55,
        )

    def test_operation(self):
        assert self.op == SoapOperation.FAULT

    def test_code(self):
        assert "Receiver" in self.fault.code

    def test_subcode(self):
        assert self.fault.subcode is not None
        assert "SubscriptionInvalid" in self.fault.subcode

    def test_reason(self):
        assert "subscription" in self.fault.reason.lower()

    def test_detail(self):
        assert self.fault.detail is not None
        assert "SubscriptionId" in self.fault.detail

    def test_http_status(self):
        assert self.fault.http_status == 500

    def test_provenance(self):
        assert self.fault.tcp_stream == 7
        assert self.fault.frame_number == 55

    def test_raw_xml_retained(self):
        assert "Fault" in self.fault.raw_xml

    def test_parse_fault_convenience(self):
        fault = parse_fault(self.xml, http_status=500)
        assert fault.code == self.fault.code

    def test_parse_notifications_returns_empty_on_fault(self):
        assert parse_notifications(self.xml) == []


# ---------------------------------------------------------------------------
# CreatePullPointSubscriptionResponse
# ---------------------------------------------------------------------------


class TestSubscription:
    def setup_method(self):
        self.xml = _load("subscription.xml")
        self.op, self.sub = parse_envelope(
            self.xml,
            tcp_stream=1,
            frame_number=10,
            source=EventSource.LOCAL,
        )

    def test_operation(self):
        assert self.op == SoapOperation.CREATE_PULLPOINT_RESPONSE

    def test_subscription_id(self):
        assert self.sub.subscription_id is not None
        assert "192.168.1.100" in self.sub.subscription_id or \
               "sub" in self.sub.subscription_id.lower()

    def test_termination_time(self):
        assert self.sub.termination_time is not None
        assert self.sub.termination_time.year == 2024

    def test_source(self):
        assert self.sub.source == EventSource.LOCAL

    def test_raw_xml_retained(self):
        assert "CreatePullPointSubscription" in self.sub.raw_xml


# ---------------------------------------------------------------------------
# PullMessages request (no parsed object expected)
# ---------------------------------------------------------------------------


class TestPullMessagesRequest:
    def test_request_returns_none_object(self):
        xml = _load("pullmessages.xml")
        op, obj = parse_envelope(xml)
        assert op == SoapOperation.PULL_MESSAGES
        assert obj is None


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    def test_malformed_xml_raises(self):
        with pytest.raises(SoapParseError):
            parse_envelope(b"<not valid xml")

    def test_non_envelope_raises(self):
        with pytest.raises(SoapParseError):
            parse_envelope(b"<root><child/></root>")

    def test_parse_fault_on_non_fault_raises(self):
        xml = _load("motion_true.xml")
        with pytest.raises(SoapParseError):
            parse_fault(xml)

    def test_empty_bytes_raises(self):
        with pytest.raises(SoapParseError):
            parse_envelope(b"")
