"""Unit tests for ``onvif_compare.onvif_client``.

Tests cover the pure-logic helpers (_parse_notification, _to_bool, etc.).
No camera connection required.  No network access.
"""

from __future__ import annotations

from datetime import timezone
from unittest.mock import MagicMock

import pytest
from lxml import etree

from onvif_compare.models import EventSource
from onvif_compare.onvif_client import (
    _classify_connect_error,
    _parse_notification,
    _parse_utc,
    _simple_items_from_element,
    _to_bool,
    _zeep_to_element,
)


class TestToBool:
    def test_true_string(self):
        assert _to_bool("true") is True

    def test_false_string(self):
        assert _to_bool("false") is False

    def test_one(self):
        assert _to_bool("1") is True

    def test_zero(self):
        assert _to_bool("0") is False

    def test_uppercase(self):
        assert _to_bool("TRUE") is True

    def test_none(self):
        assert _to_bool(None) is None

    def test_unknown(self):
        assert _to_bool("maybe") is None


class TestParseUtc:
    def test_z_suffix(self):
        dt = _parse_utc("2024-03-15T08:41:01.123Z")
        assert dt is not None
        assert dt.tzinfo is not None
        assert dt.year == 2024

    def test_offset(self):
        dt = _parse_utc("2024-03-15T08:41:01+00:00")
        assert dt is not None

    def test_none(self):
        assert _parse_utc(None) is None

    def test_empty(self):
        assert _parse_utc("") is None

    def test_garbage(self):
        assert _parse_utc("not-a-date") is None


class TestZeepToElement:
    def test_already_element(self):
        el = etree.fromstring(b"<root/>")
        assert _zeep_to_element(el) is el

    def test_value_1_element(self):
        el = etree.fromstring(b"<root/>")
        mock = MagicMock()
        mock._value_1 = el
        assert _zeep_to_element(mock) is el

    def test_value_1_list(self):
        el = etree.fromstring(b"<root/>")
        mock = MagicMock()
        mock._value_1 = [el]
        assert _zeep_to_element(mock) is el

    def test_none_returns_none(self):
        assert _zeep_to_element(None) is None


class TestSimpleItemsFromElement:
    def test_extracts_items(self):
        xml = b"""
        <tt:Data xmlns:tt="http://www.onvif.org/ver10/schema">
          <tt:SimpleItem Name="IsMotion" Value="true"/>
          <tt:SimpleItem Name="ObjectId" Value="42"/>
        </tt:Data>
        """
        el = etree.fromstring(xml)
        items = _simple_items_from_element(el)
        assert len(items) == 2
        names = {i.name for i in items}
        assert "IsMotion" in names
        assert "ObjectId" in names

    def test_empty_element(self):
        el = etree.fromstring(b"<Data/>")
        assert _simple_items_from_element(el) == []


class TestParseNotification:
    def _make_notification(self, is_motion: str = "true", operation: str = "Changed"):
        """Build a minimal zeep-like notification mock."""
        xml = f"""
        <tt:Message xmlns:tt="http://www.onvif.org/ver10/schema"
                    UtcTime="2024-03-15T08:41:01.123Z"
                    PropertyOperation="{operation}">
          <tt:Source>
            <tt:SimpleItem Name="VideoSourceConfigurationToken" Value="vsconf"/>
          </tt:Source>
          <tt:Key/>
          <tt:Data>
            <tt:SimpleItem Name="IsMotion" Value="{is_motion}"/>
          </tt:Data>
        </tt:Message>
        """.encode()
        element = etree.fromstring(xml)

        mock = MagicMock()
        mock.Message._value_1 = element
        mock.Topic._value_1 = "tns1:VideoAnalytics/Motion"
        return mock

    def test_is_motion_true(self):
        notif = self._make_notification("true")
        event = _parse_notification(notif, EventSource.LOCAL)
        assert event is not None
        assert event.is_motion is True

    def test_is_motion_false(self):
        notif = self._make_notification("false")
        event = _parse_notification(notif, EventSource.LOCAL)
        assert event.is_motion is False

    def test_operation(self):
        notif = self._make_notification(operation="Changed")
        event = _parse_notification(notif, EventSource.LOCAL)
        assert event.operation == "Changed"

    def test_source(self):
        notif = self._make_notification()
        event = _parse_notification(notif, EventSource.PROTECT)
        assert event.source == EventSource.PROTECT

    def test_utc_parsed(self):
        notif = self._make_notification()
        event = _parse_notification(notif, EventSource.LOCAL)
        assert event.utc.year == 2024

    def test_raw_xml_retained(self):
        notif = self._make_notification()
        event = _parse_notification(notif, EventSource.LOCAL)
        assert "Message" in event.raw_xml

    def test_no_message_element_returns_none(self):
        mock = MagicMock()
        mock.Message = None
        result = _parse_notification(mock, EventSource.LOCAL)
        assert result is None

    def test_provenance_minus_one(self):
        notif = self._make_notification()
        event = _parse_notification(notif, EventSource.LOCAL)
        assert event.tcp_stream == -1
        assert event.frame_number == -1


class TestSoapHistoryPlugin:
    def _make_envelope(self, tag: str = "PullMessages") -> "etree._Element":
        from lxml import etree
        return etree.fromstring(
            f'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
            f'<s:Body><tev:{tag} xmlns:tev="http://www.onvif.org/ver10/events/wsdl"/>'
            f'</s:Body></s:Envelope>'.encode()
        )

    def test_egress_stores_pending(self):
        from onvif_compare.onvif_client import _SoapHistoryPlugin
        plugin = _SoapHistoryPlugin()
        env = self._make_envelope()
        plugin.egress(env, {}, type('Op', (), {'name': 'PullMessages'})(), {})
        assert plugin._pending_operation == "PullMessages"
        assert plugin._pending_request is not None

    def test_ingress_creates_record(self):
        from onvif_compare.onvif_client import _SoapHistoryPlugin
        plugin = _SoapHistoryPlugin()
        req_env = self._make_envelope("PullMessages")
        resp_env = self._make_envelope("PullMessagesResponse")
        plugin.egress(req_env, {}, type('Op', (), {'name': 'PullMessages'})(), {})
        plugin.ingress(resp_env, {}, type('Op', (), {'name': 'PullMessages'})())
        assert len(plugin.records) == 1
        assert plugin.records[0].operation == "PullMessages"
        assert "PullMessages" in plugin.records[0].request_envelope
        assert "PullMessagesResponse" in plugin.records[0].response_envelope

    def test_sha256_populated(self):
        from onvif_compare.onvif_client import _SoapHistoryPlugin
        plugin = _SoapHistoryPlugin()
        env = self._make_envelope()
        plugin.egress(env, {}, type('Op', (), {'name': 'PullMessages'})(), {})
        plugin.ingress(env, {}, type('Op', (), {'name': 'PullMessages'})())
        assert len(plugin.records[0].request_sha256) == 64
        assert len(plugin.records[0].response_sha256) == 64

    def test_max_records_enforced(self):
        from onvif_compare.onvif_client import _SoapHistoryPlugin
        plugin = _SoapHistoryPlugin(max_records=3)
        env = self._make_envelope()
        for _ in range(5):
            plugin.egress(env, {}, type('Op', (), {'name': 'PullMessages'})(), {})
            plugin.ingress(env, {}, type('Op', (), {'name': 'PullMessages'})())
        assert len(plugin.records) == 3


class TestClassifyConnectError:
    def test_auth_hint_401(self):
        msg = _classify_connect_error(Exception("401 Unauthorized"))
        assert "Authentication failed" in msg
        assert "--camera-password" in msg

    def test_auth_hint_not_authorized(self):
        msg = _classify_connect_error(Exception("Sender not authorized"))
        assert "Authentication failed" in msg

    def test_pullpoint_hint_surfaces_both_causes(self):
        msg = _classify_connect_error(Exception("Device doesn't support service: pullpoint"))
        assert "Wrong password" in msg
        assert "--camera-port" in msg

    def test_pullpoint_hint_backtick_variant(self):
        # Some cameras (e.g. Reolink) use a backtick: "doesn`t"
        msg = _classify_connect_error(Exception("Device doesn`t support service: pullpoint"))
        assert "Wrong password" in msg

    def test_pullpoint_hint_unknown_error_prefix(self):
        # onvif-zeep wraps the message as "Unknown error: Device doesn`t ..."
        msg = _classify_connect_error(Exception("Unknown error: Device doesn`t support service: pullpoint"))
        assert "Wrong password" in msg

    def test_unknown_error_returns_type_and_message(self):
        msg = _classify_connect_error(ValueError("something unexpected"))
        assert "ValueError" in msg
        assert "something unexpected" in msg
