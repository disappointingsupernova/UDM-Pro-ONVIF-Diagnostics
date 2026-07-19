"""Unit tests for ``onvif_compare.report``.

Tests cover Markdown rendering, HTML generation, JSON serialisation,
CSV timeline output, and raw XML file saving.
No network access.  No PCAP files.
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List

import pytest

from onvif_compare.models import (
    CaptureMetadata,
    CorrelationRecord,
    CorrelationResult,
    EvidenceBundle,
    EventSource,
    MotionEvent,
    PullTransaction,
    SoapFault,
    SoapOperation,
    TimelineEntry,
    TimelineEventKind,
)
from onvif_compare.report import (
    ReportWriter,
    _render_html,
    _render_markdown,
    _timeline_to_csv,
    _timeline_to_json,
    bundle_to_json,
    save_raw_xml,
)


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------


def _utc(second: int = 0) -> datetime:
    return datetime(2024, 3, 15, 8, 41, second, tzinfo=timezone.utc)


def _meta() -> CaptureMetadata:
    return CaptureMetadata(
        camera_ip="192.168.1.100",
        camera_port=8000,
        camera_user="admin",
        protect_ip="10.54.4.1",
        capture_interface="br554",
        capture_host="10.54.4.1",
        capture_mode="remote",
        pcap_path="/tmp/capture.pcap",
        pcap_sha256="abc123",
        start_utc=_utc(0),
        end_utc=datetime(2024, 3, 15, 8, 42, 0, tzinfo=timezone.utc),
        duration_seconds=60,
        tool_version="0.1.0",
    )


def _motion(is_motion: bool = True) -> MotionEvent:
    return MotionEvent(
        utc=_utc(1),
        operation="Changed",
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


def _pull(http_status: int = 200, notifications: List[MotionEvent] = None) -> PullTransaction:
    return PullTransaction(
        tcp_stream=12,
        request_frame=100,
        response_frame=101,
        request_time=_utc(0),
        response_time=_utc(0),
        http_status=http_status,
        operation=SoapOperation.PULL_MESSAGES,
        notifications=notifications or [],
        soap_fault=None,
        source=EventSource.PROTECT,
        subscription_id=None,
        request_xml_path=None,
        response_xml_path=None,
        raw_request="<PullMessages/>",
        raw_response="<PullMessagesResponse/>",
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


def _timeline_entry() -> TimelineEntry:
    return TimelineEntry(
        utc=_utc(0),
        kind=TimelineEventKind.PULL_TRANSACTION,
        source=EventSource.PROTECT,
        description="protect PullMessages → HTTP 200 0 notification(s) [stream 12]",
    )


def _bundle(
    protect_txns=None,
    local_events=None,
    faults=None,
    correlations=None,
) -> EvidenceBundle:
    return EvidenceBundle(
        metadata=_meta(),
        timeline=[_timeline_entry()],
        protect_transactions=protect_txns or [_pull()],
        local_transactions=[],
        local_events=local_events or [_motion()],
        soap_faults=faults or [],
        correlations=correlations or [],
        observations=["The local subscriber received 1 IsMotion=true event."],
    )


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


class TestRenderMarkdown:
    def test_contains_camera_ip(self):
        md = _render_markdown(_bundle())
        assert "192.168.1.100" in md

    def test_contains_protect_ip(self):
        md = _render_markdown(_bundle())
        assert "10.54.4.1" in md

    def test_contains_summary_heading(self):
        md = _render_markdown(_bundle())
        assert "## Summary" in md

    def test_contains_timeline_heading(self):
        md = _render_markdown(_bundle())
        assert "## Timeline" in md

    def test_contains_observations(self):
        md = _render_markdown(_bundle())
        assert "IsMotion=true" in md

    def test_fault_table_present_when_faults(self):
        md = _render_markdown(_bundle(faults=[_fault()]))
        assert "## SOAP Faults" in md

    def test_fault_table_absent_when_no_faults(self):
        md = _render_markdown(_bundle(faults=[]))
        assert "## SOAP Faults" not in md

    def test_notification_table_present_when_notifications(self):
        md = _render_markdown(_bundle(protect_txns=[_pull(notifications=[_motion()])]))
        assert "## Protect Notifications" in md

    def test_protect_transaction_table_present(self):
        md = _render_markdown(_bundle())
        assert "## Protect PullMessages Transactions" in md

    def test_sha256_in_environment(self):
        md = _render_markdown(_bundle())
        assert "abc123" in md


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------


class TestRenderHtml:
    def test_is_valid_html(self):
        md = _render_markdown(_bundle())
        html = _render_html(md)
        assert html.startswith("<!DOCTYPE html>")
        assert "</html>" in html

    def test_contains_camera_ip(self):
        md = _render_markdown(_bundle())
        html = _render_html(md)
        assert "192.168.1.100" in html

    def test_contains_table_tags(self):
        md = _render_markdown(_bundle())
        html = _render_html(md)
        assert "<table>" in html

    def test_contains_heading_tags(self):
        md = _render_markdown(_bundle())
        html = _render_html(md)
        assert "<h1>" in html
        assert "<h2>" in html


# ---------------------------------------------------------------------------
# JSON serialisation
# ---------------------------------------------------------------------------


class TestBundleToJson:
    def test_valid_json(self):
        j = bundle_to_json(_bundle())
        parsed = json.loads(j)
        assert isinstance(parsed, dict)

    def test_contains_metadata(self):
        j = bundle_to_json(_bundle())
        parsed = json.loads(j)
        assert "metadata" in parsed
        assert parsed["metadata"]["camera_ip"] == "192.168.1.100"

    def test_datetime_serialised_as_string(self):
        j = bundle_to_json(_bundle())
        assert "2024-03-15" in j

    def test_enum_serialised_as_value(self):
        j = bundle_to_json(_bundle())
        assert '"protect"' in j or '"local"' in j


# ---------------------------------------------------------------------------
# Timeline CSV / JSON
# ---------------------------------------------------------------------------


class TestTimelineCsv:
    def test_has_header(self):
        csv = _timeline_to_csv([_timeline_entry()])
        assert csv.startswith("utc,source,kind,description")

    def test_has_data_row(self):
        csv = _timeline_to_csv([_timeline_entry()])
        lines = csv.strip().split("\n")
        assert len(lines) == 2

    def test_empty_timeline(self):
        csv = _timeline_to_csv([])
        lines = csv.strip().split("\n")
        assert len(lines) == 1  # header only


class TestTimelineJson:
    def test_valid_json(self):
        j = _timeline_to_json([_timeline_entry()])
        parsed = json.loads(j)
        assert isinstance(parsed, list)
        assert len(parsed) == 1

    def test_contains_utc(self):
        j = _timeline_to_json([_timeline_entry()])
        assert "2024-03-15" in j


# ---------------------------------------------------------------------------
# Raw XML saving
# ---------------------------------------------------------------------------


class TestSaveRawXml:
    def test_protect_request_saved(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            bundle = _bundle()
            save_raw_xml(bundle, out)
            req_files = list((out / "raw" / "protect" / "requests").glob("*.xml"))
            assert len(req_files) >= 1

    def test_protect_response_saved(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            bundle = _bundle()
            save_raw_xml(bundle, out)
            resp_files = list((out / "raw" / "protect" / "responses").glob("*.xml"))
            assert len(resp_files) >= 1

    def test_local_notification_saved(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            bundle = _bundle(local_events=[_motion()])
            save_raw_xml(bundle, out)
            notif_files = list((out / "raw" / "local" / "notifications").glob("*.xml"))
            assert len(notif_files) == 1

    def test_xml_path_updated_on_transaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            bundle = _bundle()
            save_raw_xml(bundle, out)
            assert bundle.protect_transactions[0].request_xml_path is not None
            assert bundle.protect_transactions[0].response_xml_path is not None


# ---------------------------------------------------------------------------
# ReportWriter integration
# ---------------------------------------------------------------------------


class TestReportWriter:
    def test_all_files_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            writer = ReportWriter(out)
            writer.write(_bundle())
            assert (out / "report.md").exists()
            assert (out / "report.html").exists()
            assert (out / "evidence.json").exists()
            assert (out / "timeline.csv").exists()
            assert (out / "timeline.json").exists()

    def test_report_md_not_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            ReportWriter(out).write(_bundle())
            assert (out / "report.md").stat().st_size > 0

    def test_report_html_not_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            ReportWriter(out).write(_bundle())
            assert (out / "report.html").stat().st_size > 0
