"""Report generator for the ONVIF PullPoint Forensic Comparator.

Produces
--------
- ``report.md``     — Markdown suitable for GitHub issues or vendor tickets
- ``report.html``   — Self-contained HTML for human consumption
- ``evidence.json`` — Machine-readable JSON of the full evidence bundle
- ``timeline.csv``  — Chronological event stream as CSV
- ``timeline.json`` — Chronological event stream as JSON
- ``raw/``          — Directory tree of saved XML files

Both ``report.md`` and ``report.html`` are generated from the same internal
model (``EvidenceBundle``).  No logic is duplicated between them.

Design
------
- The ``ReportWriter`` class owns all file I/O.
- ``_render_markdown()`` produces the Markdown string.
- ``_render_html()`` wraps the Markdown in a minimal HTML shell.
- JSON serialisation uses a custom encoder that handles ``datetime``,
  ``Enum``, and ``dataclass`` objects.
- Raw XML files are saved by ``save_raw_xml()`` before the report is written.
"""

from __future__ import annotations

import csv
import dataclasses
import json
import logging
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import (
    CorrelationRecord,
    CorrelationResult,
    EvidenceBundle,
    MotionEvent,
    PullTransaction,
    SoapFault,
    TimelineEntry,
    TimelineEventKind,
)
from .onvif_client import LocalSoapRecord
from .util import format_utc, sha256_file

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# JSON serialisation
# ---------------------------------------------------------------------------


class _BundleEncoder(json.JSONEncoder):
    """Serialise dataclasses, datetimes, enums, and bytes to JSON."""

    def default(self, obj: Any) -> Any:
        if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
            return dataclasses.asdict(obj)
        if isinstance(obj, datetime):
            return format_utc(obj)
        if isinstance(obj, Enum):
            return obj.value
        if isinstance(obj, bytes):
            # Encode raw bytes as a hex string for JSON portability.
            # The original bytes are saved to disk separately.
            return obj.hex()
        return super().default(obj)


def bundle_to_json(bundle: EvidenceBundle, *, indent: int = 2) -> str:
    """Serialise *bundle* to a JSON string."""
    return json.dumps(dataclasses.asdict(bundle), cls=_BundleEncoder, indent=indent)


# ---------------------------------------------------------------------------
# Raw XML saving
# ---------------------------------------------------------------------------


def save_raw_xml(
    bundle: EvidenceBundle,
    output_dir: Path,
) -> None:
    """Save all raw XML from the bundle into the ``raw/`` directory tree.

    Directory layout::

        raw/
          protect/
            requests/   stream_NNN_req.xml
            responses/  stream_NNN_resp.xml
          local/
            requests/
            responses/
            notifications/  notif_NNN.xml

    Also updates ``request_xml_path`` and ``response_xml_path`` on each
    ``PullTransaction`` so the report can link to the files.
    """
    raw_dir = output_dir / "raw"

    def _save(path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    for txn in bundle.protect_transactions:
        slug = f"stream_{txn.tcp_stream:03d}"
        req_path = raw_dir / "protect" / "requests" / f"{slug}_req.xml"
        resp_path = raw_dir / "protect" / "responses" / f"{slug}_resp.xml"
        # Save exact captured bytes; fall back to string decode if bytes absent
        req_bytes = txn.raw_request_bytes or txn.raw_request.encode(errors="replace")
        resp_bytes = txn.raw_response_bytes or txn.raw_response.encode(errors="replace")
        req_path.parent.mkdir(parents=True, exist_ok=True)
        req_path.write_bytes(req_bytes)
        resp_path.parent.mkdir(parents=True, exist_ok=True)
        resp_path.write_bytes(resp_bytes)
        txn.request_xml_path = str(req_path.relative_to(output_dir))
        txn.response_xml_path = str(resp_path.relative_to(output_dir))

    for txn in bundle.local_transactions:
        slug = f"stream_{txn.tcp_stream:03d}"
        req_path = raw_dir / "local" / "requests" / f"{slug}_req.xml"
        resp_path = raw_dir / "local" / "responses" / f"{slug}_resp.xml"
        req_bytes = txn.raw_request_bytes or txn.raw_request.encode(errors="replace")
        resp_bytes = txn.raw_response_bytes or txn.raw_response.encode(errors="replace")
        req_path.parent.mkdir(parents=True, exist_ok=True)
        req_path.write_bytes(req_bytes)
        resp_path.parent.mkdir(parents=True, exist_ok=True)
        resp_path.write_bytes(resp_bytes)
        txn.request_xml_path = str(req_path.relative_to(output_dir))
        txn.response_xml_path = str(resp_path.relative_to(output_dir))

    for i, event in enumerate(bundle.local_events, start=1):
        notif_path = raw_dir / "local" / "notifications" / f"notif_{i:03d}.xml"
        _save(notif_path, event.raw_xml)

    # Write local subscriber SOAP history (CreatePullPointSubscription,
    # PullMessages, Renew, Unsubscribe — complete envelopes from Zeep plugin)
    for i, record in enumerate(bundle.local_soap_history, start=1):
        slug = f"{i:04d}_{record.operation}"
        req_path = raw_dir / "local" / "soap_history" / f"{slug}_req.xml"
        resp_path = raw_dir / "local" / "soap_history" / f"{slug}_resp.xml"
        req_path.parent.mkdir(parents=True, exist_ok=True)
        req_path.write_text(record.request_envelope, encoding="utf-8")
        resp_path.write_text(record.response_envelope, encoding="utf-8")


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------


def _render_markdown(bundle: EvidenceBundle) -> str:
    md: List[str] = []
    m = md.append

    meta = bundle.metadata

    m("# ONVIF PullPoint Forensic Report")
    m("")
    m(f"Generated by ONVIF PullPoint Forensic Comparator v{meta.tool_version}")
    m("")

    # --- Environment ---
    m("## Environment")
    m("")
    m("| Parameter | Value |")
    m("|---|---|")
    m(f"| Camera IP | `{meta.camera_ip}` |")
    m(f"| Camera port | `{meta.camera_port}` |")
    m(f"| Camera user | `{meta.camera_user}` |")
    m(f"| Protect IP | `{meta.protect_ip}` |")
    m(f"| Capture interface | `{meta.capture_interface}` |")
    m(f"| Capture host | `{meta.capture_host}` |")
    m(f"| Capture mode | `{meta.capture_mode}` |")
    m(f"| Capture start (UTC) | `{format_utc(meta.start_utc)}` |")
    m(f"| Capture end (UTC) | `{format_utc(meta.end_utc)}` |")
    m(f"| Requested duration | `{meta.duration_seconds} s` |")
    if meta.observed_start_utc:
        m(f"| First packet (UTC) | `{format_utc(meta.observed_start_utc)}` |")
    if meta.observed_end_utc:
        m(f"| Last packet (UTC) | `{format_utc(meta.observed_end_utc)}` |")
    if meta.observed_duration_seconds is not None:
        m(f"| Observed duration | `{meta.observed_duration_seconds} s` |")
    else:
        m(f"| Observed duration | `unknown (empty PCAP)` |")
    m(f"| PCAP | `{meta.pcap_path}` |")
    m(f"| SHA-256 | `{meta.pcap_sha256}` |")
    m("")

    # --- Capture quality ---
    quality = bundle.capture_quality
    m("## Capture Quality")
    m("")
    m("| Metric | Value |")
    m("|---|---|")
    m(f"| Traffic classification | `{quality.traffic_classification.value}` |")
    m(f"| Protect packets captured | {quality.protect_packets_seen} |")
    m(f"| Protect TCP connections | {quality.protect_tcp_connections} |")
    m(f"| Protect PullMessages requests | {quality.protect_pullmessages_requests} |")
    m(f"| Protect PullMessages responses | {quality.protect_pullmessages_responses} |")
    m(f"| Local subscriber packets captured | {quality.local_packets_seen} |")
    m(f"| Local PullMessages requests | {quality.local_pullmessages_requests} |")
    m("")
    if quality.warnings:
        m("**Quality warnings:**")
        m("")
        for w in quality.warnings:
            m(f"- ⚠ {w}")
        m("")

    # --- Summary ---
    protect_txns = bundle.protect_transactions
    local_events = bundle.local_events
    faults = bundle.soap_faults

    local_true = sum(1 for e in local_events if e.operation == "Changed" and e.is_motion is True)
    local_false = sum(1 for e in local_events if e.operation == "Changed" and e.is_motion is False)
    local_partial = sum(1 for e in local_events if e.parse_status == "partial")
    protect_notifs = [n for t in protect_txns for n in t.notifications]
    protect_true = sum(1 for e in protect_notifs if e.is_motion is True)
    protect_partial = sum(1 for e in protect_notifs if e.parse_status == "partial")
    empty_pulls = sum(1 for t in protect_txns if not t.notifications and t.soap_fault is None and t.http_status == 200)

    m("## Summary")
    m("")
    m("| Metric | Count |")
    m("|---|---|")
    m(f"| Local IsMotion=true (Changed) | {local_true} |")
    m(f"| Local IsMotion=false (Changed) | {local_false} |")
    if local_partial:
        m(f"| Local notifications (partial/unrecognised) | {local_partial} |")
    m(f"| Protect PullMessages requests | {len(protect_txns)} |")
    m(f"| Protect notifications received | {len(protect_notifs)} |")
    m(f"| Protect IsMotion=true | {protect_true} |")
    if protect_partial:
        m(f"| Protect notifications (partial/unrecognised) | {protect_partial} |")
    m(f"| Empty Protect PullMessages (200 OK, 0 notifications) | {empty_pulls} |")
    m(f"| SOAP faults | {len(faults)} |")
    m("")

    # --- Timeline ---
    m("## Timeline")
    m("")
    m("| UTC | Source | Kind | Description |")
    m("|---|---|---|---|")
    for entry in bundle.timeline:
        m(f"| `{format_utc(entry.utc)}` | {entry.source.value} | {entry.kind.value} | {entry.description} |")
    m("")

    # --- Protect transaction table ---
    m("## Protect PullMessages Transactions")
    m("")
    m("| UTC | HTTP | Notifications | Fault | Stream | Req frame | Resp frame | Request XML | Response XML |")
    m("|---|---|---|---|---|---|---|---|---|")
    for txn in protect_txns:
        fault_str = txn.soap_fault.code if txn.soap_fault else "—"
        req_link = f"[req]({txn.request_xml_path})" if txn.request_xml_path else "—"
        resp_link = f"[resp]({txn.response_xml_path})" if txn.response_xml_path else "—"
        m(
            f"| `{format_utc(txn.request_time)}` "
            f"| {txn.http_status} "
            f"| {len(txn.notifications)} "
            f"| {fault_str} "
            f"| {txn.tcp_stream} "
            f"| {txn.request_frame} "
            f"| {txn.response_frame} "
            f"| {req_link} "
            f"| {resp_link} |"
        )
    m("")

    # --- SOAP fault table ---
    if faults:
        m("## SOAP Faults")
        m("")
        m("| Code | Subcode | Reason | HTTP | Stream | Frame |")
        m("|---|---|---|---|---|---|")
        for fault in faults:
            m(
                f"| `{fault.code}` "
                f"| `{fault.subcode or '—'}` "
                f"| {fault.reason} "
                f"| {fault.http_status} "
                f"| {fault.tcp_stream} "
                f"| {fault.frame_number} |"
            )
        m("")

    # --- Notification table ---
    all_notifs = [n for t in protect_txns for n in t.notifications]
    fully_parsed = [n for n in all_notifs if n.parse_status == "ok"]
    partial_notifs = [n for n in all_notifs if n.parse_status == "partial"]

    if fully_parsed:
        m("## Protect Notifications")
        m("")
        m("| UTC | Operation | IsMotion | State | Topic |")
        m("|---|---|---|---|---|")
        for n in fully_parsed:
            m(
                f"| `{format_utc(n.utc)}` "
                f"| {n.operation} "
                f"| {n.is_motion} "
                f"| {n.state} "
                f"| {n.topic} |"
            )
        m("")

    if partial_notifs:
        m("## Protect Notifications (Partial / Unrecognised)")
        m("")
        m("These notifications were received but could not be fully parsed. "
          "They are preserved as evidence.")
        m("")
        m("| UTC | Topic | Warnings | Raw XML path |")
        m("|---|---|---|---|")
        for n in partial_notifs:
            warnings_str = "; ".join(n.parse_warnings) if n.parse_warnings else "—"
            m(
                f"| `{format_utc(n.utc)}` "
                f"| {n.topic or '—'} "
                f"| {warnings_str} "
                f"| — |"
            )
        m("")

    # --- Correlation table ---
    if bundle.correlations:
        m("## Correlation: Local Motion → Protect Poll")
        m("")
        m("| Local event UTC | IsMotion | Nearest before (ms) | Nearest after (ms) | Result |")
        m("|---|---|---|---|---|")
        for rec in bundle.correlations:
            before_ms = f"{rec.delta_before_ms:.0f}" if rec.delta_before_ms is not None else "—"
            after_ms = f"{rec.delta_after_ms:.0f}" if rec.delta_after_ms is not None else "—"
            m(
                f"| `{format_utc(rec.local_event.utc)}` "
                f"| {rec.local_event.is_motion} "
                f"| {before_ms} "
                f"| {after_ms} "
                f"| {rec.result.value} |"
            )
        m("")

    # --- Observations ---
    m("## Observations")
    m("")
    m("The following observations are factual.  No conclusions about fault "
      "attribution are drawn by this tool.")
    m("")
    for obs in bundle.observations:
        m(f"- {obs}")
    m("")

    return "\n".join(md)


# ---------------------------------------------------------------------------
# HTML renderer
# ---------------------------------------------------------------------------


_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ONVIF PullPoint Forensic Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         max-width: 1200px; margin: 2rem auto; padding: 0 1rem;
         color: #24292e; line-height: 1.6; }}
  h1, h2, h3 {{ border-bottom: 1px solid #eaecef; padding-bottom: .3em; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: 1rem; }}
  th, td {{ border: 1px solid #dfe2e5; padding: .4rem .8rem; text-align: left; }}
  th {{ background: #f6f8fa; }}
  tr:nth-child(even) {{ background: #f6f8fa; }}
  code {{ background: #f6f8fa; padding: .1em .3em; border-radius: 3px;
          font-family: "SFMono-Regular", Consolas, monospace; font-size: .9em; }}
  pre {{ background: #f6f8fa; padding: 1rem; overflow-x: auto; border-radius: 4px; }}
  .obs {{ background: #fffbdd; border-left: 4px solid #f9c513;
          padding: .5rem 1rem; margin: .5rem 0; }}
</style>
</head>
<body>
{body}
</body>
</html>
"""


def _md_to_html_body(markdown: str) -> str:
    """Convert Markdown to an HTML body fragment.

    Uses a minimal built-in converter so there is no dependency on an
    external Markdown library.  Handles headings, tables, lists, code
    spans, and paragraphs — sufficient for the report format.
    """
    lines = markdown.split("\n")
    html_lines: List[str] = []
    in_table = False
    in_list = False

    for line in lines:
        # Headings
        if line.startswith("#### "):
            _close(html_lines, in_table, in_list)
            in_table = in_list = False
            html_lines.append(f"<h4>{_inline(line[5:])}</h4>")
        elif line.startswith("### "):
            _close(html_lines, in_table, in_list)
            in_table = in_list = False
            html_lines.append(f"<h3>{_inline(line[4:])}</h3>")
        elif line.startswith("## "):
            _close(html_lines, in_table, in_list)
            in_table = in_list = False
            html_lines.append(f"<h2>{_inline(line[3:])}</h2>")
        elif line.startswith("# "):
            _close(html_lines, in_table, in_list)
            in_table = in_list = False
            html_lines.append(f"<h1>{_inline(line[2:])}</h1>")

        # Table rows
        elif line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if all(set(c.replace("-", "").replace(":", "").strip()) <= {""} for c in cells):
                # Separator row — skip
                continue
            if not in_table:
                html_lines.append("<table>")
                in_table = True
                tag = "th"
            else:
                tag = "td"
            row = "".join(f"<{tag}>{_inline(c)}</{tag}>" for c in cells)
            html_lines.append(f"<tr>{row}</tr>")

        # List items
        elif line.startswith("- "):
            if not in_list:
                if in_table:
                    html_lines.append("</table>")
                    in_table = False
                html_lines.append("<ul>")
                in_list = True
            html_lines.append(f"<li class='obs'>{_inline(line[2:])}</li>")

        # Blank line
        elif line.strip() == "":
            if in_table:
                html_lines.append("</table>")
                in_table = False
            if in_list:
                html_lines.append("</ul>")
                in_list = False

        # Paragraph
        else:
            if in_table:
                html_lines.append("</table>")
                in_table = False
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            if line.strip():
                html_lines.append(f"<p>{_inline(line)}</p>")

    if in_table:
        html_lines.append("</table>")
    if in_list:
        html_lines.append("</ul>")

    return "\n".join(html_lines)


def _close(lines: List[str], in_table: bool, in_list: bool) -> None:
    if in_table:
        lines.append("</table>")
    if in_list:
        lines.append("</ul>")


def _inline(text: str) -> str:
    """Apply inline Markdown formatting (code spans, bold, links)."""
    import re
    # Code spans: `...`
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    # Bold: **...**
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    # Links: [text](url)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', text)
    return text


def _render_html(markdown: str) -> str:
    body = _md_to_html_body(markdown)
    return _HTML_TEMPLATE.format(body=body)


# ---------------------------------------------------------------------------
# Timeline CSV / JSON
# ---------------------------------------------------------------------------


def _timeline_to_csv(timeline: List[TimelineEntry]) -> str:
    import io
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["utc", "source", "kind", "description"])
    for entry in timeline:
        writer.writerow([
            format_utc(entry.utc),
            entry.source.value,
            entry.kind.value,
            entry.description,
        ])
    return buf.getvalue()


def _timeline_to_json(timeline: List[TimelineEntry]) -> str:
    rows = [
        {
            "utc": format_utc(e.utc),
            "source": e.source.value,
            "kind": e.kind.value,
            "description": e.description,
        }
        for e in timeline
    ]
    return json.dumps(rows, indent=2)


# ---------------------------------------------------------------------------
# ReportWriter
# ---------------------------------------------------------------------------


class ReportWriter:
    """Writes the complete evidence bundle to *output_dir*.

    Call ``write(bundle)`` to produce all output files.
    """

    def __init__(self, output_dir: Path) -> None:
        self._dir = output_dir
        self._dir.mkdir(parents=True, exist_ok=True)

    def write(self, bundle: EvidenceBundle) -> None:
        """Write all report artefacts to the output directory."""
        save_raw_xml(bundle, self._dir)

        markdown = _render_markdown(bundle)
        html = _render_html(markdown)

        (self._dir / "report.md").write_text(markdown, encoding="utf-8")
        (self._dir / "report.html").write_text(html, encoding="utf-8")
        (self._dir / "evidence.json").write_text(bundle_to_json(bundle), encoding="utf-8")
        (self._dir / "timeline.csv").write_text(_timeline_to_csv(bundle.timeline), encoding="utf-8")
        (self._dir / "timeline.json").write_text(_timeline_to_json(bundle.timeline), encoding="utf-8")

        # SHA-256 of the PCAP
        pcap_path = Path(bundle.metadata.pcap_path)
        if pcap_path.exists():
            digest = sha256_file(pcap_path)
            (self._dir / "capture.sha256").write_text(
                f"{digest}  {pcap_path.name}\n", encoding="utf-8"
            )

        log.info("Report written to %s", self._dir)

    def print_summary(self, bundle: EvidenceBundle) -> None:
        """Print the terminal summary block."""
        meta = bundle.metadata
        protect_txns = bundle.protect_transactions
        local_events = bundle.local_events
        faults = bundle.soap_faults

        local_true = sum(1 for e in local_events if e.operation == "Changed" and e.is_motion is True)
        local_false = sum(1 for e in local_events if e.operation == "Changed" and e.is_motion is False)
        protect_notifs = [n for t in protect_txns for n in t.notifications]
        protect_true = sum(1 for e in protect_notifs if e.is_motion is True)
        empty_pulls = sum(1 for t in protect_txns if not t.notifications and t.soap_fault is None and t.http_status == 200)

        width = 54
        print()
        print("=" * width)
        print("SUMMARY")
        print("=" * width)
        print(f"Camera:                    {meta.camera_ip}:{meta.camera_port}")
        print(f"Protect IP:                {meta.protect_ip}")
        print(f"Capture duration:          {meta.duration_seconds} s")
        print(f"Capture quality:           {bundle.capture_quality.traffic_classification.value}")
        print()
        print(f"Local IsMotion=true:       {local_true}")
        print(f"Local IsMotion=false:      {local_false}")
        print(f"Protect PullMessages:      {len(protect_txns)}")
        print(f"Protect notifications:     {len(protect_notifs)}")
        print(f"Protect IsMotion=true:     {protect_true}")
        print(f"Empty PullMessages:        {empty_pulls}")
        print(f"SOAP faults:               {len(faults)}")
        print()
        print("OBSERVATIONS")
        print("-" * width)
        for obs in bundle.observations:
            print(f"  • {obs}")
        print()
        print(f"Report:  {self._dir / 'report.md'}")
        print(f"HTML:    {self._dir / 'report.html'}")
        print(f"JSON:    {self._dir / 'evidence.json'}")
        print("=" * width)
