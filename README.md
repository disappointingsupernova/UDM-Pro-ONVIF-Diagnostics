# ONVIF PullPoint Forensic Comparator

Determines conclusively whether an ONVIF camera delivers motion notifications
to UniFi Protect's PullPoint subscription.

Produces an evidence bundle suitable for submission to Ubiquiti or the camera
vendor.

---

## How it works

The tool runs two independent PullPoint subscribers simultaneously:

1. **UniFi Protect** — already subscribed to the camera. The tool captures
   its traffic passively via `tcpdump` on the UDM Pro's bridge interface.
2. **Local diagnostic subscriber** — a second, independent subscription
   created by this tool directly on the camera.

If the local subscriber receives motion events but Protect's PullMessages
responses are empty, that is strong evidence of a camera interoperability
problem rather than a motion detection failure.

```mermaid
flowchart LR
    CAM["ONVIF Camera"]
    PROTECT["UniFi Protect\nPullPoint subscriber"]
    LOCAL["Local diagnostic\nPullPoint subscriber"]
    PCAP["tcpdump on UDM Pro\n(or locally)"]
    TOOL["onvif-compare"]

    CAM -->|"NotificationMessage"| PROTECT
    CAM -->|"NotificationMessage"| LOCAL
    PROTECT -->|"PullMessages traffic"| PCAP
    PCAP --> TOOL
    LOCAL --> TOOL
    TOOL -->|"Evidence bundle"| REPORT["report.md / report.html\nevidence.json"]
```

---

## Architecture

```mermaid
flowchart TD
    subgraph Capture["Capture layer (capture.py)"]
        SSH["RemoteCapture\nSSH → UDM Pro\ntcpdump -i INTERFACE"]
        LOCAL["LocalCapture\nLocal tcpdump subprocess"]
    end

    subgraph Analysis["Analysis layer"]
        PCAP["pcap.py\nScapy TCP reconstruction\n→ HTTP pairing → SOAP"]
        ONVIF["onvif_client.py\nIndependent PullPoint\nsubscription + auto-renew"]
        SOAP["soap.py\nlxml SOAP parser\nPullMessages / Notify / Fault"]
    end

    subgraph Core["Core"]
        MODELS["models.py\nDataclasses — single source of truth\nMotionEvent · PullTransaction\nSoapFault · CorrelationRecord\nTimelineEntry · EvidenceBundle"]
        TIMELINE["timeline.py\nChronological event stream\nCorrelation engine\nneareast_before / after / absolute"]
    end

    subgraph Output["Output layer (report.py)"]
        MD["report.md"]
        HTML["report.html"]
        JSON["evidence.json"]
        CSV["timeline.csv / timeline.json"]
        BUNDLE["raw/\nprotect/requests|responses\nlocal/requests|responses|notifications"]
    end

    SSH --> PCAP
    LOCAL --> PCAP
    PCAP --> SOAP
    SOAP --> MODELS
    ONVIF --> MODELS
    MODELS --> TIMELINE
    TIMELINE --> MD
    TIMELINE --> HTML
    TIMELINE --> JSON
    TIMELINE --> CSV
    TIMELINE --> BUNDLE
```

### Data flow

```mermaid
flowchart LR
    PCAP_FILE["capture.pcap"]
    TCP["TCP stream\nreconstruction\n(Scapy)"]
    HTTP["HTTP request /\nresponse pairing"]
    SOAP_ENV["SOAP envelope\nextraction"]
    LXML["lxml parse"]
    OBJ["Python dataclasses\nPullTransaction\nMotionEvent\nSoapFault"]
    TL["Timeline\n(sorted by UTC)"]
    RPT["Evidence bundle\nreport.md + HTML\nevidence.json"]

    PCAP_FILE --> TCP --> HTTP --> SOAP_ENV --> LXML --> OBJ --> TL --> RPT
```

### Correlation engine

```mermaid
flowchart TD
    LOCAL_EVT["Local motion event\ne.g. 08:41:01.123 IsMotion=true\noperation=Changed"]
    SEARCH["Search timeline for\nProtect PullMessages\nwithin ±window (default 1000 ms)"]
    BEFORE["nearest_before\nclosest poll BEFORE event\n+ delta_before_ms"]
    AFTER["nearest_after\nclosest poll AFTER event\n+ delta_after_ms"]
    ABS["nearest_absolute\nwhichever is closer"]
    CLASSIFY["Classify\nnotification_present?\nempty_response?\nsoap_fault?\nhttp_error?\nno_poll_in_window?\ntimeout?"]
    REPORT["CorrelationRecord\nin report table"]

    LOCAL_EVT --> SEARCH
    SEARCH --> BEFORE
    SEARCH --> AFTER
    BEFORE --> ABS
    AFTER --> ABS
    ABS --> CLASSIFY
    CLASSIFY --> REPORT
```

---

## Modules

| Module | Responsibility |
|---|---|
| `models.py` | All dataclasses. No logic. Single source of truth for every data structure. |
| `capture.py` | `RemoteCapture` (SSH + tcpdump) and `LocalCapture` (subprocess). Interface auto-discovery. SFTP download. |
| `onvif_client.py` | Independent PullPoint subscription. Auto-renews on expiry. Thread-safe event collection. |
| `pcap.py` | Scapy TCP stream reconstruction → HTTP request/response pairing → SOAP extraction. No tshark. |
| `soap.py` | lxml SOAP parser. Handles PullMessagesResponse, CreatePullPointSubscription, Renew, Unsubscribe, Notify, Fault. |
| `timeline.py` | Chronological event stream. Correlation engine (nearest_before / nearest_after / nearest_absolute). |
| `report.py` | Markdown + HTML from the same `EvidenceBundle`. Raw XML saving. JSON / CSV timeline export. |
| `util.py` | SHA-256 hashing, UTC timestamps, local IP discovery, stream label formatting. |
| `main.py` | Argument parsing. Subcommands: `capture`, `analyse`, `report`. |

---

## Installation

```bash
git clone https://github.com/disappointingsupernova/UDM-Pro-ONVIF-Diagnostics
cd UDM-Pro-ONVIF-Diagnostics
pip install -r requirements.txt
```

**Runtime requirements**

| Package | Purpose |
|---|---|
| `scapy>=2.5` | TCP stream reconstruction from PCAP |
| `lxml>=4.9` | SOAP XML parsing |
| `onvif-zeep>=0.2.12` | ONVIF camera client (live capture mode) |
| `paramiko>=3.0` | SSH / SFTP to UDM Pro (remote capture mode) |
| `zeep>=4.2` | WSDL transport layer for onvif-zeep |
| `tcpdump` | Must be present on the UDM Pro (remote) or locally (local mode) |

Python 3.8+ required.

---

## Subcommands

### `capture` — live capture and analysis

Connects to the camera, starts an independent PullPoint subscription, SSHes
to the UDM Pro to run `tcpdump`, waits for the requested duration, downloads
the PCAP, analyses it, and writes the evidence bundle — all in one step.

```
onvif-compare capture \
  --camera-ip     192.168.1.100 \
  --protect-ip    10.54.4.1 \
  --ssh-host      10.54.4.1 \
  --duration      60
```

**All `capture` flags**

| Flag | Default | Description |
|---|---|---|
| `--camera-ip` | required | ONVIF camera IP address |
| `--camera-port` | `8000` | ONVIF service port |
| `--camera-user` | `admin` | ONVIF username |
| `--camera-password` | prompted | ONVIF password |
| `--protect-ip` | `10.54.4.1` | UniFi Protect IP address |
| `--capture` | `remote` | `remote` (SSH to UDM Pro) or `local` |
| `--ssh-host` | required for remote | SSH hostname / IP |
| `--ssh-port` | `22` | SSH port |
| `--ssh-user` | `root` | SSH username |
| `--ssh-key` | — | Path to SSH private key file |
| `--ssh-password` | — | Flag: prompt for SSH password |
| `--keep-remote` | — | Flag: do not delete PCAP from UDM Pro after download |
| `--interface` | auto-detected | `tcpdump` interface (e.g. `br554`). See note below. |
| `--duration` | `60` | Capture duration in seconds |
| `--correlation-window` | `1000` | Correlation search window in milliseconds |
| `--output-dir` | `evidence_YYYYMMDD_HHMMSS` | Where to write the evidence bundle |
| `--log-level` | `WARNING` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |

**Interface selection**

The `--interface` flag specifies which network interface `tcpdump` listens on.
On a UDM Pro, camera traffic typically flows through a VLAN bridge interface
such as `br554` (VLAN 554). The correct interface depends entirely on your
network configuration.

- If you know the interface, pass it explicitly: `--interface br554`
- If you omit it, the tool SSHes in, runs `ip -brief link`, and:
  - Auto-selects if exactly one `br*` interface is found
  - Lists all candidates and exits with an error if multiple bridges exist

```
# Explicit interface (recommended)
onvif-compare capture --camera-ip 192.168.1.100 --ssh-host 10.54.4.1 \
  --protect-ip 10.54.4.1 --interface br554 --duration 60

# Auto-detect (single bridge only)
onvif-compare capture --camera-ip 192.168.1.100 --ssh-host 10.54.4.1 \
  --protect-ip 10.54.4.1 --duration 60
```

**SSH authentication**

```bash
# Key-based (recommended — no password prompt)
onvif-compare capture --camera-ip 192.168.1.100 --ssh-host 10.54.4.1 \
  --protect-ip 10.54.4.1 --ssh-key ~/.ssh/udm_rsa --duration 60

# Password-based
onvif-compare capture --camera-ip 192.168.1.100 --ssh-host 10.54.4.1 \
  --protect-ip 10.54.4.1 --ssh-password --duration 60

# SSH agent (default if no key or password flag given)
onvif-compare capture --camera-ip 192.168.1.100 --ssh-host 10.54.4.1 \
  --protect-ip 10.54.4.1 --duration 60
```

**Local capture mode** (lab / same-segment setups)

```bash
onvif-compare capture --camera-ip 192.168.1.100 --protect-ip 10.54.4.1 \
  --capture local --interface eth0 --duration 60
```

---

### `analyse` — offline PCAP analysis

Analyses an existing PCAP file. No camera connection required. Useful for
re-analysing a capture with a different correlation window, or for analysing
a PCAP captured by other means (e.g. a port mirror or Wireshark).

```
onvif-compare analyse \
  --pcap        capture.pcap \
  --camera-ip   192.168.1.100 \
  --protect-ip  10.54.4.1
```

**All `analyse` flags**

| Flag | Default | Description |
|---|---|---|
| `--pcap` | required | Path to PCAP file |
| `--camera-ip` | required | ONVIF camera IP address |
| `--protect-ip` | required | UniFi Protect IP address |
| `--local-ip` | — | Local subscriber IP, if known (improves classification) |
| `--correlation-window` | `1000` | Correlation search window in milliseconds |
| `--output-dir` | next to PCAP | Where to write the evidence bundle |
| `--log-level` | `WARNING` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |

```bash
# Re-analyse with a wider correlation window
onvif-compare analyse --pcap capture.pcap \
  --camera-ip 192.168.1.100 --protect-ip 10.54.4.1 \
  --correlation-window 2000

# Specify local subscriber IP for better source classification
onvif-compare analyse --pcap capture.pcap \
  --camera-ip 192.168.1.100 --protect-ip 10.54.4.1 \
  --local-ip 192.168.1.50

# Write output to a specific directory
onvif-compare analyse --pcap capture.pcap \
  --camera-ip 192.168.1.100 --protect-ip 10.54.4.1 \
  --output-dir /tmp/evidence_reolink_2024
```

---

### `report` — regenerate report from evidence.json

Re-renders `report.md` and `report.html` from an existing `evidence.json`.
Useful after updating the report renderer without re-running a capture.

```
onvif-compare report --evidence evidence_20240315_084100/evidence.json
```

> **Note:** Full JSON deserialisation is not yet implemented. Use `analyse`
> to regenerate from the original PCAP if you need updated analysis results.

---

## Evidence bundle

Every run produces a self-contained directory:

```
evidence_YYYYMMDD_HHMMSS/
├── capture.pcap          # Raw packet capture
├── capture.sha256        # SHA-256 digest for chain of custody
├── evidence.json         # Machine-readable full evidence bundle
├── report.md             # Human-readable Markdown report
├── report.html           # Self-contained HTML report
├── timeline.csv          # Chronological event stream (spreadsheet-friendly)
├── timeline.json         # Chronological event stream (machine-readable)
└── raw/
    ├── protect/
    │   ├── requests/
    │   │   └── stream_012_req.xml    # Raw SOAP request from Protect
    │   └── responses/
    │       └── stream_012_resp.xml   # Raw SOAP response to Protect
    └── local/
        ├── notifications/
        │   └── notif_001.xml         # Raw NotificationMessage XML
        ├── requests/
        └── responses/
```

The `raw/` directory contains every SOAP envelope exactly as it appeared on
the wire. You can open any file in a text editor or load `capture.pcap`
directly into Wireshark and navigate to the frame numbers recorded in
`evidence.json`.

---

## Terminal output

At the end of every run the tool prints a summary:

```
======================================================
SUMMARY
======================================================
Camera:                    192.168.1.100:8000
Protect IP:                10.54.4.1
Capture duration:          60 s

Local IsMotion=true:       2
Local IsMotion=false:      2
Protect PullMessages:      12
Protect notifications:     0
Protect IsMotion=true:     0
Empty PullMessages:        12
SOAP faults:               0

OBSERVATIONS
------------------------------------------------------
  • The independent local subscriber received 2 IsMotion=true and
    2 IsMotion=false Changed events.
  • Protect issued 12 PullMessages request(s) during the capture period.
  • Of those, 12 returned HTTP 200 with zero NotificationMessage elements.
  • No SOAP faults were observed in the capture.
  • Protect received zero IsMotion=true notifications during the capture period.

Report:  /home/user/evidence_20240315_084100/report.md
HTML:    /home/user/evidence_20240315_084100/report.html
JSON:    /home/user/evidence_20240315_084100/evidence.json
======================================================
```

The tool records observations. It does not assign blame.

---

## Report sections

Both `report.md` and `report.html` contain:

| Section | Contents |
|---|---|
| Environment | Camera IP/port/user, Protect IP, interface, capture host/mode, start/end UTC, duration, PCAP path, SHA-256 |
| Summary | Counts of local events, Protect polls, notifications, empty responses, faults |
| Timeline | Every event in UTC order — polls, motion events, faults, subscriptions |
| Protect PullMessages Transactions | Per-transaction table with HTTP status, notification count, fault code, stream index, frame numbers, links to raw XML |
| SOAP Faults | Fault code, subcode, reason, HTTP status, stream, frame (only if faults present) |
| Protect Notifications | Topic, UTC, IsMotion, State (only if notifications present) |
| Correlation | Local motion event → nearest Protect poll before/after (ms) → result |
| Observations | Ordered factual statements, no blame attribution |

---

## Correlation results

Each local `Changed` motion event is correlated against the nearest Protect
PullMessages poll within the configured window:

| Result | Meaning |
|---|---|
| `notification_present` | The nearest poll's response contained at least one `NotificationMessage` |
| `empty_response` | HTTP 200 but zero `NotificationMessage` elements |
| `soap_fault` | The nearest poll returned a SOAP fault |
| `http_error` | Non-200, non-fault HTTP status |
| `no_poll_in_window` | No Protect poll found within the correlation window |
| `timeout` | The nearest poll had no response recorded |

---

## Provenance

Every object in the evidence bundle records where it came from:

| Field | Description |
|---|---|
| `source` | `"protect"` / `"local"` / `"camera"` / `"unknown"` |
| `tcp_stream` | Scapy TCP stream index — paste into Wireshark's stream filter |
| `request_frame` / `response_frame` | PCAP frame numbers for direct Wireshark lookup |
| `raw_xml` | The original XML string, never discarded |
| `request_xml_path` / `response_xml_path` | Relative path to the saved XML file in `raw/` |

Live subscriber events (from `onvif_client.py`) set `tcp_stream = -1` and
`frame_number = -1` because they are not captured from the PCAP.

---

## Design constraints

- **No tshark.** The parser never invokes tshark or parses its text output.
- **No regex XML.** XML is always parsed with lxml. Never located by regex.
- **No data loss.** Every parsed object retains its original raw XML.
- **Full provenance.** Every event records its source, TCP stream, and frame numbers.
- **Evidence-based conclusions.** The tool classifies observations; it does not assign blame.
- **Scapy only.** If Scapy is unavailable the tool fails with a clear error rather than falling back silently.
- **Capture abstraction.** `RemoteCapture` and `LocalCapture` both implement `CaptureBackend`. Adding a new capture backend requires no changes to the analysis engine.

---

## Tests

```bash
pip install pytest pytest-cov
pytest
```

```
148 tests · 0 failures
```

| Test file | Module under test | Tests |
|---|---|---|
| `test_soap.py` | `soap.py` | 35 |
| `test_pcap.py` | `pcap.py` | 27 |
| `test_capture.py` | `capture.py` | 9 |
| `test_onvif_client.py` | `onvif_client.py` | 26 |
| `test_timeline.py` | `timeline.py` | 21 |
| `test_report.py` | `report.py` | 30 |

Synthetic XML fixtures live in `tests/fixtures/`. Synthetic PCAP fixtures
are generated by `tests/fixtures/make_pcaps.py` and committed to
`tests/fixtures/pcap/`. Drop real captures into that directory and add
regression tests referencing them.

---

## Known limitations

- The `report` subcommand re-render path is a stub. Full JSON deserialisation
  back to `EvidenceBundle` is not yet implemented. Use `analyse` to
  regenerate from the original PCAP.
- `LocalCapture` interface auto-discovery uses `ip -brief link`, which is
  Linux-only. On Windows, pass `--interface` explicitly.
- The ONVIF subscriber does not yet proactively renew the lease before
  expiry. It recreates the subscription on any exception, which is
  functionally equivalent but produces a log warning on cameras (such as
  Reolink) that terminate subscriptions after ~60 s.
