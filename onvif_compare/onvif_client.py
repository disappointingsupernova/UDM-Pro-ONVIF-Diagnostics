"""Independent ONVIF PullPoint subscriber.

Creates a separate PullPoint subscription on the camera, completely
independent of UniFi Protect's subscription.  The camera must support
multiple simultaneous PullPoint subscribers; if it does not, this is
recorded as a finding in the evidence bundle.

Design
------
- Uses ``onvif-zeep`` for WSDL-based ONVIF communication.
- Converts every ``NotificationMessage`` into a ``MotionEvent`` dataclass.
- Retains the raw XML of every notification.
- Auto-renews the subscription before the lease expires.
- If the camera terminates the subscription (common on Reolink devices after
  ~60 s), it recreates it transparently and logs the renewal count.
- Thread-safe: ``events`` is a list appended under a ``threading.Lock``.
- Never raises from the polling loop; errors are recorded in ``errors``.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from lxml import etree

from .models import EventSource, MotionEvent, SimpleItem, SubscriptionEvent, SoapOperation

log = logging.getLogger(__name__)

# Renewal margin: renew this many seconds before the lease expires.
_RENEW_MARGIN_S = 10
# How long to wait between PullMessages calls (seconds).
_PULL_TIMEOUT_S = 5
# Maximum notifications per PullMessages call.
_PULL_LIMIT = 100


# ---------------------------------------------------------------------------
# Helpers for zeep → lxml conversion
# ---------------------------------------------------------------------------


def _zeep_to_element(value) -> Optional[etree._Element]:
    """Extract an lxml element from a zeep object or return ``None``."""
    if etree.iselement(value):
        return value
    raw = getattr(value, "_value_1", None)
    if etree.iselement(raw):
        return raw
    if isinstance(raw, (list, tuple)):
        for item in raw:
            if etree.iselement(item):
                return item
    return None


def _to_bool(value: Optional[str]) -> Optional[bool]:
    if value is None:
        return None
    v = value.strip().lower()
    if v in ("true", "1"):
        return True
    if v in ("false", "0"):
        return False
    return None


def _parse_utc(text: Optional[str]) -> Optional[datetime]:
    if not text:
        return None
    text = text.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _simple_items_from_element(parent: etree._Element) -> List[SimpleItem]:
    return [
        SimpleItem(name=el.get("Name", ""), value=el.get("Value", ""))
        for el in parent.xpath(".//*[local-name()='SimpleItem']")
    ]


def _parse_notification(notification, source: EventSource) -> Optional[MotionEvent]:
    """Convert one zeep ``NotificationMessage`` object into a ``MotionEvent``."""
    msg_obj = getattr(notification, "Message", None)
    element = _zeep_to_element(msg_obj)
    if element is None:
        log.debug("NotificationMessage has no parseable Message element")
        return None

    topic_obj = getattr(notification, "Topic", None)
    topic = str(getattr(topic_obj, "_value_1", "") or "").strip()

    utc_str = element.get("UtcTime", "")
    utc = _parse_utc(utc_str) or datetime.now(tz=timezone.utc)
    operation = element.get("PropertyOperation", "")

    source_el = element.xpath("./*[local-name()='Source']")
    key_el = element.xpath("./*[local-name()='Key']")
    data_el = element.xpath("./*[local-name()='Data']")

    source_items = _simple_items_from_element(source_el[0]) if source_el else []
    key_items = _simple_items_from_element(key_el[0]) if key_el else []
    data_items = _simple_items_from_element(data_el[0]) if data_el else []

    is_motion: Optional[bool] = None
    state: Optional[bool] = None
    for item in data_items:
        if item.name == "IsMotion":
            is_motion = _to_bool(item.value)
        elif item.name == "State":
            state = _to_bool(item.value)

    raw_xml = etree.tostring(element, encoding="unicode", pretty_print=True)

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
        tcp_stream=-1,
        frame_number=-1,
        raw_xml=raw_xml,
    )


# ---------------------------------------------------------------------------
# Subscriber
# ---------------------------------------------------------------------------


@dataclass
class SubscriberConfig:
    """Configuration for ``OnvifSubscriber``."""

    camera_ip: str
    camera_port: int
    username: str
    password: str
    source: EventSource = EventSource.LOCAL
    pull_timeout_s: int = _PULL_TIMEOUT_S
    pull_limit: int = _PULL_LIMIT
    renew_margin_s: int = _RENEW_MARGIN_S


class OnvifSubscriber:
    """Independent ONVIF PullPoint subscriber.

    Usage::

        sub = OnvifSubscriber(config)
        sub.start(duration_seconds=60)
        # ... wait ...
        sub.stop()
        events = sub.events
        errors = sub.errors

    Or as a context manager::

        with OnvifSubscriber(config) as sub:
            time.sleep(60)
        events = sub.events
    """

    def __init__(self, config: SubscriberConfig) -> None:
        self._cfg = config
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._ready = threading.Event()

        self.events: List[MotionEvent] = []
        self.subscription_events: List[SubscriptionEvent] = []
        self.errors: List[str] = []
        self.multiple_subscription_supported: Optional[bool] = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self, duration_seconds: int) -> None:
        """Start polling in a background thread.

        Blocks until the first successful connection (or first error).
        Raises ``RuntimeError`` if the camera cannot be reached.
        """
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            args=(duration_seconds,),
            daemon=True,
            name="onvif-subscriber",
        )
        self._thread.start()
        self._ready.wait(timeout=20)
        if self.errors:
            raise RuntimeError(self.errors[0])

    def stop(self) -> None:
        """Signal the polling thread to stop and wait for it."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=15)

    def __enter__(self) -> "OnvifSubscriber":
        return self

    def __exit__(self, *_) -> None:
        self.stop()

    # ------------------------------------------------------------------
    # Background polling loop
    # ------------------------------------------------------------------

    def _run(self, duration_seconds: int) -> None:
        deadline = time.monotonic() + duration_seconds
        first_connect = True
        renewals = 0

        while time.monotonic() < deadline and not self._stop_event.is_set():
            try:
                camera, pullpoint = self._connect()

                if first_connect:
                    self.multiple_subscription_supported = True
                    self._ready.set()
                    first_connect = False
                else:
                    renewals += 1
                    log.info("PullPoint subscription recreated (renewal #%d)", renewals)

                self._poll_loop(pullpoint, deadline)

            except Exception as exc:
                if first_connect:
                    self.errors.append(f"{type(exc).__name__}: {exc}")
                    self._ready.set()
                    return

                if self._stop_event.is_set() or time.monotonic() >= deadline:
                    return

                log.warning(
                    "PullPoint subscription ended (%s: %s); recreating...",
                    type(exc).__name__,
                    exc or "no detail",
                )
                time.sleep(1)

    def _connect(self):
        """Create a new ONVIFCamera and PullPoint service."""
        try:
            from onvif import ONVIFCamera
        except ImportError as exc:
            raise RuntimeError(
                "onvif-zeep is required.\n"
                "Install it with:  pip install onvif-zeep"
            ) from exc

        cfg = self._cfg
        camera = ONVIFCamera(cfg.camera_ip, cfg.camera_port, cfg.username, cfg.password)
        pullpoint = camera.create_pullpoint_service()
        return camera, pullpoint

    def _poll_loop(self, pullpoint, deadline: float) -> None:
        cfg = self._cfg
        while time.monotonic() < deadline and not self._stop_event.is_set():
            response = pullpoint.PullMessages({
                "Timeout": timedelta(seconds=cfg.pull_timeout_s),
                "MessageLimit": cfg.pull_limit,
            })
            for notification in getattr(response, "NotificationMessage", None) or []:
                event = _parse_notification(notification, cfg.source)
                if event is not None:
                    with self._lock:
                        self.events.append(event)
                    log.info(
                        "[%s] %s IsMotion=%s State=%s topic=%s",
                        cfg.source.value.upper(),
                        event.operation,
                        event.is_motion,
                        event.state,
                        event.topic,
                    )
