"""Port-scan detection using a short sliding time window."""

from collections import defaultdict, deque
from datetime import datetime, timedelta
from threading import Lock
from typing import Any

from database import insert_alert

SCAN_THRESHOLD = 8
SCAN_WINDOW_SECONDS = 10


class PortScanDetector:
    def __init__(self, threshold: int = SCAN_THRESHOLD, window_seconds: int = SCAN_WINDOW_SECONDS):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self._events: dict[tuple[str, str], deque[tuple[datetime, int]]] = defaultdict(deque)
        self._alerted: set[tuple[str, str]] = set()
        self._lock = Lock()

    def inspect(self, packet: dict[str, Any]) -> dict[str, Any] | None:
        destination_port = packet.get("destination_port")
        if packet.get("protocol") != "TCP" or destination_port is None:
            return None

        source_ip = packet["source_ip"]
        destination_ip = packet["destination_ip"]
        key = (source_ip, destination_ip)
        timestamp = datetime.fromisoformat(packet["timestamp"])

        with self._lock:
            events = self._events[key]
            events.append((timestamp, destination_port))
            cutoff = timestamp - self.window
            while events and events[0][0] < cutoff:
                events.popleft()

            ports = {port for _, port in events}
            if len(ports) < self.threshold or key in self._alerted:
                return None

            self._alerted.add(key)

        alert = {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "alert_type": "Port Scan Detected",
            "severity": "HIGH",
            "description": (
                f"{source_ip} contacted {len(ports)} different TCP ports on "
                f"{destination_ip} within {int(self.window.total_seconds())} seconds."
            ),
            "timestamp": packet["timestamp"],
        }
        insert_alert(alert)
        return alert
