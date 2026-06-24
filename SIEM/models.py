from dataclasses import dataclass
from typing import Optional

@dataclass
class LogEntry:
    event_id: str
    timestamp: str
    source_ip: str
    severity: str
    event_type: str
    description: str
    status: str = 'new'

@dataclass
class Alert:
    alert_id: str
    event_id: str
    severity: str
    threat_type: str
    description: str
    timestamp: str
    status: str = 'active'


# === ADDED ONLY (no existing code altered) ===
class LogEvent:
    def __init__(self, event_id, timestamp, source_ip, severity, event_type, description):
        self.event_id = event_id
        self.timestamp = timestamp
        self.source_ip = source_ip
        self.severity = severity
        self.event_type = event_type
        self.description = description


class AlertEvent:
    def __init__(self, event_id, timestamp, severity, message):
        self.event_id = event_id
        self.timestamp = timestamp
        self.severity = severity
        self.message = message
