from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class LogEvent:
    timestamp: datetime
    event_type: str
    username: str
    ip_address: str
    status: str
    user_agent: str
