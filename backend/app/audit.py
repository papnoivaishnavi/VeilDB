"""Audit trail of API access decisions.

Events hold only the time, role, outcome, scanned table names, and row count.
Raw SQL, error details, and result values are never recorded, because any of
them can contain personal data.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
from collections import deque
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any


ALLOWED = "ALLOWED"
BLOCKED = "BLOCKED"
ERROR = "ERROR"
UNAUTHORIZED = "UNAUTHORIZED"

MAX_AUDIT_EVENTS = 1000

logger = logging.getLogger("veildb.audit")
logger.setLevel(logging.INFO)
logger.propagate = False
if not logger.handlers:
    # Hosting platforms keep stdout, so events outlive the in-memory buffer.
    logger.addHandler(logging.StreamHandler(sys.stdout))


class AuditLog:
    """Thread-safe buffer of the most recent audit events."""

    def __init__(self, max_events: int = MAX_AUDIT_EVENTS):
        self._events: deque[dict[str, Any]] = deque(maxlen=max_events)
        self._lock = threading.Lock()

    def record(
        self,
        role: str | None,
        outcome: str,
        tables: Iterable[str] = (),
        row_count: int | None = None,
    ) -> None:
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "role": role,
            "outcome": outcome,
            "tables": sorted(tables),
            "row_count": row_count,
        }
        with self._lock:
            self._events.append(event)
        logger.info(json.dumps(event))

    def recent(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return up to ``limit`` events, newest first."""
        with self._lock:
            events = list(self._events)
        return events[:-limit - 1:-1]
