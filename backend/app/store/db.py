"""Small storage interfaces so production systems can be swapped in later.

EventSource -> Kafka/Kinesis; GraphStore -> Neo4j; AlertStore -> Postgres.
P0 implementations are SQLite + in-process replay queue.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from abc import ABC, abstractmethod
from typing import Any, Iterable

from backend.app.schema import Alert, Event, GroundTruthEvent


class EventSource(ABC):
    @abstractmethod
    def append(self, event: Event) -> None: ...

    @abstractmethod
    def iter_all(self) -> Iterable[Event]: ...


class GraphStore(ABC):
    """Persistence for the temporal entity graph (adjacency snapshots)."""
    @abstractmethod
    def save_snapshot(self, key: str, payload: dict[str, Any]) -> None: ...

    @abstractmethod
    def load_snapshot(self, key: str) -> dict[str, Any] | None: ...


class AlertStore(ABC):
    @abstractmethod
    def upsert(self, alert: Alert) -> None: ...

    @abstractmethod
    def get(self, alert_id: str) -> Alert | None: ...

    @abstractmethod
    def list(self) -> list[Alert]: ...


class SqliteEventSource(EventSource):
    def __init__(self, path: str, gt_path: str | None = None):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
        self.con = sqlite3.connect(path, check_same_thread=False)
        self.con.execute("CREATE TABLE IF NOT EXISTS events(event_id TEXT PRIMARY KEY, ts INTEGER, body TEXT)")
        # ground truth lives in a SEPARATE table in a SEPARATE db file by default;
        # the detector never opens it.
        gt = gt_path or path.replace("events", "groundtruth")
        self.gt_con = sqlite3.connect(gt, check_same_thread=False)
        self.gt_con.execute(
            "CREATE TABLE IF NOT EXISTS ground_truth(event_id TEXT PRIMARY KEY, body TEXT)")

    def append(self, event: Event) -> None:
        with self._lock:
            self.con.execute("INSERT OR REPLACE INTO events VALUES(?,?,?)",
                             (event.event_id, event.timestamp, json.dumps(event.as_dict())))
            self.con.commit()

    def append_gt(self, gt: GroundTruthEvent) -> None:
        with self._lock:
            self.gt_con.execute("INSERT OR REPLACE INTO ground_truth VALUES(?,?)",
                                (gt.event_id, gt.model_dump_json()))
            self.gt_con.commit()

    def iter_all(self) -> Iterable[Event]:
        rows = self.con.execute("SELECT body FROM events ORDER BY ts, event_id").fetchall()
        return [Event(**json.loads(r[0])) for r in rows]

    def iter_gt(self) -> dict[str, GroundTruthEvent]:
        rows = self.gt_con.execute("SELECT body FROM ground_truth").fetchall()
        return {json.loads(r[0])["event_id"]: GroundTruthEvent(**json.loads(r[0])) for r in rows}


class InMemoryEventSource(EventSource):
    def __init__(self):
        self.events: list[Event] = []

    def append(self, event: Event) -> None:
        self.events.append(event)

    def iter_all(self) -> Iterable[Event]:
        return sorted(self.events, key=lambda e: (e.timestamp, e.event_id))


class ReplayQueue(EventSource):
    """In-process replay of a saved JSONL stream (offline demo fallback)."""
    def __init__(self, path: str):
        self.path = path

    def append(self, event: Event) -> None:  # no-op: replay is read-only
        pass

    def iter_all(self) -> Iterable[Event]:
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                if obj.get("kind") == "event":
                    yield Event(**obj["data"])


class SqliteAlertStore(AlertStore):
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
        self.con = sqlite3.connect(path, check_same_thread=False)
        self.con.execute("CREATE TABLE IF NOT EXISTS alerts(alert_id TEXT PRIMARY KEY, priority REAL, body TEXT)")

    def upsert(self, alert: Alert) -> None:
        with self._lock:
            self.con.execute("INSERT OR REPLACE INTO alerts VALUES(?,?,?)",
                             (alert.alert_id, alert.scores.get("priority", 0.0), alert.model_dump_json()))
            self.con.commit()

    def get(self, alert_id: str) -> Alert | None:
        row = self.con.execute("SELECT body FROM alerts WHERE alert_id=?", (alert_id,)).fetchone()
        return Alert(**json.loads(row[0])) if row else None

    def list(self) -> list[Alert]:
        rows = self.con.execute("SELECT body FROM alerts ORDER BY priority DESC").fetchall()
        out = []
        for r in rows:
            a = Alert(**json.loads(r[0]))
            if a.merged_into is None:
                out.append(a)
        return sorted(out, key=lambda a: -a.scores.get("priority", 0))


class SqliteGraphStore(GraphStore):
    def __init__(self, path: str):
        self.con = sqlite3.connect(path, check_same_thread=False)
        self.con.execute("CREATE TABLE IF NOT EXISTS snapshots(key TEXT PRIMARY KEY, body TEXT)")

    def save_snapshot(self, key: str, payload: dict[str, Any]) -> None:
        self.con.execute("INSERT OR REPLACE INTO snapshots VALUES(?,?)", (key, json.dumps(payload)))
        self.con.commit()

    def load_snapshot(self, key: str) -> dict[str, Any] | None:
        row = self.con.execute("SELECT body FROM snapshots WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None
