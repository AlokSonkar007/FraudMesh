"""Incremental detection pipeline: layers 1-3 + alert lifecycle.

Consumes events in timestamp order. Every `recompute_every` events (and after each
event that changes a component), re-scores current graph components and updates the
alert set. Supports layer ablation flags for the evaluation harness.
"""
from __future__ import annotations

import logging
from typing import Any, Callable

from backend.app.detector.anomaly import AnomalyScorer
from backend.app.detector.campaigns import CampaignManager, component_key, template_summary
from backend.app.detector.graph import ENTITY_FIELDS, EntityGraph
from backend.app.detector.rules import RuleEngine
from backend.app.detector.scoring import CampaignScorer, assign_stage
from backend.app.schema import Alert, Event, ScoredEvent

log = logging.getLogger("fraudmesh.pipeline")


class DetectionPipeline:
    def __init__(self, cfg: dict[str, Any], anomaly_model: AnomalyScorer | None = None,
                 layers: dict[str, bool] | None = None):
        self.cfg = cfg
        self.layers = layers or {"rules": True, "anomaly": True, "graph": True}
        self.rules = RuleEngine(cfg) if self.layers.get("rules", True) else None
        self.anomaly = anomaly_model if self.layers.get("anomaly", True) else None
        self.graph = EntityGraph(cfg) if self.layers.get("graph", True) else None
        self.scorer = CampaignScorer(cfg)
        self.manager = CampaignManager(cfg)
        self.events_by_id: dict[str, Event] = {}
        self.scored_by_id: dict[str, ScoredEvent] = {}
        self.now_ts = 0
        self.window_hours = cfg["window"]["sliding_hours"]
        self.listeners: list[Callable[[str, Alert], None]] = []
        self.event_listeners: list[Callable[[Event, ScoredEvent], None]] = []

    def on_alert(self, cb: Callable[[str, Alert], None]) -> None:
        self.listeners.append(cb)

    def on_event(self, cb: Callable[[Event, ScoredEvent], None]) -> None:
        self.event_listeners.append(cb)

    def process(self, event: Event) -> list[tuple[str, Alert]]:
        """Ingest one event; returns alert deltas [(created|updated|merged, alert)]."""
        self.now_ts = max(self.now_ts, event.timestamp)
        self.events_by_id[event.event_id] = event
        hits = self.rules.evaluate(event) if self.rules else []
        a_score = self.anomaly.score(event) if self.anomaly else 0.0
        stage = assign_stage(event, self.cfg)
        se = ScoredEvent(event_id=event.event_id, rule_hits=hits, anomaly=a_score, stage=stage)
        self.scored_by_id[event.event_id] = se
        for cb in self.event_listeners:
            cb(event, se)

        if not self.graph:
            return []
        # affected components BEFORE insertion (incremental recompute scope)
        touched = set()
        for etype, val in self._event_entity_keys(event):
            for other in list(self.graph.entity_index.get((etype, val), [])):
                cid = self.graph.comp_id_of(other)
                if cid is not None:
                    touched.add(cid)
        self.graph.add_event(event)
        if self.now_ts - getattr(self, "_last_prune", 0) > self.cfg["window"]["prune_minutes"] * 60:
            self.graph.prune(self.now_ts, self.window_hours)
            self._last_prune = self.now_ts
        return self.recompute(touched)

    @staticmethod
    def _event_entity_keys(e: Event) -> list[tuple[str, str]]:
        out = []
        for etype, field in ENTITY_FIELDS.items():
            v = getattr(e, field)
            if v:
                out.append((etype, v))
        return out

    def recompute(self, touched: set[int] | None = None) -> list[tuple[str, Alert]]:
        """Re-score only components touched by the latest event (incremental)."""
        comps = self.graph.components(ids=touched)
        results: dict[str, dict] = {}
        filtered_comps: list[list[str]] = []
        for ev_ids in comps:
            scored = [i for i in ev_ids if i in self.scored_by_id]
            if len(scored) < 2:
                continue
            # w_min gate: keep events with >=1 surviving weighted link
            kept = [i for i in ev_ids
                    if any(self.graph.pair_strength(i, j)[0] >= self.graph.w_min
                           for j in ev_ids if j != i)]
            if len(kept) < 2:
                continue
            key = component_key(kept)
            results[key] = self.scorer.score([self.scored_by_id[i] for i in kept],
                                             self.events_by_id)
            filtered_comps.append(sorted(kept))
        self.graph.assign_component_ids()
        deltas = self.manager.update(filtered_comps, self.events_by_id, self.scored_by_id,
                                     results, self.graph.graph_dump if self.graph else None)
        out = [(kind, alert) for kind, alert, _key in deltas]
        for kind, alert in out:
            for cb in self.listeners:
                try:
                    cb(kind, alert)
                except Exception as exc:  # listeners must never break ingestion
                    log.warning("listener error: %s", exc)
        return out

    # ---- feedback loop surface ----
    def confirm_alert(self, alert_id: str) -> dict[str, Any]:
        a = self.manager.alerts.get(alert_id)
        if not a:
            return {"ok": False}
        a.state = "confirmed"
        a.feedback = "confirm"
        added = []
        for etype, vals in a.explanation.entities.items():
            if etype == "actor":
                for v in vals:
                    self.rules.block_actor(v)
                    added.append(f"actor:{v}")
        log.info("analyst confirmed %s; blocklist +%d entities", alert_id, len(added))
        return {"ok": True, "blocklisted": added}

    def dismiss_alert(self, alert_id: str) -> dict[str, Any]:
        a = self.manager.alerts.get(alert_id)
        if not a:
            return {"ok": False}
        a.state = "dismissed"
        a.feedback = "dismiss"
        allowed = []
        for etype in ("payee_vpa", "url_domain"):
            for v in a.explanation.entities.get(etype, []):
                self.rules.allow_entity(v, self.now_ts)
                allowed.append(f"{etype}:{v}")
        log.info("analyst dismissed %s; allowlist(TTL=%dh) +%d", alert_id,
                 self.rules.ttl_hours, len(allowed))
        return {"ok": True, "allowlisted": allowed}

    def escalate_alert(self, alert_id: str) -> dict[str, Any]:
        a = self.manager.alerts.get(alert_id)
        if not a:
            return {"ok": False}
        a.state = "escalated"
        a.feedback = "escalate"
        return {"ok": True}

    def active_alerts(self) -> list[Alert]:
        return sorted([a for a in self.manager.alerts.values() if a.merged_into is None],
                      key=lambda a: -a.scores.get("priority", 0))
