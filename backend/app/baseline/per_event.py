"""Per-event baseline: rules + logistic regression on event features.

One alert per flagged event ("baseline"), and a variant that dedupes alerts per actor
entity ("baseline + per-entity dedupe") so alert-volume comparison is fair.
Trained on labeled TUNE events only; never TEST seeds.
"""
from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.linear_model import LogisticRegression

from backend.app.detector.anomaly import event_features
from backend.app.detector.rules import RuleEngine
from backend.app.schema import Event


class EventBaseline:
    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self.rules = RuleEngine(cfg)
        self.model: LogisticRegression | None = None
        self.threshold = cfg["baseline"]["event_flag_threshold"]

    def fit(self, events: list[Event], labels: list[int]) -> None:
        X = np.array([event_features(e) for e in events], dtype=float)
        y = np.array(labels)
        if len(set(y)) < 2:
            raise ValueError("baseline needs both classes in TUNE data")
        self.model = LogisticRegression(max_iter=1000)
        self.model.fit(X, y)

    def flag_event(self, e: Event) -> tuple[bool, float]:
        hits = self.rules.evaluate(e)
        rule_score = min(1.0, sum(h.weight for h in hits) / 2.0)
        x = np.array([event_features(e)], dtype=float)
        prob = float(self.model.predict_proba(x)[0][1]) if self.model else 0.0
        combined = max(prob, 0.5 * rule_score + 0.5 * prob)
        return combined >= self.threshold, combined


def run_baseline(events: list[Event], flagged_fn) -> dict[str, Any]:
    """Return flagged event ids; 'alerts' = one per flagged event."""
    flags = {}
    for e in events:
        is_flag, score = flagged_fn(e)
        if is_flag:
            flags[e.event_id] = score
    return {"per_event": flags}


def dedupe_by_entity(flags: dict[str, float], events_by_id: dict[str, Event]) -> dict[str, float]:
    """baseline+dedupe: collapse per-event flags to one alert per principal entity
    (actor or target), keeping the max score."""
    by_ent: dict[str, float] = {}
    for eid, score in flags.items():
        e = events_by_id[eid]
        ent = e.actor_id or e.target_id or eid
        by_ent[ent] = max(by_ent.get(ent, 0.0), score)
    return by_ent
