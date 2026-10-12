"""Layer 2 — per-event anomaly score in [0,1].

IsolationForest fit on BENIGN events of TUNE seeds only (config: anomaly.train_on =
tune_benign). Never trained on TEST seeds. Score = normalized negated IF decision
function, calibrated to [0,1] via percentile clipping on the training set.
"""
from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest

from backend.app.schema import Event

FEATURE_ORDER = ["urgency", "has_link", "reply_requested", "amount_log", "is_upi",
                 "is_call", "is_app", "cat_pressure", "cat_instruction", "cat_contact"]


def event_features(e: Event) -> list[float]:
    tf = e.text_features
    cat = e.text_category
    return [
        float(tf.get("urgency", 0)),
        float(tf.get("has_link", 0)),
        float(tf.get("reply_requested", 0)),
        float(np.log1p(max(e.amount, 0.0))),
        1.0 if e.channel == "upi" else 0.0,
        1.0 if e.channel == "call" else 0.0,
        1.0 if e.channel == "app" else 0.0,
        1.0 if cat in ("urgency_threat", "penalty_threat", "account_lock_warning") else 0.0,
        1.0 if cat in ("payment_instruction", "otp_request", "remote_access_prompt", "link_click") else 0.0,
        1.0 if cat in ("authority_notice", "refund_offer", "kyc_update", "benign_alert",
                       "general_advisory") else 0.0,
    ]


class AnomalyScorer:
    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg["anomaly"]
        self.model: IsolationForest | None = None
        self.lo = -0.2
        self.hi = 0.5

    def fit(self, benign_events: list[Event]) -> None:
        """Train on BENIGN events only. Call with TUNE-seed benign events."""
        X = np.array([event_features(e) for e in benign_events], dtype=float)
        if len(X) < 20:
            raise ValueError("need >=20 benign events to fit anomaly model")
        self.model = IsolationForest(
            n_estimators=self.cfg["n_estimators"], contamination=self.cfg["contamination"],
            random_state=0)
        raw = -self.model.fit(X).score_samples(X)   # higher = more anomalous
        self.lo, self.hi = float(np.percentile(raw, 1)), float(np.percentile(raw, 99))
        if self.hi <= self.lo:
            self.hi = self.lo + 1e-6

    def score(self, e: Event) -> float:
        if self.model is None:
            return 0.0
        x = np.array([event_features(e)], dtype=float)
        raw = -self.model.score_samples(x)[0]
        s = (raw - self.lo) / (self.hi - self.lo)
        return float(min(1.0, max(0.0, s)))
