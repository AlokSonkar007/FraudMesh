"""Layer 3b — stage assignment, chain scoring and campaign risk dimensions.

likelihood = a1*stage_order_score + a2*mean(top-3 event anomaly) + a3*rule_hit_ratio
confidence = b1*min(1, independent_signals/N_sig) + b2*min(1, distinct_channels/3)
             + b3*min(1, distinct_targets/K)
novelty    = 1 - max Jaccard(campaign signature, known typology signatures)
impact     = min(1, log1p(distinct_targets * median_amount) / log1p(impact_cap))
priority   = weighted sum of the four.
"""
from __future__ import annotations

import math
from typing import Any

from backend.app.schema import Event, RuleHit, ScoredEvent

STAGE_ORDER = ["contact", "pressure", "instruction", "payment"]


def assign_stage(e: Event, cfg: dict[str, Any]) -> str | None:
    st = cfg["stages"]
    if e.channel == "upi" and e.amount > 0:
        return "payment"
    cat = e.text_category
    if cat in st["pressure"]:
        return "pressure"
    if cat in st["instruction"]:
        return "instruction"
    if cat in st["contact"]:
        return "contact"
    return None


def stage_order_score(scored: list[ScoredEvent], events_by_id: dict[str, Event]) -> float:
    """Length of the longest temporally ordered chain over the stage sequence / 4.

    DP over events sorted by time: best[s] = longest chain ending at stage s.
    A later event may extend any chain whose last stage precedes its own stage.
    """
    timed = sorted(scored, key=lambda s: (events_by_id[s.event_id].timestamp, s.event_id))
    best = {s: 0 for s in STAGE_ORDER}
    for se in timed:
        st = se.stage
        if not st:
            continue
        idx = STAGE_ORDER.index(st)
        prev = max([best[STAGE_ORDER[i]] for i in range(idx)] or [0])
        cand = prev + 1
        # same-stage events don't extend each other; strict progression only
        if cand > best[st]:
            best[st] = cand
    return max(best.values()) / len(STAGE_ORDER)


def rule_hit_ratio(scored: list[ScoredEvent]) -> float:
    if not scored:
        return 0.0
    return sum(1 for s in scored if s.rule_hits) / len(scored)


def top_anomaly_mean(scored: list[ScoredEvent], k: int = 3) -> float:
    vals = sorted((s.anomaly for s in scored), reverse=True)[:k]
    return sum(vals) / len(vals) if vals else 0.0


def independent_signals(scored: list[ScoredEvent], events_by_id: dict[str, Event]) -> list[dict[str, Any]]:
    """Distinct (entity_type, signal_type) evidence items across the component."""
    sigs: dict[tuple[str, str], dict[str, Any]] = {}
    for s in scored:
        e = events_by_id[s.event_id]
        for h in s.rule_hits:
            etype = {"bad_domain": "url_domain", "unknown_domain": "url_domain",
                     "lure_pattern": "url_domain", "bad_payee": "payee_vpa",
                     "new_payee": "payee_vpa", "large_to_new_payee": "payee_vpa",
                     "blocked_actor": "actor", "high_urgency_threat": "target",
                     "remote_access": "device"}.get(h.rule, "actor")
            val = getattr(e, {"url_domain": "url_domain", "payee_vpa": "payee_vpa",
                              "actor": "actor_id", "target": "target_id",
                              "device": "device_id"}.get(etype, "actor_id"), None) or e.actor_id or "-"
            sigs[(etype, h.rule)] = {"entity_type": etype, "signal_type": h.rule,
                                     "entity": val, "weight": h.weight}
        if s.anomaly >= 0.6:
            sigs[("event", f"anomaly_{s.stage or 'x'}")] = {
                "entity_type": "event", "signal_type": f"anomalous_{s.stage or 'unassigned'}",
                "entity": s.event_id, "weight": s.anomaly}
    return sorted(sigs.values(), key=lambda d: (d["entity_type"], d["signal_type"]))


def novelty(signature: dict[str, set[str]], library: list[dict[str, Any]]) -> tuple[float, str | None]:
    camp = set(signature.get("stage_set", [])) | set(signature.get("channel_set", [])) \
        | set(signature.get("category_set", []))
    best_j, best_name = 0.0, None
    for ref in library:
        rs = set(ref["stages"]) | set(ref["channels"]) | set(ref["categories"])
        inter, union = len(camp & rs), len(camp | rs)
        j = inter / union if union else 0.0
        if j > best_j:
            best_j, best_name = j, ref["name"]
    return 1.0 - best_j, best_name


class CampaignScorer:
    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self.sc = cfg["scoring"]

    def score(self, scored: list[ScoredEvent], events_by_id: dict[str, Event]) -> dict[str, Any]:
        scfg = self.sc
        sos = stage_order_score(scored, events_by_id)
        tam = top_anomaly_mean(scored)
        rhr = rule_hit_ratio(scored)
        a = scfg["likelihood_weights"]
        likelihood = a["a1"] * sos + a["a2"] * tam + a["a3"] * rhr

        sigs = independent_signals(scored, events_by_id)
        channels = {events_by_id[s.event_id].channel for s in scored}
        targets = set()
        for s in scored:
            e = events_by_id[s.event_id]
            if e.target_id:
                targets.add(e.target_id)
            elif e.channel == "upi" and e.actor_id and e.payee_vpa:
                targets.add(e.actor_id)   # payer is the affected target of a payment
        b = scfg["confidence_weights"]
        confidence = (b["b1"] * min(1.0, len(sigs) / scfg["n_sig"])
                      + b["b2"] * min(1.0, len(channels) / scfg["distinct_channels_cap"])
                      + b["b3"] * min(1.0, len(targets) / scfg["distinct_targets_k"]))

        amounts = sorted(events_by_id[s.event_id].amount for s in scored
                         if events_by_id[s.event_id].amount > 0)
        median_amt = amounts[len(amounts) // 2] if amounts else 0.0
        impact_cap = scfg["impact_cap"]
        impact = min(1.0, math.log1p(max(len(targets), 1) * median_amt) / math.log1p(impact_cap)) \
            if amounts else 0.0

        stages_seen = [s.stage for s in scored if s.stage]
        cats = {events_by_id[s.event_id].text_category for s in scored}
        signature = {"stage_set": sorted(set(stages_seen)), "channel_set": sorted(channels),
                     "category_set": sorted(cats)}
        novelty_score, closest = novelty(signature, scfg["novelty_reference_library"])

        pw = scfg.get("priority_weights", {"likelihood": 0.35, "confidence": 0.25,
                                           "novelty": 0.20, "impact": 0.20})
        priority = (pw["likelihood"] * likelihood + pw["confidence"] * confidence
                    + pw["novelty"] * novelty_score + pw["impact"] * impact)
        return {
            "likelihood": round(likelihood, 4), "confidence": round(confidence, 4),
            "novelty": round(novelty_score, 4), "impact": round(impact, 4),
            "priority": round(priority, 4),
            "components": {"stage_order_score": round(sos, 4), "top_anomaly_mean": round(tam, 4),
                           "rule_hit_ratio": round(rhr, 4), "independent_signals": len(sigs),
                           "distinct_channels": len(channels), "distinct_targets": len(targets),
                           "median_amount": median_amt},
            "signals": sigs, "signature": signature, "closest_known_typology": closest,
            "weights_applied": {"likelihood": a, "confidence": b,
                                "priority": pw},
        }
