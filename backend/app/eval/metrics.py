"""Evaluation harness: metrics defined precisely, computed on THIS code.

Metric definitions (also in README):
- Event-level precision/recall/F1 for flagging scam events; FPR = benign flagged/all benign.
- Campaign detection: alert cluster covers >=50% of campaign events with purity >=70%.
- Alert precision = alerts matching a true campaign / all alerts; false alert share = 1 - AP.
- Alerts per 1,000 events.
- Lead time: median (first_payment_ts - alert_created_ts) over campaigns with an alert;
  % alerted before first payment. Post-alert payments share within detected campaigns.
Headline numbers: TEST seeds only, mean +/- std over >=10 seeds. Reports: ablation,
baseline comparison, evasion variants, failure cases.
"""
from __future__ import annotations

import copy
import json
import logging
import statistics
from typing import Any

import numpy as np

from backend.app.baseline.per_event import EventBaseline, dedupe_by_entity
from backend.app.config import load_config
from backend.app.detector.anomaly import AnomalyScorer
from backend.app.detector.pipeline import DetectionPipeline
from backend.app.generator.synth import stream_for
from backend.app.schema import Event, GroundTruthEvent

log = logging.getLogger("fraudmesh.eval")


def _cfg_with_evasion(cfg: dict[str, Any], evasion: str | None) -> dict[str, Any]:
    """Return a config with exactly ONE evasion flag enabled (or the config default
    when evasion == 'none')."""
    c = copy.deepcopy(cfg)
    if evasion and evasion != "none":
        ev = {k: False for k in c["simulation"]["evasion"]}
        ev[evasion] = True
        c["simulation"]["evasion"] = ev
    return c


def _cfg_campaign_type(cfg: dict[str, Any], typology: str) -> dict[str, Any]:
    c = copy.deepcopy(cfg)
    c["generator"] = dict(c.get("generator") or {})
    c["generator"]["force_typology"] = typology
    return c


def run_stream(cfg: dict[str, Any], seed: int, anomaly: AnomalyScorer,
               layers: dict[str, bool] | None = None,
               thresholds: tuple[float, float] | None = None):
    """Replay one seeded stream through the pipeline; return alerts + ground truth."""
    events, gt = stream_for(cfg, seed)
    pipe = DetectionPipeline(cfg, anomaly_model=anomaly, layers=layers)
    if thresholds:
        pipe.manager.set_thresholds(*thresholds)
    alert_first_seen: dict[str, int] = {}     # alert_id -> sim ts when it first became eligible
    for e in events:
        deltas = pipe.process(e)
        for kind, a in deltas:
            aid = a.alert_id
            while True:
                cur = pipe.manager.alerts.get(aid)
                if not cur or cur.merged_into is None:
                    break
                aid = cur.merged_into
            if aid not in alert_first_seen:
                alert_first_seen[aid] = e.timestamp
    alerts = []
    for a in pipe.active_alerts():
        a_dict = a.model_dump()
        a_dict["_first_eligible_ts"] = alert_first_seen.get(a.alert_id, a.created_ts)
        alerts.append(a_dict)
    return events, gt, alerts


# ---------- metric computations ----------
def event_flags_from_alerts(alerts: list[dict]) -> set[str]:
    flagged = set()
    for a in alerts:
        flagged |= set(a["event_ids"])
    return flagged


def event_metrics(events: list[Event], gt: dict[str, GroundTruthEvent], flagged: set[str]) -> dict:
    tp = fp = fn = tn = 0
    benign_total = benign_flagged = 0
    for e in events:
        g = gt[e.event_id]
        is_flag = e.event_id in flagged
        if g.is_scam and not g.campaign_id:
            continue
        if g.is_scam:
            tp += is_flag
            fn += (not is_flag)
        else:
            benign_total += 1
            benign_flagged += is_flag
            tn += (not is_flag)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = benign_flagged / benign_total if benign_total else 0.0
    return {"event_precision": prec, "event_recall": rec, "event_f1": f1,
            "fpr": fpr, "benign_flagged": benign_flagged, "benign_total": benign_total}


def campaign_metrics(events: list[Event], gt: dict[str, GroundTruthEvent],
                     alerts: list[dict], coverage_min: float, purity_min: float) -> dict:
    camp_events: dict[str, set[str]] = {}
    camp_first_pay: dict[str, int] = {}
    for eid, g in gt.items():
        if g.campaign_id:
            camp_events.setdefault(g.campaign_id, set()).add(eid)
            if g.first_payment_ts:
                camp_first_pay[g.campaign_id] = min(camp_first_pay.get(g.campaign_id, 1 << 62),
                                                   g.first_payment_ts)
    ts_by_id = {e.event_id: e.timestamp for e in events}
    detected: dict[str, dict] = {}
    matched_alerts = 0
    for a in alerts:
        aset = set(a["event_ids"])
        best_cid, best_cov, best_pur = None, 0.0, 0.0
        for cid, ce in camp_events.items():
            inter = len(aset & ce)
            cov = inter / len(ce) if ce else 0.0
            pur = inter / len(aset) if aset else 0.0
            if cov >= coverage_min and pur >= purity_min and cov > best_cov:
                best_cid, best_cov, best_pur = cid, cov, pur
        if best_cid:
            matched_alerts += 1
            prev = detected.get(best_cid)
            if prev is None or a["_first_eligible_ts"] < prev["alert_ts"]:
                detected[best_cid] = {"alert_ts": a["_first_eligible_ts"], "coverage": best_cov,
                                      "purity": best_pur, "alert_id": a["alert_id"]}
    n_camps = len(camp_events)
    lead_times = []
    pct_before = 0
    post_share = []
    for cid in camp_events:
        fp_ts = camp_first_pay.get(cid)
        d = detected.get(cid)
        if d and fp_ts:
            lt = fp_ts - d["alert_ts"]           # positive => early
            lead_times.append(lt)
            pct_before += lt > 0
            pay_ts = sorted(ts_by_id[i] for i in camp_events[cid]
                            if gt[i].is_scam and _is_payment(i, events))
            after = sum(1 for t in pay_ts if t >= d["alert_ts"])
            post_share.append(after / len(pay_ts) if pay_ts else 0.0)
    ap = matched_alerts / len(alerts) if alerts else 0.0
    return {
        "campaigns_total": n_camps,
        "campaigns_detected": len(detected),
        "campaign_recall": len(detected) / n_camps if n_camps else 0.0,
        "alert_precision": ap,
        "false_alert_share": 1.0 - ap,
        "median_lead_time_sec": statistics.median(lead_times) if lead_times else None,
        "pct_alerted_before_first_payment": (pct_before / len(lead_times)) if lead_times else 0.0,
        "post_alert_payments_share": statistics.mean(post_share) if post_share else None,
        "detected_detail": detected,
    }


def _is_payment(eid: str, events: list[Event]) -> bool:
    for e in events:
        if e.event_id == eid:
            return e.channel == "upi" and e.amount > 0
    return False


def alerts_per_1000(alerts: list[dict], n_events: int) -> float:
    return 1000.0 * len(alerts) / max(n_events, 1)


def baseline_metrics(cfg, events, gt, tune_events, tune_labels) -> dict:
    bl = EventBaseline(cfg)
    bl.fit(tune_events, tune_labels)
    flags = {}
    for e in events:
        is_flag, score = bl.flag_event(e)
        if is_flag:
            flags[e.event_id] = score
    em = event_metrics(events, gt, set(flags))
    fake_alerts = [{"event_ids": [eid], "_first_eligible_ts": next(
        e.timestamp for e in events if e.event_id == eid)} for eid in flags]
    cm = campaign_metrics(events, gt, fake_alerts, cfg["eval"]["campaign_coverage_min"],
                          cfg["eval"]["campaign_purity_min"])
    deduped = dedupe_by_entity(flags, {e.event_id: e for e in events})
    return {"per_event_flags": len(flags), "alerts_per_1000_events":
            alerts_per_1000(fake_alerts, len(events)), **em,
            "campaign_recall": cm["campaign_recall"],
            "dedupe_alerts": len(deduped),
            "dedupe_alerts_per_1000": 1000.0 * len(deduped) / max(len(events), 1)}


def aggregate(runs: list[dict]) -> dict:
    out = {}
    for key in runs[0]:
        vals = [r[key] for r in runs if isinstance(r[key], (int, float)) and r[key] is not None]
        if vals:
            out[key] = {"mean": round(float(np.mean(vals)), 4),
                        "std": round(float(np.std(vals)), 4)}
    return out
