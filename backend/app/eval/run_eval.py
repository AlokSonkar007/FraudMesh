"""`make eval` entry point. Runs the harness and writes results.json + results.md.

Pipeline:
1. Generate TUNE streams -> fit anomaly model on BENIGN TUNE events; fit baseline LR
   on labeled TUNE events.
2. Grid-search theta_c/theta_l on TUNE (max campaign recall, tie-break alert precision).
3. Run TEST seeds (>=10) with tuned thresholds: full detector, baselines, ablations,
   evasion variants, per-typology breakdown.
4. Collect failure cases (missed campaigns / false alerts) with reasons. Report as-is.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any

from backend.app.baseline.per_event import EventBaseline, dedupe_by_entity
from backend.app.config import load_config
from backend.app.detector.anomaly import AnomalyScorer
from backend.app.eval.metrics import (_cfg_campaign_type, _cfg_with_evasion, aggregate,
                                      alerts_per_1000, campaign_metrics, event_flags_from_alerts,
                                      event_metrics, run_stream)
from backend.app.generator.synth import stream_for

log = logging.getLogger("fraudmesh.eval.run")
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


def tune_data(cfg) -> tuple[list, dict, list, list]:
    ev_all, gt_all, t_events, t_labels = [], {}, [], []
    for seed in cfg["eval"]["tune_seeds"]:
        events, gt = stream_for(cfg, seed)
        ev_all += events
        gt_all.update(gt)
        for e in events:
            t_events.append(e)
            t_labels.append(1 if gt[e.event_id].is_scam else 0)
    benign = [e for e in ev_all if not gt_all[e.event_id].is_scam]
    return benign, gt_all, t_events, t_labels


def sweep_thresholds(cfg, runs_raw: list, anomaly) -> tuple[float, float, dict]:
    """Grid search on TUNE streams only."""
    best = (0.45, 0.42, {"campaign_recall": -1, "alert_precision": -1})
    grid = [round(x, 2) for x in [i / 20 for i in range(6, 18)]]     # 0.30..0.85
    curves = {}
    for tc in grid:
        for tl in grid:
            recs, aps = [], []
            for seed in cfg["eval"]["tune_seeds"]:
                events, gt, alerts = run_stream(cfg, seed, anomaly, thresholds=(tc, tl))
                cm = campaign_metrics(events, gt, alerts, cfg["eval"]["campaign_coverage_min"],
                                      cfg["eval"]["campaign_purity_min"])
                recs.append(cm["campaign_recall"])
                aps.append(cm["alert_precision"] if alerts else 0.0)
            r = sum(recs) / len(recs)
            p = sum(aps) / len(aps)
            key = (r, p)
            if key > (best[2]["campaign_recall"], best[2]["alert_precision"]):
                best = (tc, tl, {"campaign_recall": round(r, 4), "alert_precision": round(p, 4)})
    curves["tuned_on"] = "TUNE seeds"
    curves["theta_c"], curves["theta_l"] = best[0], best[1]
    curves.update(best[2])
    return best[0], best[1], curves


def typology_breakdown(cfg, seeds, anomaly, thresholds) -> dict:
    out = {}
    for typ in ["authority_impersonation", "refund_kyc_lure", "mule_fan_in"]:
        c = _cfg_campaign_type(cfg, typ)
        recs, lts = [], []
        for seed in seeds:
            events, gt, alerts = run_stream(c, seed, anomaly, thresholds=thresholds)
            cm = campaign_metrics(events, gt, alerts, cfg["eval"]["campaign_coverage_min"],
                                  cfg["eval"]["campaign_purity_min"])
            recs.append(cm["campaign_recall"])
            if cm["median_lead_time_sec"] is not None:
                lts.append(cm["median_lead_time_sec"])
        out[typ] = {"recall_mean": round(sum(recs) / len(recs), 4),
                    "median_lead_sec": round(sum(lts) / len(lts), 1) if lts else None}
    return out


def failure_cases(cfg, seeds, anomaly, thresholds) -> list[dict]:
    fails = []
    for seed in seeds:
        events, gt, alerts = run_stream(cfg, seed, anomaly, thresholds=thresholds)
        cm = campaign_metrics(events, gt, alerts, cfg["eval"]["campaign_coverage_min"],
                              cfg["eval"]["campaign_purity_min"])
        camp_ev: dict[str, set] = {}
        for eid, g in gt.items():
            if g.campaign_id:
                camp_ev.setdefault(g.campaign_id, set()).add(eid)
        detected = cm["detected_detail"]
        flagged = event_flags_from_alerts(alerts)
        for cid, ce in camp_ev.items():
            if cid in detected:
                continue
            best_cov, best_pur, best_id = 0, 0, None
            for a in alerts:
                aset = set(a["event_ids"])
                cov = len(aset & ce) / len(ce) if ce else 0
                pur = len(aset & ce) / len(aset) if aset else 0
                if cov > best_cov or (cov == best_cov and pur > best_pur):
                    best_cov, best_pur, best_id = cov, pur, a["alert_id"]
            reason = ("no overlapping alert" if best_cov == 0 else
                      f"partial overlap coverage={best_cov:.2f} purity={best_pur:.2f} below gate")
            missed_ev = sorted(ce - flagged)
            fails.append({"type": "missed_campaign", "seed": seed, "campaign_id": cid,
                          "reason": reason, "n_events": len(ce),
                          "unflagged_events": len(missed_ev), "closest_alert": best_id})
        det_ids = {d["alert_id"] for d in detected.values()}
        for a in alerts:
            if a["alert_id"] not in det_ids:
                aset = set(a["event_ids"])
                scam_in = sum(1 for e in aset if gt[e].is_scam)
                fails.append({"type": "false_alert", "seed": seed, "alert_id": a["alert_id"],
                              "reason": f"cluster did not meet coverage/purity gate "
                                        f"(scam fraction {scam_in}/{len(aset)})",
                              "priority": a["scores"].get("priority"),
                              "entities": a["explanation"]["entities"]})
    return fails


def fmt(v, pct=False):
    if v is None:
        return "n/a"
    if pct:
        return f"{100*v:.1f}%"
    if isinstance(v, float):
        return f"{v:.2f}"
    return str(v)


def write_md(path, res):
    h = res["headline"]; b = res["baseline_compare"]; ab = res["ablation"]; ev = res["evasion"]
    lines = [
        "# FraudMesh evaluation results",
        "",
        "> **All numbers come from this repository's evaluation harness running on",
        "> self-generated synthetic data.** They show behavior on the modeled typologies,",
        "> **not real-world performance.** Thresholds were tuned on TUNE seeds only;",
        f"> headline metrics are mean ± std over {res['meta']['n_test_seeds']} TEST seeds.",
        "",
        "## Headline (proposed system, TEST seeds)",
        "",
        "| metric | value |",
        "|---|---|",
    ]
    def row(name, m, pct=False):
        if m is None:
            lines.append(f"| {name} | n/a |")
        else:
            lines.append(f"| {name} | {fmt(m['mean'], pct)} ± {m['std']:.2f} |")
    row("Campaign recall (coverage≥50%, purity≥70%)", h.get("campaign_recall"), True)
    row("Alert precision", h.get("alert_precision"), True)
    row("False alert share", h.get("false_alert_share"), True)
    row("% campaigns alerted before first payment", h.get("pct_alerted_before_first_payment"), True)
    med = h.get("median_lead_time_sec")
    lines.append(f"| median lead time (sec, +ve = early) | {fmt(med['mean'])} ± {med['std']:.0f} |"
                 if med else "| median lead time | n/a |")
    row("Event-level recall", h.get("event_recall"), True)
    row("Event-level precision", h.get("event_precision"), True)
    row("Event-level F1", h.get("event_f1"))
    row("FPR (benign events flagged)", h.get("fpr"), True)
    row("Alerts per 1,000 events", h.get("alerts_per_1000"))
    row("Post-alert payments share (detected campaigns)*", h.get("post_alert_payments_share"), True)
    lines += ["", "*Share of payments inside detected campaigns occurring at/after the alert.",
              "This is NOT 'losses prevented' — it is a timing statistic on synthetic data.", "",
              "## Baseline comparison (TEST seeds, same streams)", ""]
    keys = ["campaign_recall", "event_recall", "fpr", "alerts_per_1000"]
    lines.append("| metric | baseline (per-event) | baseline+dedupe | proposed |")
    lines.append("|---|---|---|---|")
    labels = {"campaign_recall": "campaign recall", "event_recall": "event recall",
              "fpr": "FPR", "alerts_per_1000": "alerts/1k events"}
    for k in keys:
        bb = b["baseline"].get(k); dd = b["baseline_dedupe"].get(k); pp = h.get(k)
        def cell(m, pct=k in ("campaign_recall", "event_recall", "fpr")):
            return "n/a" if m is None else fmt(m["mean"], pct)
        extra = ""
        if k == "alerts_per_1000":
            extra = f" ({b['baseline']['flags_mean']:.0f} flags → {b['baseline']['dedupe_mean']:.0f} alerts)"
        lines.append(f"| {labels[k]} | {cell(bb)}{extra if k=='alerts_per_1000' else ''} | {cell(dd)} | {cell(pp)} |")
    lines += ["", "## Ablation (TEST seeds, mean)", ""]
    lines.append("| configuration | campaign recall | % before payment | alerts/1k | FPR |")
    lines.append("|---|---|---|---|---|")
    for name, m in ab.items():
        lines.append(f"| {name} | {fmt(m.get('campaign_recall',{}).get('mean'), True)} | "
                     f"{fmt(m.get('pct_alerted_before_first_payment',{}).get('mean'), True)} | "
                     f"{fmt(m.get('alerts_per_1000',{}).get('mean'))} | "
                     f"{fmt(m.get('fpr',{}).get('mean'), True)} |")
    lines += ["", "## Evasion variants (TEST seeds, mean campaign recall)", ""]
    lines.append("| variant | campaign recall | % before payment | alerts/1k |")
    lines.append("|---|---|---|---|")
    for name, m in ev.items():
        lines.append(f"| {name} | {fmt(m.get('campaign_recall',{}).get('mean'), True)} | "
                     f"{fmt(m.get('pct_alerted_before_first_payment',{}).get('mean'), True)} | "
                     f"{fmt(m.get('alerts_per_1000',{}).get('mean'))} |")
    lines += ["", "## Per-typology (TEST seeds)", "",
              "| typology | recall | median lead (s) |", "|---|---|---|"]
    for t, m in res["typology"].items():
        lines.append(f"| {t} | {fmt(m['recall_mean'], True)} | {fmt(m['median_lead_sec'])} |")
    fc = res["failure_cases"]
    lines += ["", f"## Failure cases ({len(fc)} across TEST seeds) — reported as-is", ""]
    missed = [f for f in fc if f["type"] == "missed_campaign"]
    false = [f for f in fc if f["type"] == "false_alert"]
    lines.append(f"- Missed campaigns: {len(missed)}; false alerts: {len(false)}.")
    for f in fc[:25]:
        if f["type"] == "missed_campaign":
            lines.append(f"- MISSED seed={f['seed']} {f['campaign_id']}: {f['reason']} "
                         f"({f['n_events']} events)")
        else:
            lines.append(f"- FALSE ALERT seed={f['seed']} {f['alert_id']}: {f['reason']}")
    if len(fc) > 25:
        lines.append(f"- …and {len(fc)-25} more (see results.json).")
    lines += ["", "## Tuning", "",
              f"theta_c={res['tuning']['theta_c']}, theta_l={res['tuning']['theta_l']} "
              f"(grid search on {res['tuning']['tuned_on']} only).", ""]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def main() -> dict:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    cfg = load_config()
    ecfg = cfg["eval"]
    log.info("generating TUNE streams…")
    benign_tune, _, t_events, t_labels = tune_data(cfg)
    anomaly = AnomalyScorer(cfg)
    anomaly.fit(benign_tune)
    log.info("fitting baseline LR on labeled TUNE events…")
    base_model = EventBaseline(cfg)
    base_model.fit(t_events, t_labels)

    theta_c, theta_l, tuning = sweep_thresholds(cfg, None, anomaly)
    log.info("tuned thresholds: theta_c=%.2f theta_l=%.2f (TUNE recall=%.2f AP=%.2f)",
             theta_c, theta_l, tuning["campaign_recall"], tuning["alert_precision"])

    test_seeds = ecfg["test_seeds"]
    layers_full = {"rules": True, "anomaly": True, "graph": True}

    def suite(layers, thresholds=(theta_c, theta_l)):
        runs = []
        for seed in test_seeds:
            events, gt, alerts = run_stream(cfg, seed, anomaly, layers=layers,
                                            thresholds=thresholds)
            em = event_metrics(events, gt, event_flags_from_alerts(alerts))
            cm = campaign_metrics(events, gt, alerts, ecfg["campaign_coverage_min"],
                                  ecfg["campaign_purity_min"])
            r = {**em, **{k: v for k, v in cm.items() if k != "detected_detail"},
                 "alerts_per_1000": alerts_per_1000(alerts, len(events)),
                 "n_alerts": len(alerts)}
            runs.append(r)
        return aggregate(runs)

    log.info("headline runs (full detector)…")
    headline = suite(layers_full)

    log.info("ablation…")
    ablation = {
        "rules_only": suite({"rules": True, "anomaly": False, "graph": False}),
        "rules_plus_anomaly": suite({"rules": True, "anomaly": True, "graph": False}),
        "rules_anomaly_graph": headline,
    }

    log.info("baseline comparison…")
    bl_runs, bd_runs = [], []
    for seed in test_seeds:
        events, gt = stream_for(cfg, seed)
        b = base_model
        flags = {}
        for e in events:
            is_flag, score = b.flag_event(e)
            if is_flag:
                flags[e.event_id] = score
        fake = [{"event_ids": [eid], "_first_eligible_ts": next(
            e.timestamp for e in events if e.event_id == eid)} for eid in flags]
        em = event_metrics(events, gt, set(flags))
        cm = campaign_metrics(events, gt, fake, ecfg["campaign_coverage_min"],
                              ecfg["campaign_purity_min"])
        deduped = dedupe_by_entity(flags, {e.event_id: e for e in events})
        bl_runs.append({**em, "campaign_recall": cm["campaign_recall"],
                        "alerts_per_1000": alerts_per_1000(fake, len(events)),
                        "flags_mean": len(flags), "dedupe_mean": len(deduped)})
        bd_runs.append({"campaign_recall": cm["campaign_recall"],
                        "event_recall": em["event_recall"], "fpr": em["fpr"],
                        "alerts_per_1000": 1000.0 * len(deduped) / max(len(events), 1)})
    baseline_compare = {"baseline": aggregate(bl_runs), "baseline_dedupe": aggregate(bd_runs)}
    # carry flag counts through aggregation
    for agg, raw in ((baseline_compare["baseline"], bl_runs),):
        agg["flags_mean"] = {"mean": sum(r["flags_mean"] for r in raw) / len(raw), "std": 0}
        agg["dedupe_mean"] = {"mean": sum(r["dedupe_mean"] for r in raw) / len(raw), "std": 0}

    log.info("evasion variants…")
    evasion = {}
    for var in ecfg["evasions"]:
        cvar = _cfg_with_evasion(cfg, var)
        runs = []
        for seed in test_seeds:
            events, gt, alerts = run_stream(cvar, seed, anomaly, layers=layers_full,
                                            thresholds=(theta_c, theta_l))
            cm = campaign_metrics(events, gt, alerts, ecfg["campaign_coverage_min"],
                                  ecfg["campaign_purity_min"])
            em = event_metrics(events, gt, event_flags_from_alerts(alerts))
            runs.append({**cm, **em, "alerts_per_1000": alerts_per_1000(alerts, len(events))})
        evasion[var] = aggregate(runs)

    log.info("per-typology + failure cases…")
    typology = typology_breakdown(cfg, test_seeds, anomaly, (theta_c, theta_l))
    failures = failure_cases(cfg, test_seeds, anomaly, (theta_c, theta_l))

    res = {
        "meta": {
            "disclaimer": ("Results come from self-generated synthetic data and show behavior "
                           "on the modeled typologies, NOT real-world performance."),
            "n_test_seeds": len(test_seeds), "n_tune_seeds": len(ecfg["tune_seeds"]),
            "config_hash": str(hash(json.dumps(cfg, sort_keys=True))),
        },
        "tuning": tuning, "headline": headline, "ablation": ablation,
        "baseline_compare": baseline_compare, "evasion": evasion,
        "typology": typology, "failure_cases": failures,
    }
    os.makedirs(REPO, exist_ok=True)
    with open(os.path.join(REPO, "results.json"), "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=2, default=str)
    write_md(os.path.join(REPO, "results.md"), res)
    log.info("wrote results.json / results.md")
    return res


if __name__ == "__main__":
    main()
