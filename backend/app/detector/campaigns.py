"""Layer 3c — campaign candidates, alert lifecycle (ONE alert per campaign).

Components from the entity graph become campaign candidates. An alert fires only if:
independent_signals >= N_min AND distinct_channels >= 2 AND confidence >= theta_c
AND likelihood >= theta_l. New events update the existing alert and append to its
timeline; when two candidate clusters share entities they merge, keeping the OLDEST
alert id and recording the merge. States: open/updated/confirmed/dismissed/escalated.
"""
from __future__ import annotations

import hashlib
import logging
from typing import Any

from backend.app.schema import Alert, Event, Explanation, ScoredEvent, TimelineItem

log = logging.getLogger("fraudmesh.campaigns")


def component_key(event_ids: list[str]) -> str:
    return hashlib.sha1("|".join(sorted(event_ids)).encode()).hexdigest()[:12]


class CampaignManager:
    """Maps graph components to alerts with stable identity via entity overlap."""

    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self.acfg = cfg["alert"]
        # key -> alert id
        self.key_to_alert: dict[str, str] = {}
        # alert id -> set of entity keys ("etype:val") that anchor it
        self.alert_entities: dict[str, set[str]] = {}
        self.alerts: dict[str, Alert] = {}
        self.events_by_id: dict[str, Event] = {}
        self.scored_by_id: dict[str, ScoredEvent] = {}

    # ---------- eligibility ----------
    def eligible(self, result: dict[str, Any]) -> bool:
        comp = result["components"]
        if comp["independent_signals"] < self.acfg["n_min"]:
            return False
        if self.acfg.get("require_multi_channel", True) and comp["distinct_channels"] < 2:
            return False
        return (result["confidence"] >= self.threshold("theta_c")
                and result["likelihood"] >= self.threshold("theta_l"))

    def threshold(self, name: str) -> float:
        return self.acfg[name]

    def set_thresholds(self, theta_c: float, theta_l: float) -> None:
        self.acfg["theta_c"], self.acfg["theta_l"] = theta_c, theta_l

    # ---------- main entry ----------
    def update(self, comps: list[list[str]], events_by_id: dict[str, Event],
               scored_by_id: dict[str, ScoredEvent], scorer_results: dict[str, dict],
               graph_dump_fn) -> list[tuple[str, Alert, str]]:
        """Process current components; returns [(kind, alert)] for created/updated/merged."""
        self.events_by_id = events_by_id
        self.scored_by_id = scored_by_id
        out: list[tuple[str, Alert, str]] = []
        live_keys: set[str] = set()

        for ev_ids in comps:
            scored = [scored_by_id[i] for i in ev_ids if i in scored_by_id]
            if len(scored) < 2:
                continue
            key = component_key(ev_ids)
            live_keys.add(key)
            res = scorer_results.get(key)
            if res is None:
                continue
            ents = self._entities_of(ev_ids)

            # find an existing alert this component should attach to (entity overlap)
            match = self._match_alert(ents)
            if match is None and key in self.key_to_alert:
                match = self.key_to_alert[key]

            if not self.eligible(res):
                if match and self.alerts[match].state in ("open", "updated"):
                    pass  # keep existing alert; do not retract analyst-visible state
                continue

            alert = self._build_or_update(match, ev_ids, scored, res, graph_dump_fn)
            kind = "created" if match is None else "updated"
            if match is None:
                self.key_to_alert[key] = alert.alert_id
            out.append((kind, alert, key))

        # merges: two alerts now sharing entities -> keep oldest id
        out.extend(self._merge_pass(graph_dump_fn, scored_by_id, scorer_results))
        return out

    def _entities_of(self, ev_ids: list[str]) -> set[str]:
        ents = set()
        for i in ev_ids:
            e = self.events_by_id.get(i)
            if not e:
                continue
            for f in ("actor_id", "target_id", "device_id", "url_domain", "payee_vpa"):
                v = getattr(e, f)
                if v:
                    ents.add(f"{f}:{v}")
        return ents

    def _match_alert(self, ents: set[str]) -> str | None:
        best, best_ov = None, 0
        for aid, aents in self.alert_entities.items():
            ov = len(ents & aents)
            if ov > best_ov:
                best, best_ov = aid, ov
        return best if best_ov >= 1 else None

    def _build_or_update(self, match: str | None, ev_ids: list[str], scored: list[ScoredEvent],
                         res: dict[str, Any], graph_dump_fn) -> Alert:
        now_ts = max(self.events_by_id[i].timestamp for i in ev_ids)
        timeline = self._timeline(ev_ids)
        stages_seen = sorted({t.stage for t in timeline if t.stage},
                             key=lambda s: ["contact", "pressure", "instruction", "payment"].index(s))
        expl = Explanation(
            signals=res["signals"], timeline=timeline,
            entities=self._entity_map(ev_ids), scores={k: res[k] for k in
                  ("likelihood", "confidence", "novelty", "impact", "priority")},
            weights_applied=res["weights_applied"])
        if match and match in self.alerts:
            a = self.alerts[match]
            new_events = [i for i in ev_ids if i not in a.event_ids]
            a.event_ids = sorted(set(a.event_ids) | set(ev_ids))
            a.updated_ts = now_ts
            a.state = "updated" if a.state == "open" else a.state
            a.stages_seen = stages_seen or a.stages_seen
            a.scores = {k: res[k] for k in ("likelihood", "confidence", "novelty", "impact", "priority")}
            a.explanation = expl
            a.typology_guess = res.get("closest_known_typology")
            self.alert_entities[match] |= self._entities_of(new_events)
            return a
        aid = "alrt-" + hashlib.sha1(("|".join(sorted(ev_ids))).encode()).hexdigest()[:10]
        a = Alert(alert_id=aid, campaign_key=component_key(ev_ids), created_ts=now_ts,
                  updated_ts=now_ts, event_ids=sorted(ev_ids), stages_seen=stages_seen,
                  typology_guess=res.get("closest_known_typology"),
                  scores=a_scores(res), explanation=expl)
        a.summary = template_summary(a, res)
        self.alerts[aid] = a
        self.alert_entities[aid] = self._entities_of(ev_ids)
        log.info("alert created %s priority=%.3f events=%d", aid, a.scores["priority"], len(ev_ids))
        return a

    def _entity_map(self, ev_ids: list[str]) -> dict[str, list[str]]:
        m: dict[str, set] = {}
        for i in ev_ids:
            e = self.events_by_id.get(i)
            if not e:
                continue
            pairs = [("actor", e.actor_id), ("target", e.target_id), ("device", e.device_id),
                     ("url_domain", e.url_domain), ("payee_vpa", e.payee_vpa)]
            for k, v in pairs:
                if v:
                    m.setdefault(k, set()).add(v)
        return {k: sorted(v) for k, v in m.items()}

    def _timeline(self, ev_ids: list[str]) -> list[TimelineItem]:
        items = []
        for i in sorted(ev_ids, key=lambda x: (self.events_by_id[x].timestamp, x)):
            e = self.events_by_id[i]
            se = self.scored_by_id.get(i)
            items.append(TimelineItem(event_id=i, timestamp=e.timestamp, stage=se.stage if se else None,
                                      channel=e.channel, text_category=e.text_category,
                                      summary=f"[{e.text_category}]",
                                      anomaly=se.anomaly if se else 0.0,
                                      rule_hits=[h.rule for h in se.rule_hits] if se else []))
        return items

    def _merge_pass(self, graph_dump_fn, scored_by_id, scorer_results) -> list[tuple[str, Alert, str]]:
        ids = list(self.alerts.keys())
        merged_any: list[tuple[str, Alert, str]] = []
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                a, b = self.alerts.get(ids[i]), self.alerts.get(ids[j])
                if not a or not b or a.merged_into or b.merged_into:
                    continue
                if self.alert_entities[a.alert_id] & self.alert_entities[b.alert_id]:
                    old, new = (a, b) if a.created_ts <= b.created_ts else (b, a)
                    old.event_ids = sorted(set(old.event_ids) | set(new.event_ids))
                    old.updated_ts = max(old.updated_ts, new.updated_ts)
                    old.state = "updated" if old.state in ("open", "updated") else old.state
                    old.merges.append({"absorbed": new.alert_id, "at_ts": old.updated_ts})
                    old.explanation.timeline = self._timeline(old.event_ids)
                    old.explanation.entities = self._entity_map(old.event_ids)
                    old.stages_seen = sorted(
                        {t.stage for t in old.explanation.timeline if t.stage},
                        key=lambda s: ["contact", "pressure", "instruction", "payment"].index(s))
                    new.merged_into = old.alert_id
                    self.alert_entities[old.alert_id] |= self.alert_entities.pop(new.alert_id, set())
                    for k, v in list(self.key_to_alert.items()):
                        if v == new.alert_id:
                            self.key_to_alert[k] = old.alert_id
                    log.info("alert merge: %s absorbed into %s", new.alert_id, old.alert_id)
                    merged_any.append(("merged", old, old.campaign_key))
        return merged_any


def a_scores(res: dict[str, Any]) -> dict[str, float]:
    return {k: res[k] for k in ("likelihood", "confidence", "novelty", "impact", "priority")}


def template_summary(alert: Alert, res: dict[str, Any]) -> str:
    """Deterministic analyst summary. Used offline and as LLM-fallback payload source."""
    c = res["components"]
    pay = next((t for t in alert.explanation.timeline if t.stage == "payment"), None)
    timing = "before any payment event" if pay is None else f"at/near first payment ({pay.summary})"
    return (f"Candidate multi-stage campaign: {len(alert.event_ids)} linked events across "
            f"{c['distinct_channels']} channels affecting {c['distinct_targets']} targets. "
            f"Stage chain covers {c['stage_order_score']*4:.0f}/4 ordered stages; "
            f"{c['independent_signals']} independent signals; closest known typology: "
            f"{res.get('closest_known_typology') or 'none'}; novelty {res['novelty']:.2f}. "
            f"Alert raised {timing}. Priority {res['priority']:.2f} "
            f"(L {res['likelihood']:.2f} / C {res['confidence']:.2f} / N {res['novelty']:.2f} "
            f"/ I {res['impact']:.2f}). SYNTHETIC DATA.")
