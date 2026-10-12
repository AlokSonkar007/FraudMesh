"""Layer 1 — deterministic rules.

Blocklisted entities, domain/payee reputation lookups, known-bad pattern flags.
Returns per-event RuleHit list. Blocklist/allowlist are mutable at runtime via the
analyst feedback loop (confirm -> blocklist, dismiss -> allowlist with TTL).
"""
from __future__ import annotations

import time
from typing import Any

from backend.app.schema import Event, RuleHit


class RuleEngine:
    def __init__(self, cfg: dict[str, Any]):
        rep = cfg["reputation"]
        self.blocked_domains = set(rep["blocked_domains"])
        self.blocked_vpAs = set(rep["blocked_vpAs"])
        self.blocked_actors = set(rep.get("blocked_actors") or [])
        self.legit_domains = set(rep["legit_domains"])
        self.legit_vpAs = set(rep["legit_vpAs"])
        self.allow_ttl: dict[str, int] = {}          # entity -> expiry sim-time
        self.ttl_hours = cfg["alert"]["dedupe_ttl_hours"]
        self.new_payees: set[str] = set()            # payees seen for first time
        self.seen_payees: set[str] = set()
        self.now_ts: int = 0

    # ---- runtime mutation from analyst feedback ----
    def block_actor(self, actor_id: str) -> None:
        self.blocked_actors.add(actor_id)

    def allow_entity(self, entity: str, sim_ts: int) -> None:
        self.allow_ttl[entity] = sim_ts + self.ttl_hours * 3600

    def _allowed(self, entity: str | None) -> bool:
        return bool(entity) and self.allow_ttl.get(entity, 0) > self.now_ts

    # ---- scoring ----
    def evaluate(self, event: Event) -> list[RuleHit]:
        self.now_ts = max(self.now_ts, event.timestamp)
        hits: list[RuleHit] = []
        cat = event.text_category
        tf = event.text_features

        if event.actor_id in self.blocked_actors:
            hits.append(RuleHit(rule="blocked_actor", detail="actor on confirmed blocklist"))
        if event.url_domain in self.blocked_domains:
            hits.append(RuleHit(rule="bad_domain", detail=f"domain {event.url_domain} blocklisted"))
        elif event.url_domain and self._allowed(event.url_domain):
            pass
        elif event.url_domain and event.url_domain not in self.legit_domains:
            hits.append(RuleHit(rule="unknown_domain", detail=f"unrecognized domain {event.url_domain}", weight=0.5))

        if event.payee_vpa in self.blocked_vpAs:
            hits.append(RuleHit(rule="bad_payee", detail=f"VPA {event.payee_vpa} blocklisted"))
        elif event.payee_vpa and self._allowed(event.payee_vpa):
            pass
        elif event.payee_vpa and event.payee_vpa not in self.legit_vpAs:
            if event.payee_vpa not in self.seen_payees:
                self.new_payees.add(event.payee_vpa)
                hits.append(RuleHit(rule="new_payee", detail="first-seen payee VPA", weight=0.5))
            self.seen_payees.add(event.payee_vpa)

        # known-bad pattern flags (numeric features only; detector never sees free text)
        if tf.get("urgency", 0) >= 4 and cat in ("urgency_threat", "penalty_threat",
                                                 "account_lock_warning"):
            hits.append(RuleHit(rule="high_urgency_threat", detail="max-urgency pressure category"))
        if cat == "remote_access_prompt":
            hits.append(RuleHit(rule="remote_access", detail="remote-access indicator"))
        if tf.get("has_link", 0) and tf.get("reply_requested", 0) and \
                cat in ("refund_offer", "kyc_update") and self._unknown_domain(event):
            hits.append(RuleHit(rule="lure_pattern", detail="link+reply lure on unrecognized domain"))
        if event.channel == "upi" and event.amount >= 25000 and \
                event.payee_vpa in self.new_payees:
            hits.append(RuleHit(rule="large_to_new_payee", detail="large payment to first-seen payee"))
        return hits

    def _unknown_domain(self, event: Event) -> bool:
        d = event.url_domain
        return bool(d) and d not in self.legit_domains and not self._allowed(d)
