"""Seeded synthetic event generator with ground truth.

Deterministic: same (seed, scenario, evasion flags) => identical stream.
Synthetic data only: fictional phone format 91XXXXXXNN hashed to actor ids,
no real agency/bank/brand names, no scam scripts (enumerated categories only).
"""
from __future__ import annotations

import hashlib
import random
from typing import Any, Iterator

from backend.app.schema import Event, GroundTruthEvent

FICTIONAL_PREFIXES = ["91", "98", "97"]  # fictional-format, not allocated ranges


def hash_id(kind: str, raw: str, seed: int) -> str:
    """Pseudonymize an identifier deterministically."""
    h = hashlib.sha256(f"{kind}:{seed}:{raw}".encode()).hexdigest()[:16]
    return f"{kind[:3]}-{h}"


def fake_phone(rng: random.Random) -> str:
    return rng.choice(FICTIONAL_PREFIXES) + "".join(rng.choice("0123456789") for _ in range(9))


SCAM_DOMAINS = ["secure-kyc-verify.example", "refund-helpdesk.example", "bank-update-portal.example"]
SCAM_VPAS = ["fakepayee@okaxisbank", "urgentrefund@ybl", "mulewallet@apl"]
LEGIT_DOMAINS = ["notify.bankalert.example", "cdn.paytmexample", "help.bankcare.example"]
LEGIT_VPAS = ["cityrent@okhdfcbank", "tuition.univ@ybl", "popularstore@apl"]
HUB_PAYEE = "popularstore@apl"          # benign hub: many victims pay it (must NOT cluster)
POPULAR_ACTOR = "bcast-notifier"        # benign broadcast alert sender (hub actor)


class ScenarioGenerator:
    def __init__(self, cfg: dict[str, Any], seed: int, overrides: dict[str, Any] | None = None):
        sim = dict(cfg["simulation"])
        if overrides:
            ev = overrides.pop("evasion", None)
            sim.update(overrides)
            if ev is not None:
                merged = dict(sim.get("evasion", {}))
                merged.update(ev)
                sim["evasion"] = merged
        self.sim = sim
        self.force_typology = (cfg.get("generator") or {}).get("force_typology") or ""
        self.seed = seed
        self.rng = random.Random(seed)
        self.ev = sim.get("evasion", {})
        self._n = 0
        self.events: list[Event] = []
        self.ground_truth: dict[str, GroundTruthEvent] = {}

    # ---------- helpers ----------
    def _eid(self) -> str:
        self._n += 1
        return f"ev-{self.seed}-{self._n:06d}"

    def _phone_actor(self, tag: str) -> str:
        return hash_id("actor", fake_phone(self.rng) + tag, self.seed)

    def mk(self, ts: int, channel: str, category: str, features: dict[str, float],
           actor: str | None = None, target: str | None = None, device: str | None = None,
           domain: str | None = None, payee: str | None = None, amount: float = 0.0,
           campaign_id: str | None = None, typology: str | None = None) -> Event:
        eid = self._eid()
        e = Event(event_id=eid, timestamp=ts, channel=channel, actor_id=actor, target_id=target,
                  device_id=device, url_domain=domain, payee_vpa=payee, amount=amount,
                  text_category=category, text_features=features)
        self.events.append(e)
        self.ground_truth[eid] = GroundTruthEvent(
            event_id=eid, campaign_id=campaign_id, is_scam=campaign_id is not None,
            typology=typology)
        return e

    # ---------- scam typologies ----------
    def gen_campaign(self, t0: int, cid: str, typology: str) -> int:
        """Emit one campaign; returns first-payment timestamp.

        Typologies rotate deterministically by campaign index unless the config
        forces a single typology (used for per-typology evaluation reports).
        """
        kinds = ["authority_impersonation", "refund_kyc_lure", "mule_fan_in"]
        idx = int(cid.rsplit("-", 1)[-1])
        kind = self.force_typology or (typology if typology in kinds else kinds[idx % 3])
        if kind == "authority_impersonation":
            return self._campaign_authority(t0, cid)
        if kind == "refund_kyc_lure":
            return self._campaign_refund(t0, cid)
        return self._campaign_mule(t0, cid)

    def _stage_gap(self, lo_min: int, hi_min: int) -> int:
        return self.rng.randint(lo_min, hi_min) * 60

    def _campaign_authority(self, t0: int, cid: str) -> int:
        nv = 1 if self.ev.get("low_volume_single_victim") else self.rng.randint(
            self.sim["victims_min"], self.sim["victims_max"])
        scammer = self._phone_actor("boss")
        device = hash_id("device", f"remote-{cid}", self.seed)
        domain = HUB_PAYEE and (LEGIT_DOMAINS[0] if self.ev.get("reuse_legitimate")
                                else SCAM_DOMAINS[self.rng.randrange(len(SCAM_DOMAINS))])
        payee = LEGIT_VPAS[0] if self.ev.get("reuse_legitimate") else \
            SCAM_VPAS[self.rng.randrange(len(SCAM_VPAS))]
        first_pay = None
        for v in range(nv):
            victim = self._phone_actor(f"v{cid}{v}")
            vdev = hash_id("device", f"rot-{cid}-{v}-{self.rng.random()}", self.seed) \
                if self.ev.get("rotated_identifiers") else hash_id("device", f"ph-{cid}-{v}", self.seed)
            t = t0
            ch_call = "call"
            ch_msg = "sms" if not self.ev.get("channel_switching") or self.rng.random() < .5 else "app"
            # stage 1 contact: authority call
            self.mk(t, ch_call, "authority_notice", {"urgency": 3, "has_link": 0, "reply_requested": 0},
                    actor=scammer, target=victim, campaign_id=cid, typology="authority_impersonation")
            t += self._stage_gap(20, 90)
            # stage 2 pressure
            self.mk(t, ch_msg, "urgency_threat", {"urgency": 5, "has_link": 0, "reply_requested": 1},
                    actor=scammer, target=victim, campaign_id=cid, typology="authority_impersonation")
            t += self._stage_gap(10, 60)
            self.mk(t, ch_msg, "penalty_threat", {"urgency": 5, "has_link": 1, "reply_requested": 1},
                    actor=scammer, target=victim, domain=domain, campaign_id=cid,
                    typology="authority_impersonation")
            t += self._stage_gap(15, 120)
            # stage 3 instruction + remote-access indicator
            self.mk(t, "app", "remote_access_prompt", {"urgency": 4, "has_link": 1, "reply_requested": 1},
                    actor=scammer, target=victim, device=vdev, domain=domain, campaign_id=cid,
                    typology="authority_impersonation")
            t += self._stage_gap(10, 45)
            self.mk(t, ch_msg, "payment_instruction", {"urgency": 4, "has_link": 0, "reply_requested": 1},
                    actor=scammer, target=victim, campaign_id=cid, typology="authority_impersonation")
            # stage 4 payment — the harmful moment
            if self.ev.get("delayed_payment"):
                t += self._stage_gap(60 * 6, 60 * 40)   # hours to days later
            else:
                t += self._stage_gap(5, 40)
            amt = self.rng.choice([4900, 9900, 25000, 48000, 99000]) \
                if not self.ev.get("low_volume_single_victim") else self.rng.choice([500, 1200])
            self.mk(t, "upi", "payment_instruction", {"urgency": 4, "has_link": 0, "reply_requested": 0},
                    actor=victim, target=None, device=vdev, payee=payee, amount=amt,
                    campaign_id=cid, typology="authority_impersonation")
            if first_pay is None or t < first_pay:
                first_pay = t
        return first_pay

    def _campaign_refund(self, t0: int, cid: str) -> int:
        nv = 1 if self.ev.get("low_volume_single_victim") else self.rng.randint(
            self.sim["victims_min"], self.sim["victims_max"])
        scammer = self._phone_actor("ref")
        domain = LEGIT_DOMAINS[1] if self.ev.get("reuse_legitimate") else \
            SCAM_DOMAINS[self.rng.randrange(len(SCAM_DOMAINS))]
        payee = LEGIT_VPAS[2] if self.ev.get("reuse_legitimate") else \
            SCAM_VPAS[self.rng.randrange(len(SCAM_VPAS))]
        first_pay = None
        for v in range(nv):
            victim = self._phone_actor(f"v{cid}{v}")
            vdev = hash_id("device", f"rot-{cid}-{v}-{self.rng.random()}", self.seed) \
                if self.ev.get("rotated_identifiers") else hash_id("device", f"ph-{cid}-{v}", self.seed)
            t = t0 + v * self._stage_gap(5, 30)
            self.mk(t, "sms", "refund_offer", {"urgency": 2, "has_link": 1, "reply_requested": 1},
                    actor=scammer, target=victim, domain=domain, campaign_id=cid,
                    typology="refund_kyc_lure")
            t += self._stage_gap(10, 90)
            self.mk(t, "sms", "kyc_update", {"urgency": 3, "has_link": 1, "reply_requested": 1},
                    actor=scammer, target=victim, domain=domain, campaign_id=cid,
                    typology="refund_kyc_lure")
            t += self._stage_gap(5, 30)
            self.mk(t, "app", "link_click", {"urgency": 2, "has_link": 1, "reply_requested": 0},
                    actor=victim, target=None, device=vdev, domain=domain, campaign_id=cid,
                    typology="refund_kyc_lure")
            t += self._stage_gap(60 * 6, 60 * 30) if self.ev.get("delayed_payment") else self._stage_gap(5, 30)
            amt = self.rng.choice([2000, 5000, 11000]) if not self.ev.get("low_volume_single_victim") else 300
            self.mk(t, "upi", "payment_instruction", {"urgency": 3, "has_link": 0, "reply_requested": 0},
                    actor=victim, device=vdev, payee=payee, amount=amt, campaign_id=cid,
                    typology="refund_kyc_lure")
            if first_pay is None or t < first_pay:
                first_pay = t
        return first_pay

    def _campaign_mule(self, t0: int, cid: str) -> int:
        nv = 1 if self.ev.get("low_volume_single_victim") else self.rng.randint(
            max(4, self.sim["victims_min"]), max(6, self.sim["victims_max"]))
        payee = LEGIT_VPAS[1] if self.ev.get("reuse_legitimate") else \
            SCAM_VPAS[self.rng.randrange(len(SCAM_VPAS))]
        recruiter = self._phone_actor("rec")
        first_pay = None
        base_amt = self.rng.choice([500, 1000, 2000])
        for v in range(nv):
            victim = self._phone_actor(f"v{cid}{v}")
            vdev = hash_id("device", f"rot-mule-{v}-{self.rng.random()}", self.seed) \
                if self.ev.get("rotated_identifiers") else hash_id("device", f"ph-{cid}-{v}", self.seed)
            t = t0 + v * self._stage_gap(3, 15)
            if not self.ev.get("rotated_identifiers") or self.rng.random() < .5:
                self.mk(t, "sms", "payment_instruction", {"urgency": 3, "has_link": 0, "reply_requested": 1},
                        actor=recruiter, target=victim, campaign_id=cid, typology="mule_fan_in")
            t += self._stage_gap(2, 20)
            amt = base_amt * (v + 1)          # escalating amounts
            self.mk(t, "upi", "payment_instruction", {"urgency": 3, "has_link": 0, "reply_requested": 0},
                    actor=victim, device=vdev, payee=payee, amount=amt, campaign_id=cid,
                    typology="mule_fan_in")
            if first_pay is None or t < first_pay:
                first_pay = t
        return first_pay

    # ---------- benign lookalikes ----------
    def gen_benign(self, t: int) -> None:
        r = self.rng.random()
        if r < 0.30:  # genuine bank alert w/ legit link
            victim = self._phone_actor("bg")
            self.mk(t, "sms", "benign_alert", {"urgency": 1, "has_link": 1, "reply_requested": 0},
                    actor=POPULAR_ACTOR, target=victim, domain=LEGIT_DOMAINS[0])
        elif r < 0.50:  # merchant collect request
            victim = self._phone_actor("bg")
            self.mk(t, "upi", "general_advisory", {"urgency": 0, "has_link": 0, "reply_requested": 0},
                    actor=HUB_PAYEE, target=victim, payee=HUB_PAYEE,
                    amount=self.rng.choice([150, 300, 640, 999]))
        elif r < 0.62:  # large legitimate payments (rent/tuition)
            victim = self._phone_actor("bg")
            self.mk(t, "upi", "general_advisory", {"urgency": 0, "has_link": 0, "reply_requested": 0},
                    actor=victim, payee=self.rng.choice(LEGIT_VPAS),
                    amount=self.rng.choice([25000, 45000, 80000, 120000]))
        elif r < 0.72:  # burst of payments to popular merchant (hub stress test)
            burst_ts = t
            for _ in range(self.rng.randint(4, 9)):
                victim = self._phone_actor("burst")
                self.mk(burst_ts, "upi", "general_advisory",
                        {"urgency": 0, "has_link": 0, "reply_requested": 0},
                        actor=victim, payee=HUB_PAYEE, amount=self.rng.choice([200, 350, 500]))
                burst_ts += self._stage_gap(1, 4)
        elif r < 0.85:  # genuine support call
            victim = self._phone_actor("bg")
            self.mk(t, "call", "general_advisory", {"urgency": 1, "has_link": 0, "reply_requested": 0},
                    actor=hash_id("actor", "support-desk", self.seed), target=victim)
        else:  # generic app/sms noise
            victim = self._phone_actor("bg")
            self.mk(t, self.rng.choice(["app", "sms"]), "benign_alert",
                    {"urgency": 0, "has_link": 0, "reply_requested": 0},
                    actor=POPULAR_ACTOR, target=victim)

    # ---------- top-level stream ----------
    def build(self) -> tuple[list[Event], dict[str, GroundTruthEvent]]:
        base = self.sim["start_epoch"]
        span_hours = 30
        cursor = {t: base + self.rng.randint(0, span_hours * 60) * 60
                  for t in range(self.sim["campaigns_per_run"])}
        # benign background interleaved by timestamp
        t = base
        end = base + span_hours * 3600
        while t < end:
            self.gen_benign(t)
            t += self._stage_gap(*self.sim["inter_arrival_minutes"])
        # campaigns
        n_scam = 0
        for i, cts in sorted(cursor.items(), key=lambda kv: kv[1]):
            cid = f"camp-{self.seed}-{i}"
            fp = self.gen_campaign(cts, cid, "")
            for gtr in self.ground_truth.values():
                if gtr.campaign_id == cid:
                    gtr.first_payment_ts = fp
        # global sort by timestamp (detector consumes in timestamp order)
        order = sorted(self.events, key=lambda e: (e.timestamp, e.event_id))
        self.events = order
        return self.events, self.ground_truth

    def iter_events(self) -> Iterator[Event]:
        yield from self.events


def stream_for(cfg: dict[str, Any], seed: int, overrides: dict[str, Any] | None = None):
    g = ScenarioGenerator(cfg, seed, overrides)
    events, gt = g.build()
    return events, gt
