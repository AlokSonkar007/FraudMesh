"""Pydantic schemas for FraudMesh.

Design rules enforced here:
- Events carry an enumerated `text_category` + numeric `text_features`. No free text.
- Actor/target ids are hashed pseudonyms; phone numbers use a fictional format.
- Ground truth (`campaign_id`, `is_scam`) lives in GroundTruthEvent, a SEPARATE table,
  never returned by the detector-facing Event model.
"""
from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

Channel = Literal["sms", "call", "app", "upi"]
TextCategory = Literal[
    "authority_notice", "urgency_threat", "payment_instruction", "refund_offer",
    "kyc_update", "benign_alert", "penalty_threat", "account_lock_warning",
    "otp_request", "remote_access_prompt", "link_click", "general_advisory",
]
Stage = Literal["contact", "pressure", "instruction", "payment"]
AlertState = Literal["open", "updated", "confirmed", "dismissed", "escalated"]


class Event(BaseModel):
    """Detector-visible event. Contains NO ground-truth fields."""
    event_id: str
    timestamp: int                       # simulated unix seconds
    channel: Channel
    actor_id: Optional[str] = None       # hashed sender (scammer / bank bot / merchant)
    target_id: Optional[str] = None      # hashed receiver/victim/payer
    device_id: Optional[str] = None
    url_domain: Optional[str] = None
    payee_vpa: Optional[str] = None
    amount: float = 0.0
    text_category: TextCategory
    text_features: dict[str, float] = Field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump()


class GroundTruthEvent(BaseModel):
    """Hidden label table row. NEVER handed to detector layers."""
    event_id: str
    campaign_id: Optional[str] = None    # None => benign background
    is_scam: bool
    typology: Optional[str] = None       # authority_impersonation | refund_kyc_lure | mule_fan_in
    first_payment_ts: Optional[int] = None  # campaign-level, stored on each scam row for convenience


class RuleHit(BaseModel):
    rule: str
    detail: str
    weight: float = 1.0


class ScoredEvent(BaseModel):
    event_id: str
    rule_hits: list[RuleHit] = Field(default_factory=list)
    anomaly: float = 0.0                 # layer-2 score in [0,1]
    stage: Optional[Stage] = None


class TimelineItem(BaseModel):
    event_id: str
    timestamp: int
    stage: Optional[Stage] = None
    channel: Channel
    text_category: TextCategory
    summary: str                         # neutral placeholder like "[authority_notice]"
    anomaly: float = 0.0
    rule_hits: list[str] = Field(default_factory=list)


class Explanation(BaseModel):
    signals: list[dict[str, Any]] = Field(default_factory=list)     # (entity_type, signal_type) evidence items
    timeline: list[TimelineItem] = Field(default_factory=list)
    entities: dict[str, list[str]] = Field(default_factory=dict)    # entity_type -> ids
    scores: dict[str, float] = Field(default_factory=dict)          # likelihood/confidence/novelty/impact/priority
    weights_applied: dict[str, Any] = Field(default_factory=dict)


class CampaignGraph(BaseModel):
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]


class Alert(BaseModel):
    alert_id: str
    campaign_key: str                    # internal component signature
    state: AlertState = "open"
    created_ts: int
    updated_ts: int
    event_ids: list[str] = Field(default_factory=list)
    stages_seen: list[str] = Field(default_factory=list)
    typology_guess: Optional[str] = None
    scores: dict[str, float] = Field(default_factory=dict)
    explanation: Explanation = Field(default_factory=Explanation)
    merged_into: Optional[str] = None    # set if this alert was absorbed by an older one
    merges: list[dict[str, Any]] = Field(default_factory=list)
    before_first_payment: Optional[bool] = None   # filled at eval time from ground truth
    feedback: Optional[str] = None                # confirmed | dismissed | escalated
    summary: str = ""                             # template or LLM-generated analyst summary


class AlertUpdate(BaseModel):
    alert: Alert
    kind: Literal["created", "updated", "merged"]


class SimulationStatus(BaseModel):
    running: bool
    paused: bool
    seed: int
    sim_time: int
    events_emitted: int
    alerts_raised: int
    mode: str                            # live | replay


class FeedbackRequest(BaseModel):
    action: Literal["confirm", "dismiss", "escalate"]
    note: Optional[str] = None
