"""Minimal FastAPI wrapper for the FraudMesh synthetic hackathon demo.

This API deliberately uses synthetic events only. It is not a bank or UPI integration.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from backend.app.config import load_config
from backend.app.detector.anomaly import AnomalyScorer
from backend.app.detector.pipeline import DetectionPipeline
from backend.app.generator.synth import stream_for

app = FastAPI(
    title="FraudMesh Demo API",
    description=(
        "Synthetic scam-campaign detection prototype. Outputs are for demonstration "
        "and do not represent validated real-world fraud detection performance."
    ),
    version="0.1.0",
)

_state: dict = {
    "pipeline": None,
    "seed": None,
    "events_processed": 0,
    "alerts_created": 0,
}


class DemoRequest(BaseModel):
    seed: int = Field(default=7, ge=1, le=2_147_483_647)


class FeedbackBody(BaseModel):
    action: Literal["confirm", "dismiss", "escalate"]


@lru_cache(maxsize=1)
def _trained_anomaly_model() -> AnomalyScorer:
    """Fit the anomaly layer on a separate synthetic seed before demo replay."""
    cfg = load_config()
    training_events, truth = stream_for(cfg, seed=101)
    benign = [event for event in training_events if not truth[event.event_id].is_scam]
    model = AnomalyScorer(cfg)
    model.fit(benign)
    return model


def _require_pipeline() -> DetectionPipeline:
    pipe = _state["pipeline"]
    if pipe is None:
        raise HTTPException(
            status_code=409,
            detail="No demo has been run yet. Call POST /demo/run first.",
        )
    return pipe


@app.get("/", tags=["status"])
def root() -> dict:
    return {
        "name": "FraudMesh",
        "mode": "synthetic-demo",
        "docs": "/docs",
        "health": "/health",
        "run_demo": "POST /demo/run",
        "warning": "Synthetic prototype only; not connected to any bank or UPI network.",
    }


@app.get("/health", tags=["status"])
def health() -> dict:
    return {"status": "ok", "mode": "synthetic-demo", "version": app.version}


@app.post("/demo/run", tags=["demo"])
def run_demo(request: DemoRequest) -> dict:
    """Generate a deterministic synthetic event stream and run the detection pipeline."""
    cfg = load_config()
    try:
        events, truth = stream_for(cfg, seed=request.seed)
        pipe = DetectionPipeline(cfg, anomaly_model=_trained_anomaly_model())
        for event in events:
            pipe.process(event)
    except Exception as exc:
        # Keep the response useful without exposing internal paths or secrets.
        raise HTTPException(status_code=500, detail=f"Demo run failed: {type(exc).__name__}") from exc

    alerts = pipe.active_alerts()
    _state.update({
        "pipeline": pipe,
        "seed": request.seed,
        "events_processed": len(events),
        "alerts_created": len(alerts),
    })

    return {
        "status": "completed",
        "seed": request.seed,
        "events_processed": len(events),
        "synthetic_scam_events": sum(1 for item in truth.values() if item.is_scam),
        "alerts_created": len(alerts),
        "alerts": [alert.model_dump(mode="json") for alert in alerts],
        "disclaimer": "All events and results are synthetic; these are not real-world performance metrics.",
    }


@app.get("/demo/status", tags=["demo"])
def demo_status() -> dict:
    pipe = _state["pipeline"]
    return {
        "has_run": pipe is not None,
        "seed": _state["seed"],
        "events_processed": _state["events_processed"],
        "active_alerts": len(pipe.active_alerts()) if pipe is not None else 0,
        "mode": "synthetic-demo",
    }


@app.get("/alerts", tags=["alerts"])
def list_alerts() -> dict:
    pipe = _require_pipeline()
    alerts = pipe.active_alerts()
    return {
        "count": len(alerts),
        "alerts": [alert.model_dump(mode="json") for alert in alerts],
        "mode": "synthetic-demo",
    }


@app.post("/alerts/{alert_id}/feedback", tags=["alerts"])
def alert_feedback(alert_id: str, body: FeedbackBody) -> dict:
    pipe = _require_pipeline()
    if alert_id not in pipe.manager.alerts:
        raise HTTPException(status_code=404, detail="Alert not found")

    if body.action == "confirm":
        result = pipe.confirm_alert(alert_id)
    elif body.action == "dismiss":
        result = pipe.dismiss_alert(alert_id)
    else:
        result = pipe.escalate_alert(alert_id)

    if not result.get("ok"):
        raise HTTPException(status_code=404, detail="Alert not found")

    return {
        "alert_id": alert_id,
        "action": body.action,
        "result": result,
        "warning": "Feedback is held in memory for this demo process; it is not durable storage.",
    }
