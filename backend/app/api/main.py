"""Minimal FastAPI wrapper for the FraudMesh synthetic hackathon demo.

This API deliberately uses synthetic events only. It is not a bank or UPI integration.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
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


@app.get("/", tags=["status"], response_class=HTMLResponse)
def root() -> HTMLResponse:
    """Tiny single-page dashboard so judges can run the demo without API tooling."""
    page = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FraudMesh | Scam Campaign Intelligence</title>
<style>
:root{color-scheme:light;--bg:#f4f6f9;--panel:#fff;--line:#dfe5ed;--muted:#657286;--text:#202b3c;--blue:#265fc5;--blue-dark:#1c4da4;--red:#a83236;--amber:#81520b;--green:#23744d;--soft:#f8fafc}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:1160px;margin:auto;padding:28px 26px 44px}.top{display:flex;justify-content:space-between;gap:18px;align-items:center;flex-wrap:wrap;padding-bottom:17px;border-bottom:1px solid var(--line)}.brand{display:flex;align-items:center;gap:11px}.mark{width:37px;height:37px;border-radius:8px;background:#234e91;display:grid;place-items:center;color:#fff;font-size:19px;font-weight:700}.eyebrow{color:#42618b;font-size:10px;font-weight:750;letter-spacing:.105em;text-transform:uppercase}.brand h1{font-size:19px;margin:0;letter-spacing:-.025em;font-weight:700}.pill{border:1px solid #c6ddce;color:var(--green);background:#edf7f0;border-radius:5px;padding:6px 10px;font-size:11px;font-weight:650}
.hero{padding:32px 0 19px;max-width:800px}.hero h2{font-size:clamp(29px,4vw,40px);line-height:1.16;letter-spacing:-.035em;margin:8px 0 10px;font-weight:700}.hero h2 span{color:var(--blue)}.hero p{color:#5a6677;font-size:15px;max-width:700px;margin:0}
.actions{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-top:18px}.btn{border:1px solid var(--blue);border-radius:6px;padding:10px 14px;background:var(--blue);color:#fff;font-weight:650;font-size:13px;cursor:pointer}.btn:hover{background:var(--blue-dark)}.btn:disabled{opacity:.6;cursor:wait}.btn.secondary{background:#fff;color:#33445b;border:1px solid #cbd4e0}.btn.secondary:hover{background:#f2f5f9}.notice{font-size:12px;color:var(--muted)}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:13px;margin:18px 0 24px}.stat,.panel{background:var(--panel);border:1px solid var(--line);border-radius:9px;box-shadow:0 1px 2px rgba(26,39,60,.025)}.stat{padding:16px 17px}.stat .label{color:#68778b;font-size:10px;font-weight:700;letter-spacing:.045em}.stat .num{font-size:27px;font-weight:700;letter-spacing:-.035em;margin-top:5px;color:#18283f}.stat .hint{color:#758196;font-size:11px;margin-top:2px}
.section-head{display:flex;justify-content:space-between;align-items:end;gap:12px;margin:26px 0 13px}.section-head h3{font-size:18px;margin:0;font-weight:700}.section-head p{font-size:12px;color:#68778b;margin:3px 0 0}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:13px}.alert{background:#fff;border:1px solid var(--line);border-radius:9px;padding:17px;min-width:0;box-shadow:0 1px 2px rgba(26,39,60,.025)}.alert-top{display:flex;justify-content:space-between;gap:10px;align-items:start}.aid{font-size:11px;color:#6c788a;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.alert h4{margin:5px 0 7px;font-size:15px;overflow-wrap:anywhere;font-weight:700}.risk{font-size:10px;font-weight:750;border-radius:5px;padding:4px 7px;white-space:nowrap;background:#fff3df;color:var(--amber);border:1px solid #ead7af}.scores{display:flex;gap:7px;flex-wrap:wrap;margin:12px 0}.score{border:1px solid #e4e9f0;border-radius:6px;background:#f7f9fc;padding:7px 9px;color:#647187;font-size:10px;min-width:75px}.score strong{display:block;font-size:15px;color:#263a59;font-weight:700}.summary{font-size:12px;line-height:1.55;color:#46556a;overflow-wrap:anywhere}.meta{margin-top:11px;color:#68778b;font-size:11px;line-height:1.6}.feedback{display:flex;gap:7px;flex-wrap:wrap;margin-top:14px}.feedback button{background:#fff;color:#344761;border:1px solid #ccd5e1;border-radius:5px;padding:7px 10px;cursor:pointer;font-size:11px;font-weight:650}.feedback button:hover{background:#f2f6fb;border-color:#8ea9d0}.feedback button:disabled{opacity:.5;cursor:default}.empty,.loading{grid-column:1/-1;text-align:center;color:#68778b;padding:30px 17px;background:#fff;border:1px dashed #ccd5e1;border-radius:9px}.error{margin:12px 0;color:#8b2b32;background:#fff0f0;border:1px solid #edc9cb;border-radius:6px;padding:11px;display:none}.footer{border-top:1px solid var(--line);margin-top:29px;padding-top:15px;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;color:#6c788a;font-size:11px}.footer a{color:var(--blue);text-decoration:none}.footer a:hover{text-decoration:underline}
@media(max-width:760px){main{padding:22px 16px 35px}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.grid{grid-template-columns:1fr}.hero{padding-top:27px}}@media(max-width:380px){main{padding:18px 12px}.stat{padding:12px}.stat .num{font-size:23px}}
</style>
</head>
<body><main>
<header class="top"><div class="brand"><div class="mark">F</div><div><div class="eyebrow">Scam Flow Intelligence</div><h1>FraudMesh</h1></div></div><div class="pill">● Demo mode · Synthetic data</div></header>
<section class="hero"><div class="eyebrow">Fraud prevention · Campaign review</div><h2>Fraud campaign <span>monitoring</span></h2><p>Review suspicious activity grouped across simulated SMS, calls, app events and UPI-like transactions. The prototype combines rules, anomaly scoring and temporal links to surface related events for analyst review.</p><div class="actions"><button id="run" class="btn" onclick="runDemo()">Run simulation</button><button class="btn secondary" onclick="loadStatus()">Refresh status</button><span id="runNote" class="notice">Ready to run · Seed 7</span></div><div id="error" class="error" role="alert"></div></section>
<section class="stats" aria-label="Simulation summary"><div class="stat"><div class="label">SIMULATED EVENTS</div><div id="events" class="num">—</div><div class="hint">Generated event stream</div></div><div class="stat"><div class="label">SCAM-LABELLED EVENTS</div><div id="scams" class="num">—</div><div class="hint">Synthetic ground truth</div></div><div class="stat"><div class="label">CAMPAIGN ALERTS</div><div id="alertsN" class="num">—</div><div class="hint">Grouped alert candidates</div></div><div class="stat"><div class="label">CURRENT SEED</div><div id="seed" class="num">—</div><div class="hint">Repeatable scenario</div></div></section>
<div class="section-head"><div><h3>Campaign alerts</h3><p>Potentially related events ranked for review. Select an alert to record an analyst decision.</p></div><span id="lastRun" class="notice">No simulation run yet</span></div>
<section id="alerts" class="grid"><div class="empty">Run the simulation to generate synthetic events and view the resulting campaign alerts here.</div></section>
<footer class="footer"><span>FraudMesh · Hackathon prototype · Synthetic data only</span><span><a href="/docs">API docs</a> · <a href="/health">Health check</a></span></footer>
</main>
<script>
const $=id=>document.getElementById(id);
function esc(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function pct(v){return typeof v==="number"?(v*100).toFixed(0)+"%":"—";}
function showError(message){$("error").style.display="block";$("error").textContent=message;}
function clearError(){$("error").style.display="none";$("error").textContent="";}
async function api(path,options={}){const res=await fetch(path,{headers:{"Content-Type":"application/json"},...options});const body=await res.json().catch(()=>({detail:"Server returned an unreadable response"}));if(!res.ok)throw new Error(body.detail||("HTTP "+res.status));return body;}
async function runDemo(){clearError();const b=$("run");b.disabled=true;b.textContent="Running simulation…";$("runNote").textContent="Generating events and scoring campaigns…";$("alerts").innerHTML='<div class="loading">Processing synthetic stream and reconstructing campaigns…</div>';
try{const d=await api("/demo/run",{method:"POST",body:JSON.stringify({seed:7})});$("events").textContent=Number(d.events_processed||0).toLocaleString();$("scams").textContent=Number(d.synthetic_scam_events||0).toLocaleString();$("alertsN").textContent=Number(d.alerts_created||0).toLocaleString();$("seed").textContent=d.seed;$("lastRun").textContent="Simulation completed";$("runNote").textContent="Completed · seed "+d.seed;renderAlerts(d.alerts||[]);}
catch(e){showError("Simulation failed: "+e.message);$("alerts").innerHTML='<div class="empty">The demo could not complete. Check the API docs or try refreshing the service.</div>';$("runNote").textContent="Run failed";}
finally{b.disabled=false;b.textContent="▶ Run synthetic simulation";}}
function renderAlerts(arr){if(!arr.length){$("alerts").innerHTML='<div class="empty">Simulation completed, but no campaign met the alert threshold in this run. Try rerunning or inspect API docs.</div>';return;}
$("alerts").innerHTML=arr.map(a=>{const s=a.scores||{},e=a.explanation||{},entities=e.entities||{},stages=(a.stages_seen||[]).join(" → ")||"Stages pending";const top=Number(s.priority||0)>=.7?"High priority":Number(s.priority||0)>=.45?"Elevated priority":"Review";const ids=(a.event_ids||[]).length;const signal=(e.signals||[]).slice(0,4).map(x=>esc(x.signal_type||x.rule||"signal")).join(" · ");return '<article class="alert"><div class="alert-top"><div><div class="aid">'+esc(a.alert_id)+'</div><h4>Candidate scam campaign</h4></div><span class="risk">'+top+'</span></div><div class="scores"><div class="score">PRIORITY<strong>'+pct(s.priority)+'</strong></div><div class="score">CONFIDENCE<strong>'+pct(s.confidence)+'</strong></div><div class="score">LIKELIHOOD<strong>'+pct(s.likelihood)+'</strong></div><div class="score">NOVELTY<strong>'+pct(s.novelty)+'</strong></div></div><div class="summary">'+esc(a.summary||"Linked suspicious events grouped for analyst review.")+'</div><div class="meta">'+ids+' linked events · '+esc(stages)+'<br>Entities: '+Object.values(entities).reduce((n,x)=>n+(Array.isArray(x)?x.length:0),0)+' · Signals: '+(signal||"No rule labels available")+'</div><div class="feedback"><button onclick="feedback(\''+esc(a.alert_id)+'\',\'confirm\')">Confirm</button><button onclick="feedback(\''+esc(a.alert_id)+'\',\'dismiss\')">Dismiss</button><button onclick="feedback(\''+esc(a.alert_id)+'\',\'escalate\')">Escalate</button></div></article>';}).join("");}
async function feedback(id,action){clearError();try{const r=await api("/alerts/"+encodeURIComponent(id)+"/feedback",{method:"POST",body:JSON.stringify({action})});$("runNote").textContent="Analyst action saved in this demo: "+action;const cards=[...document.querySelectorAll(".alert")];const card=cards.find(el=>el.querySelector(".aid")?.textContent===id);if(card){let tag=card.querySelector(".meta");if(tag)tag.insertAdjacentHTML("beforeend",'<br><strong>Analyst action: '+esc(action.toUpperCase())+'</strong>');card.querySelectorAll("button").forEach(b=>b.disabled=true);}}
catch(e){showError("Could not save analyst action: "+e.message);}}
async function loadStatus(){clearError();try{const d=await api("/demo/status");if(d.has_run){$("events").textContent=Number(d.events_processed||0).toLocaleString();$("alertsN").textContent=Number(d.active_alerts||0).toLocaleString();$("seed").textContent=d.seed;$("runNote").textContent="Service active · seed "+d.seed;$("lastRun").textContent="Existing in-memory run";const a=await api("/alerts");renderAlerts(a.alerts||[]);}else{$("runNote").textContent="Service ready · run a simulation";$("lastRun").textContent="No simulation run yet";}}
catch(e){showError("Could not contact API: "+e.message);}}
loadStatus();
</script></body></html>"""
    return HTMLResponse(content=page)


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
