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
:root{color-scheme:dark;--bg:#0b1020;--panel:#121a2d;--line:#27344e;--muted:#9aa9c3;--text:#edf3ff;--cyan:#5be1e6;--red:#ff777e;--amber:#ffc66d;--green:#83e3ad}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 85% 0%,#123046 0,transparent 36%),var(--bg);color:var(--text);font:15px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1120px;margin:auto;padding:34px 22px 50px}.top{display:flex;justify-content:space-between;gap:18px;align-items:center;flex-wrap:wrap}.brand{display:flex;align-items:center;gap:12px}.mark{width:43px;height:43px;border-radius:13px;background:linear-gradient(145deg,#5be1e6,#3f83cf);display:grid;place-items:center;color:#071323;font-size:22px;font-weight:900}.eyebrow{color:var(--cyan);font-size:11px;font-weight:800;letter-spacing:.19em;text-transform:uppercase}.brand h1{font-size:20px;margin:0;letter-spacing:-.03em}.pill{border:1px solid #32645f;color:var(--green);background:#102d2a;border-radius:30px;padding:7px 12px;font-size:12px;font-weight:700}
.hero{padding:46px 0 27px;max-width:760px}.hero h2{font-size:clamp(32px,5vw,51px);line-height:1.08;letter-spacing:-.045em;margin:13px 0}.hero h2 span{color:var(--cyan)}.hero p{color:var(--muted);font-size:16px;max-width:690px}
.actions{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-top:23px}.btn{border:0;border-radius:10px;padding:12px 17px;background:var(--cyan);color:#071323;font-weight:800;font-size:14px;cursor:pointer}.btn:disabled{opacity:.55;cursor:wait}.btn.secondary{background:#26334a;color:var(--text);border:1px solid #3b4b66}.notice{font-size:12px;color:var(--muted)}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:24px 0}.stat,.panel{background:linear-gradient(135deg,rgba(21,32,54,.96),rgba(15,23,40,.96));border:1px solid var(--line);border-radius:15px}.stat{padding:18px}.stat .label{color:var(--muted);font-size:12px}.stat .num{font-size:27px;font-weight:800;letter-spacing:-.04em;margin-top:4px}.stat .hint{color:#8b9ab4;font-size:11px;margin-top:3px}
.section-head{display:flex;justify-content:space-between;align-items:end;gap:12px;margin:29px 0 14px}.section-head h3{font-size:19px;margin:0}.section-head p{font-size:12px;color:var(--muted);margin:3px 0 0}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:13px}.alert{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px;min-width:0}.alert-top{display:flex;justify-content:space-between;gap:10px;align-items:start}.aid{font-size:11px;color:var(--muted);font-family:ui-monospace,monospace}.alert h4{margin:5px 0 8px;font-size:16px;overflow-wrap:anywhere}.risk{font-size:11px;font-weight:800;border-radius:7px;padding:5px 8px;white-space:nowrap;background:#3a202b;color:#ffb0b4;border:1px solid #703943}.scores{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}.score{border-radius:8px;background:#0c1425;padding:7px 9px;color:#b7c4d9;font-size:11px}.score strong{display:block;font-size:15px;color:var(--text)}.summary{font-size:13px;color:#bbc7d9;overflow-wrap:anywhere}.meta{margin-top:12px;color:var(--muted);font-size:11px}.feedback{display:flex;gap:8px;flex-wrap:wrap;margin-top:16px}.feedback button{background:#202d43;color:#dbe7fa;border:1px solid #394b68;border-radius:8px;padding:8px 10px;cursor:pointer;font-size:12px;font-weight:700}.feedback button:hover{border-color:var(--cyan)}.empty,.loading{grid-column:1/-1;text-align:center;color:var(--muted);padding:35px 18px;border:1px dashed #33415b;border-radius:14px}.error{margin:12px 0;color:#ffc0c2;background:#351d29;border:1px solid #713644;border-radius:10px;padding:12px;display:none}.footer{border-top:1px solid var(--line);margin-top:34px;padding-top:17px;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;color:var(--muted);font-size:11px}.footer a{color:var(--cyan);text-decoration:none}
@media(max-width:760px){.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.grid{grid-template-columns:1fr}.hero{padding-top:34px}}@media(max-width:380px){main{padding:24px 14px}.stat{padding:13px}.stat .num{font-size:23px}}
</style>
</head>
<body><main>
<header class="top"><div class="brand"><div class="mark">F</div><div><div class="eyebrow">Scam Flow Intelligence</div><h1>FraudMesh</h1></div></div><div class="pill">● Synthetic Demo Environment</div></header>
<section class="hero"><div class="eyebrow">Detect the network, not just the transaction</div><h2>Spot scam campaigns <span>before the pattern spreads.</span></h2><p>FraudMesh correlates synthetic SMS, call, app and UPI-like events into campaign candidates using rules, anomaly scoring and temporal entity graphs.</p><div class="actions"><button id="run" class="btn" onclick="runDemo()">▶ Run synthetic simulation</button><button class="btn secondary" onclick="loadStatus()">Refresh status</button><span id="runNote" class="notice">Ready to run · Seed 7</span></div><div id="error" class="error" role="alert"></div></section>
<section class="stats" aria-label="Simulation summary"><div class="stat"><div class="label">SIMULATED EVENTS</div><div id="events" class="num">—</div><div class="hint">Generated event stream</div></div><div class="stat"><div class="label">SCAM-LABELLED EVENTS</div><div id="scams" class="num">—</div><div class="hint">Synthetic ground truth</div></div><div class="stat"><div class="label">CAMPAIGN ALERTS</div><div id="alertsN" class="num">—</div><div class="hint">Grouped alert candidates</div></div><div class="stat"><div class="label">CURRENT SEED</div><div id="seed" class="num">—</div><div class="hint">Repeatable scenario</div></div></section>
<div class="section-head"><div><h3>Campaign intelligence</h3><p>Risk-ranked clusters with linked event evidence and analyst actions.</p></div><span id="lastRun" class="notice">No simulation run yet</span></div>
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
