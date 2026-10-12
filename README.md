# FraudMesh — synthetic scam-campaign demo

FraudMesh is a hackathon prototype for detecting **linked scam campaigns**, rather than treating each event as an isolated transaction. It combines:

- deterministic rules and synthetic reputation lists;
- an Isolation Forest anomaly score;
- a time-aware entity graph;
- campaign scoring, alert grouping, and analyst feedback actions.

> **Demo limitation:** This project generates synthetic data. It is not connected to a bank, UPI, telecom provider, or live fraud feed. Demo results are not evidence of real-world detection performance, and the prototype must not be used to make production financial decisions.

## Fast local run

Requires Python 3.11+.

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
# source .venv/bin/activate

python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn backend.app.api.main:app --reload
```

Open `http://127.0.0.1:8000/docs` for the interactive API demo. `GET /health` checks that the service is running.

## Demo flow

1. Call `POST /demo/run` with `{"seed": 7}`.
2. Review the synthetic event count and the campaign alerts returned.
3. Call `GET /alerts` or `GET /demo/status`.
4. Send analyst feedback with `POST /alerts/{alert_id}/feedback` and JSON such as `{"action":"escalate"}`. Supported actions: `confirm`, `dismiss`, `escalate`.
5. Run again with a different seed to generate another deterministic synthetic stream.

The alert feedback state is in memory and resets when the service restarts. Run the demo again after each restart.

## Deploy a demo on Render

The included `render.yaml` describes a minimal Python web service.

1. In Render, create a **Blueprint** from this GitHub repository and select branch `fraudmesh-white-theme-5bc57`.
2. Let it build from `requirements.txt` and start with the configured Uvicorn command.
3. Once deployed, open `https://YOUR-SERVICE.onrender.com/health`, then `/docs` to run the demo.
4. Call `POST /demo/run` first, then inspect alerts.

A free instance may sleep between requests, so the first request can be slow. The API is a minimal demo wrapper, not a hardened public service. Keep it on synthetic data only and do not submit real personal, account, or payment details.

## Evaluation code

The offline evaluation harness is under `backend/app/eval/`. It runs multiple synthetic seeds and can take substantially longer than the API demo. Its metrics should be described as synthetic-simulation results, not bank-validated results.

## Repository map

- `backend/app/api/main.py` — minimal FastAPI demo endpoints
- `backend/app/detector/` — rules, anomaly scores, graph construction, campaign scoring and alert lifecycle
- `backend/app/generator/synth.py` — seeded synthetic event and ground-truth generation
- `backend/app/eval/` — baseline, ablation, evasion and campaign metrics
- `backend/app/store/db.py` — lightweight SQLite and in-memory storage interfaces
- `configs/default.yaml` — editable simulation and detector configuration
