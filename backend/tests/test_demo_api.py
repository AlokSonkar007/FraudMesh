from fastapi.testclient import TestClient

from backend.app.api.main import app


def test_health_endpoint():
    with TestClient(app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_synthetic_demo_endpoint():
    with TestClient(app) as client:
        response = client.post("/demo/run", json={"seed": 777})
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["status"] == "completed"
        assert payload["events_processed"] > 0
        assert payload["synthetic_scam_events"] > 0
        assert "synthetic" in payload["disclaimer"].lower()
        alerts = client.get("/alerts")
        assert alerts.status_code == 200
        assert isinstance(alerts.json()["alerts"], list)
