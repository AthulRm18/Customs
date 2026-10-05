"""Tests for demo scenarios and FastAPI API endpoints."""
from fastapi.testclient import TestClient
from app.main import app
from app.schemas import Verdict, ServerStatus

client = TestClient(app)


def test_api_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert data["total_servers"] >= 4


def test_demo_clean_mail():
    response = client.post("/api/demo/clean-mail")
    assert response.status_code == 200
    data = response.json()
    assert data["demonstration"]["status"] == "DELIVERED"
    assert data["pipeline_result"]["final_verdict"] == "ALLOW"
    assert data["demonstration"]["recipient_inbox_count"] == 1


def test_demo_mailer_attack():
    response = client.post("/api/demo/mailer-attack")
    assert response.status_code == 200
    data = response.json()
    assert data["demonstration"]["status"] == "BLOCKED_AND_PAUSED"
    assert data["demonstration"]["undeclared_recipient"] == "ghost@evil.io"
    assert data["demonstration"]["attacker_inbox_count"] == 0
    assert data["demonstration"]["mailer_server_status"] == "PAUSED"
    assert data["pipeline_result"]["final_verdict"] == "BLOCK"


def test_demo_secret_exfiltration():
    response = client.post("/api/demo/secret-exfiltration")
    assert response.status_code == 200
    data = response.json()
    assert data["demonstration"]["status"] == "BLOCKED_AT_CHECKPOINT_1"
    assert data["demonstration"]["github_contacted"] is False
    assert data["pipeline_result"]["final_verdict"] == "BLOCK"


def test_demo_readonly_tool_lie():
    response = client.post("/api/demo/readonly-tool-lie")
    assert response.status_code == 200
    data = response.json()
    assert data["demonstration"]["status"] == "BLOCKED_AT_CHECKPOINT_2"
    assert data["demonstration"]["exfiltration_detected"] is True
    assert data["demonstration"]["attacker_received_bytes"] == 0
    assert data["demonstration"]["browser_server_status"] == "PAUSED"


def test_servers_pause_and_reset_api():
    # Pause server
    res_pause = client.post("/api/servers/filesystem/pause")
    assert res_pause.status_code == 200
    assert res_pause.json()["server"]["status"] == "PAUSED"

    # Reset server
    res_reset = client.post("/api/servers/filesystem/reset")
    assert res_reset.status_code == 200
    assert res_reset.json()["server"]["status"] == "ACTIVE"


def test_policies_api():
    response = client.get("/api/policies")
    assert response.status_code == 200
    policies = response.json()
    assert len(policies) >= 7
    assert any(p["name"] == "no-secret-to-public" for p in policies)


def test_audit_api():
    # Trigger a clean mail to have audit records
    client.post("/api/demo/clean-mail")
    response = client.get("/api/audit")
    assert response.status_code == 200
    records = response.json()
    assert len(records) >= 1
