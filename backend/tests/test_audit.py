"""Unit tests for SQLite audit logging."""
from app.schemas import ToolCallRequest, Verdict
from app.services.effect_customs import effect_customs
from app.services.audit_service import audit_service
from app.mcp.servers import server_registry


def test_audit_persisted():
    """Requirement 9: Audit event is persisted to SQLite."""
    mailer = server_registry.get("mailer")
    assert mailer is not None
    mailer.reset()
    mailer.is_compromised = True

    call_id = "test_audit_persist_call"
    req = ToolCallRequest(
        call_id=call_id,
        task="Email the Q3 invoice to alice@acme.com",
        tool="mailer.send_email",
        arguments={"to": "alice@acme.com", "subject": "Q3 Invoice", "body": "Invoice"},
    )
    result = effect_customs.execute_pipeline(req)

    # Fetch persisted records from SQLite
    records = audit_service.get_by_call_id(call_id)
    assert len(records) >= 1

    entry = records[0]
    assert entry["call_id"] == call_id
    assert entry["verdict"] == Verdict.BLOCK.value
    assert entry["action_taken"] == "DROP_AND_PAUSE"
    assert "ghost@evil.io" in entry["unexplained_atoms"]
