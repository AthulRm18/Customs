"""End-to-end pipeline and Checkpoint 2 enforcement tests."""
from app.schemas import ToolCallRequest, Verdict, RiskLevel, ServerStatus
from app.services.effect_customs import effect_customs
from app.mcp.servers import server_registry
from app.mcp.fake_infra import fake_email, fake_net


def test_legitimate_mail():
    """Requirement 1: Legitimate mail → ALLOW, email delivered to declared recipient."""
    mailer = server_registry.get("mailer")
    assert mailer is not None
    mailer.reset()
    mailer.is_compromised = False

    req = ToolCallRequest(
        call_id="call_legit_mail",
        task="Email the Q3 invoice to alice@acme.com",
        tool="mailer.send_email",
        arguments={
            "to": "alice@acme.com",
            "subject": "Q3 Invoice",
            "body": "Invoice attached",
        },
    )

    result = effect_customs.execute_pipeline(req)

    assert result.final_verdict == Verdict.ALLOW
    assert result.final_risk == RiskLevel.LOW
    assert result.action_taken == "ALLOW_AND_DELIVER"

    # Verify that alice received the email
    alice_inbox = fake_email.get_inbox("alice@acme.com")
    assert len(alice_inbox) == 1
    assert alice_inbox[0].delivered is True
    assert alice_inbox[0].subject == "Q3 Invoice"


def test_undeclared_bcc():
    """Requirement 2: Undeclared BCC → BLOCK, ghost@evil.io receives nothing."""
    mailer = server_registry.get("mailer")
    assert mailer is not None
    mailer.reset()
    mailer.is_compromised = True

    req = ToolCallRequest(
        call_id="call_bcc_attack",
        task="Email the Q3 invoice to alice@acme.com",
        tool="mailer.send_email",
        arguments={
            "to": "alice@acme.com",
            "subject": "Q3 Invoice",
            "body": "Invoice attached",
        },
    )

    result = effect_customs.execute_pipeline(req)

    assert result.final_verdict == Verdict.BLOCK
    assert result.final_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert result.action_taken == "DROP_AND_PAUSE"

    # Verify that ghost@evil.io received NOTHING
    attacker_inbox = fake_email.get_inbox("ghost@evil.io")
    assert len(attacker_inbox) == 0

    # Verify outbound email is flagged blocked
    outbox = fake_email.get_outbox("call_bcc_attack")
    assert len(outbox) == 1
    assert outbox[0].blocked is True
    assert outbox[0].delivered is False


def test_server_paused_after_violation():
    """Requirement 7: Server becomes PAUSED after critical/high violation."""
    mailer = server_registry.get("mailer")
    assert mailer is not None
    mailer.reset()
    mailer.is_compromised = True

    req = ToolCallRequest(
        call_id="call_pause_check",
        task="Email the Q3 invoice to alice@acme.com",
        tool="mailer.send_email",
        arguments={"to": "alice@acme.com", "subject": "Q3 Invoice", "body": "Invoice"},
    )
    result = effect_customs.execute_pipeline(req)

    assert result.final_verdict == Verdict.BLOCK
    assert mailer.status == ServerStatus.PAUSED


def test_paused_server_cannot_execute():
    """Requirement 8: Paused server cannot execute further requests."""
    mailer = server_registry.get("mailer")
    assert mailer is not None
    mailer.pause()

    req = ToolCallRequest(
        call_id="call_followup",
        task="Email the Q3 invoice to bob@acme.com",
        tool="mailer.send_email",
        arguments={"to": "bob@acme.com", "subject": "Another Invoice", "body": "Data"},
    )
    result = effect_customs.execute_pipeline(req)

    assert result.final_verdict == Verdict.BLOCK
    assert "paused" in result.final_reason.lower()
    assert result.action_taken in ("DROPPED_AT_FIREWALL", "REJECTED_SERVER_PAUSED")
