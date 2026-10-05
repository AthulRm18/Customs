"""Live verification script for CUSTOMS backend."""
import httpx
import json
import asyncio

def run_verification():
    with httpx.Client(base_url="http://127.0.0.1:8000", timeout=10.0) as client:
        print("==================================================")
        print("1. HEALTH CHECK")
        print("==================================================")
        health = client.get("/api/health").json()
        print("Health response:", json.dumps(health, indent=2))
        assert health["status"] == "HEALTHY"

        print("\n==================================================")
        print("2. CLEAN MAIL DEMO (Expected: ALLOW, Delivered to alice)")
        print("==================================================")
        clean = client.post("/api/demo/clean-mail").json()
        print("Verdict:", clean["pipeline_result"]["final_verdict"])
        print("Details:", json.dumps(clean["demonstration"], indent=2))
        assert clean["pipeline_result"]["final_verdict"] == "ALLOW"
        assert clean["demonstration"]["status"] == "DELIVERED"
        assert clean["demonstration"]["recipient_inbox_count"] >= 1

        print("\n==================================================")
        print("3. COMPROMISED MAILER DEMO (Expected: BLOCK, ghost receives 0)")
        print("==================================================")
        attack = client.post("/api/demo/mailer-attack").json()
        print("Verdict:", attack["pipeline_result"]["final_verdict"])
        print("Details:", json.dumps(attack["demonstration"], indent=2))
        assert attack["pipeline_result"]["final_verdict"] == "BLOCK"
        assert attack["demonstration"]["status"] == "BLOCKED_AND_PAUSED"
        assert attack["demonstration"]["attacker_inbox_count"] == 0
        assert attack["demonstration"]["mailer_server_status"] == "PAUSED"

        print("\n==================================================")
        print("4. PAUSED SERVER ATTEMPT (Expected: BLOCK because server is PAUSED)")
        print("==================================================")
        followup = client.post("/api/calls/execute", json={
            "task": "Email invoice to bob@acme.com",
            "tool": "mailer.send_email",
            "arguments": {"to": "bob@acme.com", "subject": "Test", "body": "Test"}
        }).json()
        print("Verdict:", followup["final_verdict"])
        print("Reason:", followup["final_reason"])
        assert followup["final_verdict"] == "BLOCK"
        assert "paused" in followup["final_reason"].lower()

        print("\n==================================================")
        print("5. SERVER RESET (Expected: Mailer restored to ACTIVE)")
        print("==================================================")
        reset_res = client.post("/api/servers/mailer/reset").json()
        print("Reset response:", reset_res["message"])
        assert reset_res["server"]["status"] == "ACTIVE"

        print("\n==================================================")
        print("6. SECRET EXFILTRATION DEMO (Expected: BLOCK at Checkpoint 1)")
        print("==================================================")
        exfil = client.post("/api/demo/secret-exfiltration").json()
        print("Verdict:", exfil["pipeline_result"]["final_verdict"])
        print("Checkpoint:", exfil["pipeline_result"]["checkpoint"])
        print("Details:", json.dumps(exfil["demonstration"], indent=2))
        assert exfil["pipeline_result"]["final_verdict"] == "BLOCK"
        assert exfil["demonstration"]["github_contacted"] is False

        print("\n==================================================")
        print("7. READ-ONLY TOOL LIE DEMO (Expected: BLOCK at Checkpoint 2, CRITICAL)")
        print("==================================================")
        lie = client.post("/api/demo/readonly-tool-lie").json()
        print("Verdict:", lie["pipeline_result"]["final_verdict"])
        print("Risk:", lie["pipeline_result"]["final_risk"])
        print("Details:", json.dumps(lie["demonstration"], indent=2))
        assert lie["pipeline_result"]["final_verdict"] == "BLOCK"
        assert lie["pipeline_result"]["final_risk"] == "CRITICAL"
        assert lie["demonstration"]["attacker_received_bytes"] == 0

        print("\n==================================================")
        print("8. SQLITE AUDIT LOG VERIFICATION")
        print("==================================================")
        audit_entries = client.get("/api/audit").json()
        print(f"Total audit entries in SQLite: {len(audit_entries)}")
        assert len(audit_entries) >= 4
        for a in audit_entries[:4]:
            print(f" - [{a['checkpoint']}] {a['tool']} => {a['verdict']} ({a['risk']}) | {a['action_taken']} | {a['reason']}")

        print("\n==================================================")
        print("9. MCP SERVER FLEET STATUS")
        print("==================================================")
        servers = client.get("/api/servers").json()
        for s in servers:
            print(f" * Server '{s['name']}' ({s['server_id']}): status={s['status']}, blocked_calls={s['blocked_calls']}")

        print("\n==================================================")
        print("ALL LIVE VERIFICATION CHECKS PASSED SUCCESSFULLY!")
        print("==================================================")


if __name__ == "__main__":
    run_verification()
