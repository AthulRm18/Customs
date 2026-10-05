"""Effect Customs — Coordinates Checkpoint 2, server execution, and enforcement."""
from __future__ import annotations

from typing import Any, Optional
from datetime import datetime

from app.schemas import (
    Verdict,
    RiskLevel,
    Checkpoint,
    ServerStatus,
    EventType,
    ToolCallRequest,
    PipelineResult,
    CP1Result,
    ReconciliationResult,
)
from app.services.call_firewall import call_firewall
from app.services.reconciler import reconciler
from app.services.effect_tracker import effect_tracker
from app.services.audit_service import audit_service
from app.mcp.servers import server_registry
from app.mcp.fake_infra import fake_net, fake_email
from app.core.events import emit


class EffectCustomsService:
    """
    Orchestrates the two-checkpoint CUSTOMS security pipeline:
    1. Checkpoint 1 (Call Firewall)
    2. Controlled MCP server execution within an observation window
    3. Checkpoint 2 (Effect Customs Reconciler)
    4. Runtime Enforcement (Drop request, deliver, pause/quarantine server)
    5. Audit Logging
    """

    def __init__(self):
        self._history: dict[str, PipelineResult] = {}

    def execute_pipeline(self, req: ToolCallRequest) -> PipelineResult:
        call_id = req.call_id
        task = req.task
        tool = req.tool
        arguments = req.arguments

        # ── Step 1: Checkpoint 1 — Call Firewall ────────────────────
        cp1: CP1Result = call_firewall.evaluate(req)

        # If CP1 blocks, halt immediately before server execution
        if cp1.verdict == Verdict.BLOCK:
            server = server_registry.get_for_tool(tool)
            server_id = server.server_id if server else None
            reason = cp1.reasons[0] if cp1.reasons else "Blocked by Call Firewall"
            action = "DROPPED_AT_FIREWALL"

            emit(EventType.REQUEST_DROPPED, call_id,
                 f"Call blocked at Checkpoint 1 (Pre-Execution Gate): {reason}",
                 checkpoint="CALL_FIREWALL", reason=reason)

            audit_service.record(
                call_id=call_id,
                task=task,
                tool=tool,
                checkpoint=Checkpoint.CALL_FIREWALL.value,
                verdict=cp1.verdict.value,
                risk=cp1.risk.value,
                reason=reason,
                action_taken=action,
                detected_data=cp1.detected_data,
                server_id=server_id,
            )

            res = PipelineResult(
                call_id=call_id,
                task=task,
                tool=tool,
                arguments=arguments,
                cp1=cp1,
                cp2=None,
                final_verdict=Verdict.BLOCK,
                final_risk=cp1.risk,
                final_reason=reason,
                checkpoint=Checkpoint.CALL_FIREWALL,
                action_taken=action,
                server_status=server.status if server else None,
            )
            self._history[call_id] = res
            return res

        # ── Step 2: Open Call Window & Execute MCP Server ───────────
        window = effect_tracker.open_window(call_id, tool, arguments)
        server = server_registry.get_for_tool(tool)

        if not server:
            reason = f"Unknown tool provider for '{tool}'"
            action = "DROPPED_UNKNOWN_SERVER"
            res = PipelineResult(
                call_id=call_id,
                task=task,
                tool=tool,
                arguments=arguments,
                cp1=cp1,
                cp2=None,
                final_verdict=Verdict.BLOCK,
                final_risk=RiskLevel.HIGH,
                final_reason=reason,
                checkpoint=Checkpoint.CALL_FIREWALL,
                action_taken=action,
            )
            self._history[call_id] = res
            return res

        if not server.can_execute():
            reason = f"MCP Server '{server.name}' is {server.status.value}. Execution suspended."
            action = "REJECTED_SERVER_PAUSED"
            res = PipelineResult(
                call_id=call_id,
                task=task,
                tool=tool,
                arguments=arguments,
                cp1=cp1,
                cp2=None,
                final_verdict=Verdict.BLOCK,
                final_risk=RiskLevel.HIGH,
                final_reason=reason,
                checkpoint=Checkpoint.CALL_FIREWALL,
                action_taken=action,
                server_status=server.status,
            )
            self._history[call_id] = res
            return res

        # Execute simulated server action
        server.execute(call_id, tool, arguments)

        # ── Step 3: Checkpoint 2 — Effect Reconciler ────────────────
        cp2: ReconciliationResult = reconciler.reconcile(call_id, tool, arguments, window)

        # ── Step 4: Enforcement ────────────────────────────────────
        final_verdict = cp2.verdict
        final_risk = cp2.risk
        final_reason = cp2.reasons[0] if cp2.reasons else "Effects reconciled"

        if final_verdict == Verdict.BLOCK:
            # Drop all outbound network calls and emails from this call window
            for nc in window.network_requests():
                fake_net.block(nc, final_reason)
            for em in window.email_messages():
                fake_email.block(em)

            emit(EventType.REQUEST_DROPPED, call_id,
                 f"Outbound payload dropped: {final_reason}. Attacker received 0 bytes.",
                 checkpoint="EFFECT_CUSTOMS", reason=final_reason)

            # Server quarantine / pause if violation is HIGH or CRITICAL
            if final_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                server.pause(call_id)
                server.blocked_calls += 1
                action_taken = "DROP_AND_PAUSE"
            else:
                action_taken = "DROP_REQUEST"
        else:
            # Safe to deliver intercepted packets
            for nc in window.network_requests():
                fake_net.deliver(nc)
            for em in window.email_messages():
                fake_email.deliver(em)

            emit(EventType.REQUEST_DELIVERED, call_id,
                 "Tool execution approved and outbound effects delivered safely.",
                 checkpoint="EFFECT_CUSTOMS")
            action_taken = "ALLOW_AND_DELIVER"

        # ── Step 5: Persist Audit Record ───────────────────────────
        audit_service.record(
            call_id=call_id,
            task=task,
            tool=tool,
            checkpoint=Checkpoint.EFFECT_CUSTOMS.value,
            verdict=final_verdict.value,
            risk=final_risk.value,
            reason=final_reason,
            action_taken=action_taken,
            declared_atoms=cp2.declared_atoms,
            actual_atoms=cp2.actual_atoms,
            unexplained_atoms=cp2.unexplained_atoms,
            server_id=server.server_id,
        )

        effect_tracker.close_window(call_id)

        res = PipelineResult(
            call_id=call_id,
            task=task,
            tool=tool,
            arguments=arguments,
            cp1=cp1,
            cp2=cp2,
            final_verdict=final_verdict,
            final_risk=final_risk,
            final_reason=final_reason,
            checkpoint=Checkpoint.EFFECT_CUSTOMS,
            action_taken=action_taken,
            server_status=server.status,
        )
        self._history[call_id] = res
        return res

    def get_result(self, call_id: str) -> Optional[PipelineResult]:
        return self._history.get(call_id)

    def all_results(self) -> list[PipelineResult]:
        return list(self._history.values())


effect_customs = EffectCustomsService()
