"""API endpoints for tool call evaluation and execution."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.schemas import ToolCallRequest, CP1Result, PipelineResult
from app.services.call_firewall import call_firewall
from app.services.effect_customs import effect_customs

router = APIRouter(prefix="/api/calls", tags=["Calls"])


@router.post("/evaluate", response_model=CP1Result)
def evaluate_call(req: ToolCallRequest):
    """Checkpoint 1 only: evaluate a tool call before running it."""
    return call_firewall.evaluate(req)


@router.post("/execute", response_model=PipelineResult)
def execute_call(req: ToolCallRequest):
    """Full security pipeline: CP1 → MCP Server execution → CP2 Reconciler → Enforcement."""
    return effect_customs.execute_pipeline(req)


@router.get("", response_model=list[PipelineResult])
def list_calls():
    """Retrieve full history of evaluated and executed tool calls."""
    return effect_customs.all_results()


@router.get("/{call_id}", response_model=PipelineResult)
def get_call(call_id: str):
    """Get security inspection details for a specific tool call."""
    res = effect_customs.get_result(call_id)
    if not res:
        raise HTTPException(status_code=404, detail=f"Call '{call_id}' not found")
    return res
