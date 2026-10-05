"""Pydantic schemas for the CUSTOMS API."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field
import uuid


# ── Enums ────────────────────────────────────────────────────

class Verdict(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class Checkpoint(str, Enum):
    CALL_FIREWALL = "CALL_FIREWALL"
    EFFECT_CUSTOMS = "EFFECT_CUSTOMS"

class ServerStatus(str, Enum):
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    QUARANTINED = "QUARANTINED"

class EventType(str, Enum):
    CALL_RECEIVED = "CALL_RECEIVED"
    CP1_EVALUATING = "CP1_EVALUATING"
    CP1_RESULT = "CP1_RESULT"
    MCP_EXECUTING = "MCP_EXECUTING"
    FILE_READ = "FILE_READ"
    NETWORK_REQUEST = "NETWORK_REQUEST"
    EMAIL_OUTBOUND = "EMAIL_OUTBOUND"
    EFFECT_DETECTED = "EFFECT_DETECTED"
    CP2_EVALUATING = "CP2_EVALUATING"
    CP2_RESULT = "CP2_RESULT"
    RECONCILIATION = "RECONCILIATION"
    SERVER_PAUSED = "SERVER_PAUSED"
    SERVER_QUARANTINED = "SERVER_QUARANTINED"
    REQUEST_DROPPED = "REQUEST_DROPPED"
    REQUEST_DELIVERED = "REQUEST_DELIVERED"
    AUDIT_CREATED = "AUDIT_CREATED"


# ── Tool Call ────────────────────────────────────────────────

class ToolCallRequest(BaseModel):
    task: str = Field(..., description="User's original task description")
    tool: str = Field(..., description="Tool name e.g. 'mailer.send_email'")
    arguments: dict[str, Any] = Field(default_factory=dict)
    call_id: str = Field(default_factory=lambda: f"call_{uuid.uuid4().hex[:12]}")


# ── Checkpoint 1 Response ────────────────────────────────────

class CP1Result(BaseModel):
    call_id: str
    verdict: Verdict
    risk: RiskLevel
    reasons: list[str] = Field(default_factory=list)
    detected_data: list[dict[str, str]] = Field(default_factory=list)
    destination: Optional[str] = None
    destination_label: Optional[str] = None
    task_relevance: Optional[str] = None


# ── Effect Tracking ──────────────────────────────────────────

class FileAccessRecord(BaseModel):
    call_id: str
    path: str
    operation: str = "READ"
    content_preview: Optional[str] = None
    size: int = 0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    is_secret_file: bool = False

class NetworkRequestRecord(BaseModel):
    call_id: str
    method: str
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    delivered: bool = False
    blocked: bool = False
    block_reason: Optional[str] = None


# ── Checkpoint 2 / Reconciliation ────────────────────────────

class ReconciliationResult(BaseModel):
    call_id: str
    verdict: Verdict
    risk: RiskLevel
    declared_atoms: list[str] = Field(default_factory=list)
    actual_atoms: list[str] = Field(default_factory=list)
    unexplained_atoms: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    action_taken: str = ""
    file_reads: list[dict[str, Any]] = Field(default_factory=list)
    network_requests: list[dict[str, Any]] = Field(default_factory=list)
    exfiltration_detected: bool = False


# ── Full Pipeline Result ─────────────────────────────────────

class PipelineResult(BaseModel):
    call_id: str
    task: str
    tool: str
    arguments: dict[str, Any]
    cp1: CP1Result
    cp2: Optional[ReconciliationResult] = None
    final_verdict: Verdict
    final_risk: RiskLevel
    final_reason: str
    checkpoint: Checkpoint
    action_taken: str
    server_status: Optional[ServerStatus] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ── SSE Event ────────────────────────────────────────────────

class SecurityEvent(BaseModel):
    event_type: EventType
    call_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    data: dict[str, Any] = Field(default_factory=dict)
    message: str = ""


# ── Server Info ──────────────────────────────────────────────

class ServerInfo(BaseModel):
    server_id: str
    name: str
    status: ServerStatus
    tools: list[str]
    total_calls: int = 0
    blocked_calls: int = 0
    is_compromised: bool = False
    compromise_type: Optional[str] = None


# ── Audit Entry ──────────────────────────────────────────────

class AuditEntry(BaseModel):
    id: Optional[int] = None
    call_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    task: str
    tool: str
    checkpoint: str
    verdict: str
    risk: str
    reason: str
    action_taken: str
    detected_data: Optional[str] = None
    declared_atoms: Optional[str] = None
    actual_atoms: Optional[str] = None
    unexplained_atoms: Optional[str] = None
    server_id: Optional[str] = None


# ── Policy ───────────────────────────────────────────────────

class Policy(BaseModel):
    id: str
    name: str
    description: str
    data_label: Optional[str] = None
    destination: Optional[str] = None
    action: Verdict
    checkpoint: int = 1  # 1 or 2
    enabled: bool = True
