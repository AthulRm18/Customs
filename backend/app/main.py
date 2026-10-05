"""Main FastAPI application entry point for CUSTOMS."""
from __future__ import annotations

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.db.database import init_db
from app.api.calls import router as calls_router
from app.api.events import router as events_router
from app.api.audit import router as audit_router
from app.api.servers import router as servers_router
from app.api.policies import router as policies_router
from app.api.demo import router as demo_router
from app.mcp.servers import server_registry
from app.services.policy_engine import policy_engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite database schema
    init_db()
    yield


app = FastAPI(
    title="CUSTOMS — Runtime Security Enforcement for MCP Tools",
    description="Dual-checkpoint security layer: Checkpoint 1 (Call Firewall) + Checkpoint 2 (Effect Customs Reconciler)",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware for React / Vite frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount all API routers
app.include_router(calls_router)
app.include_router(events_router)
app.include_router(audit_router)
app.include_router(servers_router)
app.include_router(policies_router)
app.include_router(demo_router)


@app.get("/")
def root():
    return {
        "service": "CUSTOMS",
        "description": "MCP Security Enforcement Layer",
        "checkpoints": [
            "Checkpoint 1: Call Firewall (Pre-execution validation)",
            "Checkpoint 2: Effect Customs Reconciler (Observed vs declared effects)",
        ],
        "endpoints": {
            "evaluate": "POST /api/calls/evaluate",
            "execute": "POST /api/calls/execute",
            "events_stream": "GET /api/events/stream",
            "audit_log": "GET /api/audit",
            "servers": "GET /api/servers",
            "policies": "GET /api/policies",
            "demo_mailer_attack": "POST /api/demo/mailer-attack",
            "demo_clean_mail": "POST /api/demo/clean-mail",
            "demo_secret_exfil": "POST /api/demo/secret-exfiltration",
            "demo_readonly_lie": "POST /api/demo/readonly-tool-lie",
        },
        "docs": "/docs",
    }


@app.get("/api/health")
def health_check():
    return {
        "status": "HEALTHY",
        "active_servers": len([s for s in server_registry.all() if s.can_execute()]),
        "total_servers": len(server_registry.all()),
        "active_policies": len([p for p in policy_engine.policies if p.enabled]),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
