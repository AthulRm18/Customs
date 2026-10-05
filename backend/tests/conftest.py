"""Pytest fixtures and configuration."""
import os
import pytest
from app.db.database import init_db, Base, engine
from app.mcp.fake_infra import reset_all
from app.mcp.servers import server_registry


@pytest.fixture(autouse=True)
def setup_test_env():
    # Initialize DB schema
    init_db()
    # Reset fake infrastructure
    reset_all()
    # Reset server statuses and flags
    server_registry.reset_all()
    yield
