"""SQLAlchemy database setup and audit table."""
from __future__ import annotations

import os
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from datetime import datetime

DB_PATH = os.environ.get("CUSTOMS_DB", "customs.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False}, echo=False)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()


class AuditRecord(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    call_id = Column(String(64), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    task = Column(Text, nullable=False)
    tool = Column(String(128), nullable=False)
    checkpoint = Column(String(32), nullable=False)
    verdict = Column(String(16), nullable=False)
    risk = Column(String(16), nullable=False)
    reason = Column(Text, nullable=False)
    action_taken = Column(String(64), nullable=False)
    detected_data = Column(Text, nullable=True)
    declared_atoms = Column(Text, nullable=True)
    actual_atoms = Column(Text, nullable=True)
    unexplained_atoms = Column(Text, nullable=True)
    server_id = Column(String(64), nullable=True)


def init_db():
    """Create all tables."""
    Base.metadata.create_all(bind=engine)


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
