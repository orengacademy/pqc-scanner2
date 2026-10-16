from __future__ import annotations

from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from pqcscan.util.clock import utcnow


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    host_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    mode: Mapped[str] = mapped_column(String(8))                # root | user
    status: Mapped[str] = mapped_column(String(16), index=True) # running | done | failed
    label: Mapped[str | None] = mapped_column(String(128), nullable=True)
    probe_versions: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    tool_versions: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # Fleet: which enrolled host produced this scan (NULL for a local scan),
    # and a stable id so a re-posted bundle is not stored twice.
    host_id: Mapped[int | None] = mapped_column(ForeignKey("hosts.id"), nullable=True, index=True)
    scan_uuid: Mapped[str | None] = mapped_column(String(36), nullable=True)


class Host(Base):
    """An enrolled agent host (fleet mode). One row per machine id."""
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    machine_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    hostname: Mapped[str] = mapped_column(String(255), default="")
    os: Mapped[str] = mapped_column(String(32), default="")
    labels: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    agent_version: Mapped[str] = mapped_column(String(32), default="")
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    # SHA-256 hex of the per-agent bearer token; the token itself is never stored.
    token_hash: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class ComponentRow(Base):
    __tablename__ = "components"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    purl: Mapped[str] = mapped_column(String(512), index=True)
    type: Mapped[str] = mapped_column(String(32))
    name: Mapped[str] = mapped_column(String(256))
    version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    location: Mapped[str] = mapped_column(Text, default="")
    discovered_by: Mapped[str] = mapped_column(String(64))
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    __table_args__ = (Index("ix_components_scan_type", "scan_id", "type"),)


class FindingRow(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    component_id: Mapped[int | None] = mapped_column(
        ForeignKey("components.id"), nullable=True, index=True
    )
    probe_id: Mapped[str] = mapped_column(String(64))
    algorithm: Mapped[str] = mapped_column(String(64), index=True)
    classification: Mapped[str] = mapped_column(String(16), index=True)
    severity: Mapped[str] = mapped_column(String(8))
    title: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    remediation: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class GraphEdge(Base):
    __tablename__ = "graph_edges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    src_id: Mapped[int] = mapped_column(ForeignKey("components.id"))
    dst_id: Mapped[int] = mapped_column(ForeignKey("components.id"))
    edge_type: Mapped[str] = mapped_column(String(32), index=True)
    attrs: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class FrameworkView(Base):
    __tablename__ = "framework_views"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    framework: Mapped[str] = mapped_column(String(32), index=True)
    clause: Mapped[str] = mapped_column(String(128))
    verdict: Mapped[str] = mapped_column(String(32))
    deadline: Mapped[date | None] = mapped_column(Date, nullable=True)


class Baseline(Base):
    __tablename__ = "baselines"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    label: Mapped[str] = mapped_column(String(128), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
