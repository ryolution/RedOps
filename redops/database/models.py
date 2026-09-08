"""Assessment-scoped relational observations and immutable report snapshots."""

from __future__ import annotations

from typing import Any

from sqlalchemy import JSON, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class SchemaVersion(Base):
    __tablename__ = "schema_version"
    id: Mapped[int] = mapped_column(primary_key=True)
    version: Mapped[int]


class Assessment(Base):
    __tablename__ = "assessments"
    __table_args__ = (Index("ix_assessments_engagement_history", "engagement", "created_at", "id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[str] = mapped_column(String(40), index=True)
    engagement: Mapped[str] = mapped_column(String(200), index=True)
    operator: Mapped[str] = mapped_column(String(200))
    document: Mapped[dict[str, Any]] = mapped_column(JSON)
    hosts: Mapped[list[HostRecord]] = relationship(cascade="all, delete-orphan")


class HostRecord(Base):
    __tablename__ = "hosts"
    __table_args__ = (UniqueConstraint("assessment_id", "ip"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id"), index=True)
    ip: Mapped[str] = mapped_column(String(45))
    hostname: Mapped[str] = mapped_column(Text)
    os: Mapped[str] = mapped_column(Text)
    services: Mapped[list[ServiceRecord]] = relationship(cascade="all, delete-orphan")


class ServiceRecord(Base):
    __tablename__ = "services"
    __table_args__ = (UniqueConstraint("host_id", "port", "protocol"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"), index=True)
    port: Mapped[int]
    protocol: Mapped[str] = mapped_column(String(4))
    name: Mapped[str] = mapped_column(Text)
    product: Mapped[str] = mapped_column(Text)
    version: Mapped[str] = mapped_column(Text)
    cpes: Mapped[list[str]] = mapped_column(JSON)
    vulnerabilities: Mapped[list[VulnerabilityRecord]] = relationship(cascade="all, delete-orphan")


class VulnerabilityRecord(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (UniqueConstraint("service_id", "vulnerability_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), index=True)
    vulnerability_id: Mapped[str] = mapped_column(String(100))
    cvss: Mapped[float | None]
    description: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(40))


class ActionRecord(Base):
    __tablename__ = "actions"
    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id"), index=True)
    timestamp: Mapped[str] = mapped_column(String(40))
    operator: Mapped[str] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(40))
