"""Transactional persistence; no implicit schema changes on read commands."""

from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, event, inspect, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from redops.core.errors import AssessmentNotFound, RedOpsError
from redops.database.models import (
    ActionRecord,
    Assessment,
    Base,
    HostRecord,
    SchemaVersion,
    ServiceRecord,
    VulnerabilityRecord,
)


class Repository:
    def __init__(self, database_url: str, *, create: bool = False):
        url = make_url(database_url)
        if url.get_backend_name() not in {"sqlite", "postgresql"}:
            raise RedOpsError("Only SQLite and PostgreSQL databases are supported.")
        if url.get_backend_name() == "sqlite" and url.database not in {None, "", ":memory:"}:
            path = Path(url.database)
            if not create and not path.is_file():
                raise RedOpsError(
                    "Database does not exist; run redops init or an assessment first."
                )
            if create:
                path.parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(url, hide_parameters=True)
        if url.get_backend_name() == "sqlite":
            event.listen(self.engine, "connect", self._sqlite_foreign_keys)

    @staticmethod
    def _sqlite_foreign_keys(connection: Any, _: Any) -> None:
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    def initialize(self) -> None:
        tables = set(inspect(self.engine).get_table_names())
        if tables:
            self._check_schema()
            return
        Base.metadata.create_all(self.engine)
        with Session(self.engine) as session, session.begin():
            session.add(SchemaVersion(id=1, version=1))

    def _check_schema(self) -> None:
        if not set(Base.metadata.tables).issubset(inspect(self.engine).get_table_names()):
            raise RedOpsError(
                "Database schema is missing or incompatible; an explicit migration is required."
            )
        with Session(self.engine) as session:
            version = session.get(SchemaVersion, 1)
            if version is None or version.version != 1:
                raise RedOpsError(
                    "Database schema version is incompatible; an explicit migration is required."
                )

    def save(self, document: dict[str, Any]) -> None:
        self._check_schema()
        findings: dict[tuple[str, int, str], list[dict[str, Any]]] = {}
        for finding in document["findings"]:
            key = finding["host"], finding["port"], finding["protocol"]
            findings.setdefault(key, []).append(finding)
        assessment = Assessment(
            id=document["id"],
            created_at=document["created_at"],
            engagement=document["scope"]["engagement"],
            operator=document["scope"]["operator"],
            document=document,
        )
        for host in document["hosts"]:
            row = HostRecord(ip=host["ip"], hostname=host["hostname"], os=host["os"])
            for service in host["services"]:
                number, protocol = service["port"]["number"], service["port"]["protocol"]
                service_row = ServiceRecord(
                    port=number,
                    protocol=protocol,
                    name=service["name"],
                    product=service["product"],
                    version=service["version"],
                    cpes=list(service["cpes"]),
                )
                for finding in findings.get((host["ip"], number, protocol), []):
                    service_row.vulnerabilities.append(
                        VulnerabilityRecord(
                            **{
                                key: finding[key]
                                for key in (
                                    "vulnerability_id",
                                    "cvss",
                                    "description",
                                    "remediation",
                                    "source",
                                    "status",
                                )
                            }
                        )
                    )
                row.services.append(service_row)
            assessment.hosts.append(row)
        with Session(self.engine) as session, session.begin():
            session.add(assessment)
            session.flush()
            session.add(
                ActionRecord(
                    assessment_id=assessment.id,
                    timestamp=assessment.created_at,
                    operator=assessment.operator,
                    action="assessment",
                    status="completed",
                )
            )

    def get(self, assessment_id: str | None = None) -> dict[str, Any]:
        self._check_schema()
        with Session(self.engine) as session:
            if assessment_id:
                row = session.get(Assessment, assessment_id)
            else:
                row = session.scalars(
                    select(Assessment)
                    .order_by(Assessment.created_at.desc(), Assessment.id.desc())
                    .limit(1)
                ).first()
            if row is None:
                raise AssessmentNotFound("No matching assessment found.")
            return row.document

    def list_assessments(
        self,
        *,
        engagement: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        if not 1 <= limit <= 100 or not 0 <= offset <= 1000000:
            raise RedOpsError("Assessment pagination is outside the supported bounds.")
        self._check_schema()
        statement = (
            select(
                Assessment.id,
                Assessment.created_at,
                Assessment.engagement,
                Assessment.operator,
            )
            .order_by(Assessment.created_at.desc(), Assessment.id.desc())
            .limit(limit)
            .offset(offset)
        )
        if engagement is not None:
            statement = statement.where(Assessment.engagement == engagement)
        with Session(self.engine) as session:
            return [dict(row) for row in session.execute(statement).mappings()]

    def inventory(self, assessment_id: str | None = None) -> list[dict[str, Any]]:
        return self.get(assessment_id)["hosts"]

    def close(self) -> None:
        self.engine.dispose()
