"""Append-only operator decisions, serialized with maintenance and assessment writers."""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.engine import Connection

from redops.core.config import Settings
from redops.core.errors import AssessmentNotFound, InputError, RedOpsError, ReviewConflict
from redops.core.reviews import DISPOSITIONS, finding_key
from redops.database.maintenance import _audited, _repository
from redops.database.models import ActionRecord, Assessment, FindingReview
from redops.database.schema import lock_tables, schema_version, transaction


def _document(connection: Connection, assessment_id: str) -> dict[str, Any]:
    document = connection.scalar(select(Assessment.document).where(Assessment.id == assessment_id))
    if document is None:
        raise AssessmentNotFound("Assessment not found.")
    return document


def _require_finding(document: dict[str, Any], key: str) -> None:
    if not any(finding_key(document["id"], item) == key for item in document["findings"]):
        raise AssessmentNotFound("Finding not found in this assessment.")


def review_snapshot(connection: Connection, assessment_id: str) -> dict[str, Any]:
    version = schema_version(connection)
    document = _document(connection, assessment_id)
    latest = {}
    revision = 0
    if version >= 3:
        # A single bounded assessment can have 10000 findings. Fetch only the latest
        # row per finding, rather than accumulating an unbounded review history.
        from sqlalchemy import func

        ids = (
            select(func.max(FindingReview.id))
            .where(FindingReview.assessment_id == assessment_id)
            .group_by(FindingReview.finding_key)
        )
        for row in connection.execute(
            select(FindingReview.__table__).where(FindingReview.id.in_(ids))
        ).mappings():
            latest[row["finding_key"]] = dict(row)
            revision = max(revision, row["id"])
    return {
        "assessment": document,
        "revision": revision,
        "writable": version >= 3,
        "findings": [
            {
                **item,
                "key": finding_key(assessment_id, item),
                "review": latest.get(finding_key(assessment_id, item)),
            }
            for item in document["findings"]
        ],
    }


def list_reviews(
    settings: Settings,
    assessment_id: str,
    key: str | None = None,
    *,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    def execute() -> dict[str, Any]:
        if not 1 <= limit <= 100 or not 0 <= offset <= 1000000:
            raise InputError("Review pagination is outside supported bounds.")
        with _repository(settings) as repository, transaction(repository.engine) as connection:
            snapshot = review_snapshot(connection, assessment_id)
            if key is None:
                return {"status": "checked", **snapshot}
            _require_finding(snapshot["assessment"], key)
            items = []
            if snapshot["writable"]:
                statement = (
                    select(FindingReview.__table__)
                    .where(
                        FindingReview.assessment_id == assessment_id,
                        FindingReview.finding_key == key,
                    )
                    .order_by(FindingReview.id.desc())
                    .limit(limit)
                    .offset(offset)
                )
                items = [dict(row) for row in connection.execute(statement).mappings()]
            current = next(item["review"] for item in snapshot["findings"] if item["key"] == key)
            return {
                "status": "checked",
                "items": items,
                "latest_id": current["id"] if current else 0,
                "limit": limit,
                "offset": offset,
                "writable": snapshot["writable"],
            }

    return _audited(settings, "review.list", [], execute)


def add_review(
    settings: Settings,
    assessment_id: str,
    key: str,
    *,
    disposition: str,
    notes: str,
    expected_previous: int,
    operator: str,
) -> dict[str, Any]:
    def execute() -> dict[str, Any]:
        if (
            disposition not in DISPOSITIONS
            or type(expected_previous) is not int
            or expected_previous < 0
        ):
            raise InputError("Invalid review disposition or expected previous identifier.")
        if (
            not isinstance(notes, str)
            or len(notes) > 10000
            or "\x00" in notes
            or not operator.strip()
            or len(operator) > 200
            or "\x00" in operator
        ):
            raise InputError("Invalid review notes or operator attribution.")
        if disposition != "needs_review" and not notes.strip():
            raise InputError("A review decision requires explanatory notes.")
        with (
            _repository(settings) as repository,
            transaction(repository.engine, write=True) as connection,
        ):
            lock_tables(connection)
            if schema_version(connection) < 3:
                raise RedOpsError("Review writes require an explicit database migration.")
            document = _document(connection, assessment_id)
            _require_finding(document, key)
            previous = (
                connection.scalar(
                    select(FindingReview.id)
                    .where(
                        FindingReview.assessment_id == assessment_id,
                        FindingReview.finding_key == key,
                    )
                    .order_by(FindingReview.id.desc())
                    .limit(1)
                )
                or 0
            )
            if previous != expected_previous:
                raise ReviewConflict("A newer review exists; reload its history before submitting.")
            values = {
                "assessment_id": assessment_id,
                "finding_key": key,
                "timestamp": datetime.now(UTC).isoformat(),
                "operator": operator,
                "disposition": disposition,
                "notes": notes,
            }
            identifier = connection.execute(
                FindingReview.__table__.insert().values(**values)
            ).inserted_primary_key[0]
            connection.execute(
                ActionRecord.__table__.insert().values(
                    assessment_id=assessment_id,
                    timestamp=values["timestamp"],
                    operator=operator,
                    action="finding_review",
                    status="completed",
                )
            )
        return {"status": "completed", "review": {"id": identifier, **values}}

    return _audited(settings, "review.add", [], execute, operator=operator)
