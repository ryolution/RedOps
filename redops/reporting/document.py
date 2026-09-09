"""Build optional, consistent review exports without changing assessment snapshots."""

from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

from redops.database.repository import Repository
from redops.database.reviews import review_snapshot
from redops.database.schema import transaction


def report_document(
    repository: Repository, assessment_id: str | None, *, include_reviews: bool = False
) -> dict[str, Any]:
    document = repository.get(assessment_id)
    if not include_reviews:
        return document
    with transaction(repository.engine) as connection:
        snapshot = review_snapshot(connection, document["id"])
        exported_at = datetime.now(UTC).isoformat()
    result = deepcopy(snapshot["assessment"])
    result["review_export"] = {
        "schema_version": 1,
        "revision": snapshot["revision"],
        "exported_at": exported_at,
        "interpretation": "Operator judgments; original candidate findings are unchanged.",
        "findings": [
            {
                "finding_key": item["key"],
                "disposition": (item["review"] or {}).get("disposition", "needs_review"),
                "review": item["review"],
            }
            for item in snapshot["findings"]
        ],
    }
    return result


def review_by_key(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item["finding_key"]: item for item in document.get("review_export", {}).get("findings", [])
    }
