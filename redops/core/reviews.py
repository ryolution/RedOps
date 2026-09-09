"""Stable identities and dispositions for operator reviews of immutable findings."""

import hashlib
import json
from typing import Any

DISPOSITIONS = ("needs_review", "affected", "not_affected", "accepted_risk", "remediated")


def finding_key(assessment_id: str, finding: dict[str, Any]) -> str:
    identity = [
        assessment_id,
        finding["host"],
        finding["protocol"],
        finding["port"],
        finding["vulnerability_id"],
    ]
    return hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()
