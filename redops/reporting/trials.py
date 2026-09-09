"""Evaluate operator-recorded paired tasks; retain unsuccessful and ineligible trials."""

import csv
import hashlib
import io
import json
import logging
import math
import os
import re
import shutil
import tempfile
from collections import Counter, defaultdict
from datetime import datetime
from decimal import Decimal, InvalidOperation, localcontext
from html import escape
from pathlib import Path
from typing import Any

from redops.core.branding import logo_data_uri
from redops.core.errors import InputError
from redops.core.io import atomic_write, read_bounded, require_distinct_paths

logger = logging.getLogger(__name__)
FIELDS = [
    "trial_id",
    "target",
    "input_sha256",
    "method_order",
    "cache_state",
    "operator",
    "environment_id",
    "started_at",
    "manual_seconds",
    "redops_seconds",
    "manual_status",
    "redops_status",
    "includes_human_review",
    "notes",
]
TARGETS = tuple(f"service-{number:02}" for number in range(1, 13))
OUTPUTS = ("raw-trials.csv", "summary.json", "per-target.csv", "report.html")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")


def _duration(value: str, status: str) -> Decimal | None:
    if status == "not_run":
        if value:
            raise ValueError
        return None
    if len(value) > 32:
        raise ValueError
    result = Decimal(value)
    if not result.is_finite() or not Decimal("0.001") <= result <= Decimal("1000000000"):
        raise ValueError
    return result


def parse_trials(content: bytes) -> list[dict[str, Any]]:
    """Parse a bounded strict CSV; duration decimals retain threshold precision."""
    try:
        reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig")), strict=True)
        if reader.fieldnames != FIELDS:
            raise ValueError
        records, seen = [], set()
        for row in reader:
            if None in row or any(value is None for value in row.values()) or len(records) >= 10000:
                raise ValueError
            if (
                any(
                    not IDENTIFIER.fullmatch(row[key])
                    for key in ("trial_id", "target", "operator", "environment_id")
                )
                or row["trial_id"] in seen
            ):
                raise ValueError
            seen.add(row["trial_id"])
            if not re.fullmatch(r"[a-fA-F0-9]{64}", row["input_sha256"]):
                raise ValueError
            row["input_sha256"] = row["input_sha256"].lower()
            if row["method_order"] not in {"manual_first", "redops_first"} or row[
                "cache_state"
            ] not in {"cold", "warm", "offline"}:
                raise ValueError
            stamp = datetime.fromisoformat(row["started_at"])
            if stamp.tzinfo is None or stamp.utcoffset() is None or len(row["started_at"]) > 40:
                raise ValueError
            if row["includes_human_review"] not in {"true", "false"}:
                raise ValueError
            row["includes_human_review"] = row["includes_human_review"] == "true"
            if len(row["notes"]) > 10000 or any(
                ord(char) < 32 and char not in "\n\t" for char in row["notes"]
            ):
                raise ValueError
            for method in ("manual", "redops"):
                status = row[method + "_status"]
                if status not in {"completed", "failed", "not_run"}:
                    raise ValueError
                row[method + "_seconds"] = _duration(row[method + "_seconds"], status)
            completed = row["manual_status"] == row["redops_status"] == "completed"
            row["eligible"] = completed and row["includes_human_review"]
            row["exclusion_reason"] = (
                None
                if row["eligible"]
                else "task_not_completed"
                if not completed
                else "human_review_missing"
            )
            if not row["eligible"] and not row["notes"].strip():
                raise ValueError
            records.append(row)
        if not records:
            raise ValueError
        return records
    except (ValueError, TypeError, KeyError, csv.Error, InvalidOperation) as exc:
        raise InputError(
            "Invalid paired-trial CSV. Check the documented header, unique IDs, hashes, "
            "timezone-aware dates, status fields, bounded durations and failure notes."
        ) from exc


def _summary(rows: list[dict]) -> dict[str, Any]:
    eligible = [row for row in rows if row["eligible"]]
    with localcontext() as context:
        context.prec = 80
        manual = sum((row["manual_seconds"] for row in eligible), Decimal(0))
        redops = sum((row["redops_seconds"] for row in eligible), Decimal(0))
        reduction = (manual - redops) / manual * 100 if manual else None
        exceeds = redops < manual * Decimal("0.4") if manual else None
    return {
        "recorded_pairs": len(rows),
        "eligible_pairs": len(eligible),
        "unsuccessful_pairs": sum(row["exclusion_reason"] == "task_not_completed" for row in rows),
        "missing_review_pairs": sum(
            row["exclusion_reason"] == "human_review_missing" for row in rows
        ),
        "manual_seconds": float(manual),
        "redops_seconds": float(redops),
        "reduction_percent": float(reduction) if reduction is not None else None,
        "reduction_percent_exact": str(reduction) if reduction is not None else None,
        "exceeds_60_percent": exceeds,
        "all_attempt_manual_seconds": math.fsum(float(row["manual_seconds"] or 0) for row in rows),
        "all_attempt_redops_seconds": math.fsum(float(row["redops_seconds"] or 0) for row in rows),
        "method_orders": dict(Counter(row["method_order"] for row in rows)),
    }


def evaluate_trials(content: bytes) -> dict[str, Any]:
    if len(content) > 1024 * 1024:
        raise InputError("Paired-trial input exceeds the 1 MiB limit.")
    rows = parse_trials(content)
    groups = defaultdict(list)
    for row in rows:
        groups[row["cache_state"], row["environment_id"], row["operator"]].append(row)
    cohorts = []
    for (cache, environment, operator), group in sorted(groups.items()):
        targets = []
        for target in sorted({row["target"] for row in group}):
            matching = [row for row in group if row["target"] == target]
            targets.append(
                {
                    "target": target,
                    **_summary(matching),
                    "input_hashes": sorted({row["input_sha256"] for row in matching}),
                }
            )
        by_target = {target["target"]: target for target in targets}
        insufficient = [
            target for target in TARGETS if by_target.get(target, {}).get("eligible_pairs", 0) < 3
        ]
        changed_inputs = [
            target["target"] for target in targets if len(target["input_hashes"]) != 1
        ]
        unexpected = sorted(set(by_target) - set(TARGETS))
        summary = _summary(group)
        complete = not insufficient and not changed_inputs and not unexpected
        criterion = (
            "incomplete"
            if not complete
            else "passed_observed_threshold"
            if summary["exceeds_60_percent"]
            else "failed_observed_threshold"
        )
        cohorts.append(
            {
                "cache_state": cache,
                "environment_id": environment,
                "operator": operator,
                **summary,
                "targets": targets,
                "measurement_coverage_complete": complete,
                "insufficient_targets": insufficient,
                "changed_input_targets": changed_inputs,
                "unexpected_targets": unexpected,
                "performance_criterion": criterion,
            }
        )
    # Keep exact recorded decimal strings in raw normalized rows for audit/recalculation.
    normalized = [
        {key: str(value) if isinstance(value, Decimal) else value for key, value in row.items()}
        for row in rows
    ]
    result = {
        "schema": "redops-paired-benchmark",
        "schema_version": 1,
        "basis": (
            "Operator-supplied full task durations; provenance and authenticity require review."
        ),
        "task_scope": (
            "Equivalent inventory assessment, evidence review, persistence and reporting."
        ),
        "comparison_basis": (
            "Completed pairs including human review; failed attempts remain separately visible."
        ),
        "source_sha256": hashlib.sha256(content).hexdigest(),
        "required_targets": list(TARGETS),
        "minimum_pairs_per_target_per_cohort": 3,
        "cohorts": cohorts,
        "trials": normalized,
        "external_acceptance": "awaiting_operator_evidence_review",
    }
    logger.info(
        "Evaluated %d paired records in %d cache/environment/operator cohorts",
        len(rows),
        len(cohorts),
    )
    return result


def _target_csv(result: dict) -> str:
    columns = [
        "cache_state",
        "environment_id",
        "operator",
        "target",
        "recorded_pairs",
        "eligible_pairs",
        "unsuccessful_pairs",
        "missing_review_pairs",
        "manual_seconds",
        "redops_seconds",
        "reduction_percent_exact",
        "exceeds_60_percent",
    ]
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=columns)
    writer.writeheader()
    for cohort in result["cohorts"]:
        for target in cohort["targets"]:
            values = {**cohort, **target}
            writer.writerow({column: values[column] for column in columns})
    return output.getvalue()


def _html(result: dict) -> str:
    def text(value):
        return escape("unavailable" if value is None else str(value), quote=True)

    sections = []
    for cohort in result["cohorts"]:
        rows = "".join(
            "<tr>"
            + "".join(
                f"<td>{text(target[key])}</td>"
                for key in (
                    "target",
                    "eligible_pairs",
                    "unsuccessful_pairs",
                    "missing_review_pairs",
                    "manual_seconds",
                    "redops_seconds",
                    "reduction_percent_exact",
                )
            )
            + "</tr>"
            for target in cohort["targets"]
        )
        sections.append(
            f"<h2>{text(cohort['cache_state'])} · {text(cohort['environment_id'])} · "
            f"{text(cohort['operator'])}</h2><p>{text(cohort['performance_criterion'])}</p>"
            "<p>Reduction from total eligible paired durations: "
            f"{text(cohort['reduction_percent_exact'])}%</p>"
            f"<p>Eligible pairs: {cohort['eligible_pairs']}; "
            f"unsuccessful pairs: {cohort['unsuccessful_pairs']}; "
            f"missing review: {cohort['missing_review_pairs']}.</p>"
            "<p>Insufficient targets: "
            f"{text(', '.join(cohort['insufficient_targets']) or 'none')}. "
            f"Changed inputs: {text(', '.join(cohort['changed_input_targets']) or 'none')}. "
            f"Unexpected targets: {text(', '.join(cohort['unexpected_targets']) or 'none')}.</p>"
            "<div class='scroll'><table><thead><tr><th>Target</th><th>Pairs</th>"
            "<th>Unsuccessful</th><th>Missing review</th><th>Manual seconds</th>"
            "<th>RedOps seconds</th><th>Reduction %</th>"
            f"</tr></thead><tbody>{rows}</tbody></table></div>"
        )
    attempts = "".join(
        "<tr>"
        + "".join(
            f"<td>{text(row[key])}</td>"
            for key in (
                "trial_id",
                "target",
                "cache_state",
                "manual_status",
                "redops_status",
                "manual_seconds",
                "redops_seconds",
                "exclusion_reason",
                "notes",
            )
        )
        + "</tr>"
        for row in result["trials"]
    )
    return (
        "<!doctype html><html lang='en'><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width'>"
        "<meta http-equiv='Content-Security-Policy' "
        "content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">"
        "<title>RedOps paired benchmark</title><style>body{font:16px/1.5 system-ui;margin:2rem;"
        "color:#182531}table{border-collapse:collapse}td,th{padding:.6rem;border:1px solid #ccc;"
        "text-align:left;overflow-wrap:anywhere}.scroll{overflow:auto}p{overflow-wrap:anywhere}"
        ".brand{display:flex;align-items:center;gap:.7rem;font-weight:700}</style>"
        f'<p class="brand"><img src="{logo_data_uri()}" width="40" height="40" alt="">RedOps</p>'
        f"<h1>RedOps paired assessment benchmark</h1><p>{text(result['basis'])}</p>"
        f"<p>{text(result['task_scope'])}</p><p>{text(result['comparison_basis'])}</p>"
        "<p>Cache, environment and operator cohorts are evaluated separately. "
        "The observed threshold "
        "passes only above 60%; no result is rounded into success. These measurements do not cover "
        "exploitation preparation. External acceptance requires genuine evidence review.</p>"
        + "".join(sections)
        + "<h2>Every recorded attempt</h2><div class='scroll'><table><thead><tr><th>Trial</th>"
        "<th>Target</th><th>Cache</th><th>Manual status</th><th>RedOps status</th>"
        "<th>Manual seconds</th><th>RedOps seconds</th><th>Exclusion reason</th>"
        f"<th>Notes</th></tr></thead><tbody>{attempts}"
        f"</tbody></table></div><p>Source SHA-256: {result['source_sha256']}</p></html>"
    )


def benchmark_trials(path: Path, output_dir: Path | None = None, *, protected_paths=()) -> dict:
    destinations = [output_dir / name for name in OUTPUTS] if output_dir else []
    require_distinct_paths([path, *protected_paths, *destinations])
    if output_dir and (output_dir.exists() or output_dir.is_symlink()):
        raise InputError(
            "Benchmark output directory must be new; existing results are never replaced."
        )
    content = read_bounded(path, 1024 * 1024)
    result = evaluate_trials(content)
    if output_dir:
        artifacts = {
            "raw-trials.csv": content,
            "summary.json": json.dumps(result, indent=2, allow_nan=False) + "\n",
            "per-target.csv": _target_csv(result),
            "report.html": _html(result),
        }
        output_dir.parent.mkdir(parents=True, exist_ok=True)
        temporary = Path(tempfile.mkdtemp(prefix=".redops-benchmark-", dir=output_dir.parent))
        try:
            for name, data in artifacts.items():
                atomic_write(temporary / name, data, overwrite=False)
            os.rename(temporary, output_dir)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
        result["output_dir"] = str(output_dir)
        logger.info("Published paired benchmark artifacts")
    return result
