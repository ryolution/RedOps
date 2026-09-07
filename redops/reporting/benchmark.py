"""Compute reductions from measurements; never manufacture evaluation results."""

import csv
import io
import math
from pathlib import Path
from typing import Any

from redops.core.errors import InputError
from redops.core.io import read_bounded


def calculate_benchmark(path: Path) -> dict[str, Any]:
    try:
        reader = csv.DictReader(io.StringIO(read_bounded(path, 1024 * 1024).decode("utf-8-sig")))
        if reader.fieldnames != ["target", "manual_seconds", "redops_seconds"]:
            raise ValueError
        rows = []
        seen = set()
        for row in reader:
            if None in row or not row["target"].strip() or row["target"] in seen:
                raise ValueError
            seen.add(row["target"])
            manual, automated = float(row["manual_seconds"]), float(row["redops_seconds"])
            if not all(math.isfinite(value) and value > 0 for value in (manual, automated)):
                raise ValueError
            rows.append(
                {
                    "target": row["target"],
                    "manual_seconds": manual,
                    "redops_seconds": automated,
                    "reduction_percent": round((manual - automated) / manual * 100, 2),
                }
            )
        if not rows:
            raise ValueError
        manual_total = math.fsum(row["manual_seconds"] for row in rows)
        automated_total = math.fsum(row["redops_seconds"] for row in rows)
        reduction = (manual_total - automated_total) / manual_total * 100
        return {
            "basis": "operator-supplied measurements; not independently verified",
            "targets": rows,
            "manual_seconds": manual_total,
            "redops_seconds": automated_total,
            "reduction_percent": round(reduction, 2),
            "exceeds_60_percent": reduction > 60,
        }
    except (ValueError, TypeError, KeyError, AttributeError, csv.Error, OverflowError) as exc:
        raise InputError(
            "Invalid benchmark CSV; provide unique targets and positive, finite timings."
        ) from exc
