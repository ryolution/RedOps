"""Synthetic arithmetic fixtures only; these timings are never acceptance evidence."""

import csv
import hashlib
import io
import json

import pytest

from redops.cli.main import main
from redops.core.errors import InputError
from redops.reporting.trials import FIELDS, OUTPUTS, TARGETS, benchmark_trials, evaluate_trials


def trial(identifier="trial-1", target="service-01", **changes):
    return {
        "trial_id": identifier,
        "target": target,
        "input_sha256": "a" * 64,
        "method_order": "manual_first",
        "cache_state": "cold",
        "operator": "fixture",
        "environment_id": "synthetic-unit-test",
        "started_at": "2026-09-01T12:00:00Z",
        "manual_seconds": "100",
        "redops_seconds": "30",
        "manual_status": "completed",
        "redops_status": "completed",
        "includes_human_review": "true",
        "notes": "Synthetic test values; not measured evidence.",
        **changes,
    }


def encoded(rows):
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=FIELDS)
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().encode()


def complete(**changes):
    return [
        trial(f"{target}-{index}", target, **changes) for target in TARGETS for index in range(3)
    ]


def test_requires_three_pairs_for_all_twelve_targets():
    result = evaluate_trials(encoded(complete()))
    cohort = result["cohorts"][0]
    assert cohort["eligible_pairs"] == 36
    assert cohort["measurement_coverage_complete"]
    assert cohort["performance_criterion"] == "passed_observed_threshold"
    assert result["external_acceptance"] == "awaiting_operator_evidence_review"
    partial = evaluate_trials(encoded(complete()[:-1]))["cohorts"][0]
    assert partial["performance_criterion"] == "incomplete"
    assert partial["insufficient_targets"] == ["service-12"]


@pytest.mark.parametrize(
    "seconds,passed",
    [
        ("40", False),
        ("40.000000000001", False),
        ("39.999999999999", True),
        ("120", False),
    ],
)
def test_strict_unrounded_threshold(seconds, passed):
    cohort = evaluate_trials(encoded(complete(redops_seconds=seconds)))["cohorts"][0]
    assert cohort["exceeds_60_percent"] is passed
    assert cohort["performance_criterion"] == (
        "passed_observed_threshold" if passed else "failed_observed_threshold"
    )


def test_ratio_of_totals_not_average_of_percentages():
    rows = [
        trial(manual_seconds="100", redops_seconds="50"),
        trial("trial-2", manual_seconds="900", redops_seconds="180"),
    ]
    cohort = evaluate_trials(encoded(rows))["cohorts"][0]
    assert cohort["reduction_percent"] == 77


def test_cache_environment_and_operator_cohorts_are_never_pooled():
    rows = [
        trial(),
        trial("warm", cache_state="warm"),
        trial("environment", environment_id="second"),
        trial("operator", operator="second"),
    ]
    result = evaluate_trials(encoded(rows))
    assert len(result["cohorts"]) == 4
    assert "reduction_percent" not in result
    assert all(cohort["eligible_pairs"] == 1 for cohort in result["cohorts"])


def test_failures_and_missing_human_review_are_retained():
    rows = [
        trial(),
        trial("failure", redops_status="failed", redops_seconds="15"),
        trial("not-run", manual_status="not_run", manual_seconds=""),
        trial("no-review", includes_human_review="false"),
    ]
    result = evaluate_trials(encoded(rows))
    cohort = result["cohorts"][0]
    assert len(result["trials"]) == 4
    assert cohort["eligible_pairs"] == 1 and cohort["unsuccessful_pairs"] == 2
    assert cohort["missing_review_pairs"] == 1
    assert cohort["all_attempt_redops_seconds"] == 105
    assert cohort["redops_seconds"] == 30
    assert result["trials"][2]["manual_seconds"] is None


def test_changed_inputs_and_unknown_targets_block_coverage():
    rows = complete()
    rows[0]["input_sha256"] = "b" * 64
    rows.append(trial("extra", "different-service"))
    cohort = evaluate_trials(encoded(rows))["cohorts"][0]
    assert not cohort["measurement_coverage_complete"]
    assert cohort["changed_input_targets"] == ["service-01"]
    assert cohort["unexpected_targets"] == ["different-service"]


@pytest.mark.parametrize(
    "changes",
    [
        {"input_sha256": "invalid"},
        {"started_at": "2026-09-01"},
        {"method_order": "unknown"},
        {"cache_state": "unknown"},
        {"manual_seconds": "nan"},
        {"redops_seconds": "inf"},
        {"manual_seconds": "0"},
        {"manual_seconds": "-1"},
        {"manual_seconds": "1e999999999"},
        {"manual_status": "unknown"},
        {"manual_status": "not_run"},
        {"redops_status": "failed", "notes": ""},
        {"includes_human_review": "false", "notes": ""},
        {"includes_human_review": "yes"},
        {"notes": "\x00"},
        {"operator": "<script>"},
    ],
)
def test_invalid_records_are_rejected(changes):
    with pytest.raises(InputError):
        evaluate_trials(encoded([trial(**changes)]))


def test_empty_duplicate_header_extra_column_and_size_limits():
    for content in (
        encoded([]),
        encoded([trial(), trial()]),
        b"target,manual_seconds\n",
        encoded([trial()]) + b"extra,column\n",
        b"x" * (1024 * 1024 + 1),
    ):
        with pytest.raises(InputError):
            evaluate_trials(content)


def test_artifacts_preserve_input_and_escape_notes(tmp_path):
    content = encoded([trial(notes="<script>fixture</script>")])
    source, output = tmp_path / "trials.csv", tmp_path / "published"
    source.write_bytes(content)
    result = benchmark_trials(source, output)
    assert set(path.name for path in output.iterdir()) == set(OUTPUTS)
    assert (output / "raw-trials.csv").read_bytes() == content
    assert result["source_sha256"] == hashlib.sha256(content).hexdigest()
    saved = json.loads((output / "summary.json").read_text())
    assert saved["trials"] == result["trials"]
    assert "<script>fixture" not in (output / "report.html").read_text()
    assert "&lt;script&gt;fixture" in (output / "report.html").read_text()
    with pytest.raises(InputError, match="new"):
        benchmark_trials(source, output)
    with pytest.raises(InputError, match="distinct"):
        benchmark_trials(source, protected_paths=[source])


def test_interrupted_artifact_write_leaves_no_published_bundle(tmp_path, monkeypatch):
    source = tmp_path / "trials.csv"
    source.write_bytes(encoded([trial()]))

    def fail(*args, **kwargs):
        raise OSError("controlled export failure")

    monkeypatch.setattr("redops.reporting.trials.atomic_write", fail)
    with pytest.raises(OSError):
        benchmark_trials(source, tmp_path / "output")
    assert list(tmp_path.iterdir()) == [source]


def test_cli_paired_and_legacy_compatibility(tmp_path, capsys):
    source = tmp_path / "trials.csv"
    source.write_bytes(encoded([trial()]))
    base = ["--audit", str(tmp_path / "audit.jsonl")]
    assert (
        main(
            base + ["benchmark", "--trials", str(source), "--output-dir", str(tmp_path / "output")]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["cohorts"][0]["eligible_pairs"] == 1
    legacy = tmp_path / "legacy.csv"
    legacy.write_text("target,manual_seconds,redops_seconds\na,100,30\n")
    assert main(base + ["benchmark", "--input", str(legacy)]) == 0
    assert json.loads(capsys.readouterr().out)["exceeds_60_percent"] is True
    assert (
        main(
            base
            + ["benchmark", "--input", str(legacy), "--output-dir", str(tmp_path / "legacy-out")]
        )
        == 2
    )
    with pytest.raises(SystemExit) as error:
        main(["benchmark", "--input", str(legacy), "--trials", str(source)])
    assert error.value.code == 2
