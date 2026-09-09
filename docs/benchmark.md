# Paired assessment measurements

The toolkit calculates results from operator-recorded timings. It cannot establish
that timings are genuine, that the same tasks were completed, or that a server is
the intended lab target. External acceptance requires the raw records and an
operator-reviewed environment/method description. No measurements ship with RedOps.
`labs/paired-trials-template.csv` contains only a header and intentionally fails
validation until records are supplied. Test-generated timings are not evidence.

## Recording protocol

1. Freeze the exact inventory input, reviewed catalog, scope and reporting task.
   Record their SHA-256 hashes in a study manifest and reference that manifest in
   notes. `input_sha256` identifies the identical inventory supplied to both methods.
2. Describe the environment using a pseudonymous ID: OS, Python, RedOps commit,
   database backend, relevant tool versions, lab configuration and resource limits.
   Keep credentials and private endpoint details outside the published record.
3. For each `service-01` through `service-12` in the healthy inventory lab, record
   at least three paired trials in each reported cache/environment/operator group.
   Service names correspond to `172.30.77.10` through `.21`, TCP port 8080, in the
   provided Compose fixture. Document any configured address changes in the manifest.
4. Alternate the method order to reduce learning effects and record the actual
   order. Use the same environment and input within a pair. Reset cold caches or
   record warmed caches consistently; do not mix those conditions in one group.
5. Start a monotonic wall-clock timer before inventory assessment. Stop after
   candidate evidence review, durable persistence and the agreed report formats
   are complete. **Include human review in both methods.** Record the whole task,
   including errors/retries, rather than an internal processing timer. Document
   manual tools and any unavoidable differences in the study manifest.
6. Retain every attempt. A failed method records elapsed time and a failure note;
   a method never started has `not_run` status and an empty duration. Keep the
   paired counterpart and explain incomplete or missing human-review tasks.
7. Publish the original CSV, manifest, generated per-target summaries and HTML/JSON
   results after checking provenance and removing credentials/private identifiers.

`processing_seconds` only covers local assessment processing before persistence.
It excludes reports and operator work, so it must never substitute for these timings.
These tasks evaluate inventory assessment, not exploitation preparation. The healthy
fixture does not fulfill the original vulnerable-target requirement.

## CSV contract

Copy the exact header from the template. Input is UTF-8 CSV, at most 1 MiB and
10,000 records. Text identifiers start with a letter/digit and contain only letters,
digits, `.`, `_`, `:`, or `-`, with a maximum of 200 characters.

| Column | Meaning |
| --- | --- |
| `trial_id` | Globally unique attempt-pair identifier |
| `target` | Canonical lab service name, `service-01` … `service-12` |
| `input_sha256` | 64 hexadecimal characters identifying the shared inventory input |
| `method_order` | `manual_first` or `redops_first` |
| `cache_state` | `cold`, `warm`, or `offline` (document precise conditions) |
| `operator` | Operator pseudonym |
| `environment_id` | ID of the recorded environment/method manifest |
| `started_at` | Actual timezone-aware ISO 8601 start timestamp |
| `manual_seconds`, `redops_seconds` | Entire task durations, 0.001–1,000,000,000 seconds; blank only for `not_run` |
| `manual_status`, `redops_status` | `completed`, `failed`, or `not_run` |
| `includes_human_review` | `true` only when both methods include human candidate review; otherwise `false` |
| `notes` | Up to 10,000 characters; required for failed/incomplete or missing-review pairs |

Run the evaluator, choosing a new output directory:

```bash
redops benchmark --trials /path/to/recorded-trials.csv --output-dir reports/paired-study
```

It creates an unchanged `raw-trials.csv`, a complete `summary.json`, a derived
`per-target.csv`, and a self-contained escaped `report.html`. Files are prepared
before publishing the directory; existing results are never replaced. The summary
includes a SHA-256 of the original CSV and retains original decimal timing strings.

## Interpretation and acceptance

Results remain separate for each cache/environment/operator group. Each group
reports the reduction from **total completed paired durations that include human
review**, not an average of target percentages. It also shows every unsuccessful
or missing-review attempt, its reason, and total elapsed time across all attempts.
Failed tasks are not equivalent completed work and do not enter the reduction;
their frequency and explanations must be reviewed before accepting the study.

Coverage is incomplete if a required service has fewer than three eligible pairs,
if a target's input hash changes within a group, or if unexpected target names
appear. Such records remain visible. Different studies belong in separate files
or environment IDs, with the differences documented.

The formula is `(total_manual - total_redops) / total_manual * 100`. Decimal
arithmetic compares the threshold before converting a display value. Exactly 60%
fails; a lower or negative result remains failed. `reduction_percent_exact` preserves
the unrounded representation. A complete group above 60% is labeled
`passed_observed_threshold`; it still requires genuine evidence review. The overall
`external_acceptance` field remains `awaiting_operator_evidence_review`, and groups
are never combined into a misleading overall percentage.

The legacy `redops benchmark --input FILE` aggregate CSV interface is preserved.
Its three columns are `target,manual_seconds,redops_seconds`. It supports historical
calculations but cannot meet paired-trial evidence requirements. `--input` and
`--trials` are mutually exclusive; `--output-dir` requires `--trials`.
