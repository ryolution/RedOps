# Offline demonstration

`demo-nmap.xml` is authored synthetic data containing 12 hosts in the documentation
address range `192.0.2.0/24`. No hosts were scanned. `demo-catalog.json` contains
fictional products and `DEMO-*` identifiers, not real CVEs. Its `example.invalid`
source strings deliberately do not refer to actual advisories.

Expected result: 12 hosts, 12 open services, 10 services with a supported versioned
CPE, and 8 candidate findings (4 high, 4 medium). Two services have no matching
catalog entry; two lack a versioned CPE. All reports identify the evidence as
synthetic. This fixture is a software demonstration, not a 12-machine laboratory
evaluation or evidence of exploitation.

The scope's long expiry is solely for this offline synthetic fixture. For real
assessment data, copy the configuration and enter the actual scope, approval
attribution, operator, host limit, and short engagement expiry.

## Measurement protocol

Use [paired measurement instructions](../docs/benchmark.md) and
`paired-trials-template.csv` for completion evidence. Record at least three paired
full-task trials per healthy lab service and cache/environment/operator group.
Include human review in both methods and preserve unsuccessful attempts.

The legacy `benchmark-template.csv` and `redops benchmark --input FILE` remain
available for aggregate arithmetic; they do not meet paired-trial acceptance.
The formula uses total manual and RedOps times, and only an unrounded result
strictly above 60% passes the observed threshold. No measurements are bundled.

`processing_seconds` excludes persistence, reports and human review, so it must
not be used as the complete task duration. The workflow measured here is inventory
assessment, not the excluded exploitation-preparation workflow.
