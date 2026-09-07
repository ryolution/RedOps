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

1. Define identical inventory, evidence-review, and reporting tasks for both methods.
2. Collect manual and RedOps wall-clock times on the same inputs and environment.
3. Include human candidate review time in both measurements; record cache state.
4. Repeat each target trial and retain raw timings and notes outside this template.
5. Put one chosen aggregate per unique target into `benchmark-template.csv`.
6. Run `redops benchmark --input your-measurements.csv`.

The formula is `(sum(manual) - sum(redops)) / sum(manual) * 100`; this is a
ratio of total times, not an average of per-target percentages. Slower automated
runs produce negative savings. The tool reports whether the unrounded reduction
strictly exceeds 60%; it does not verify the measurements. An empty template
intentionally fails validation. No time-reduction claim is made by this project.

`processing_seconds` in an assessment measures local validation and correlation
before persistence; it excludes database writes, reports, and human review. Do
not use it as the end-to-end benchmark measurement.
