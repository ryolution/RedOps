# Validation record

## Completion batches: inventory, reviews, dashboard and delivery

The requirement matrix is maintained in [completion.md](completion.md). The new
software supports JSON inventory provenance, evidence-catalog validation, append-only
reviews with schema migration, browser sessions/CSRF, reviewed exports and bundled
Unicode fonts. Original offensive exclusions remain unmet.

Local checks on Linux Python 3.14 include 215 passing regression tests with warnings treated
as errors, three real Chromium journeys (desktop and 390px), hash-locked dependency
installation, wheel/source asset validation, and execution of the installed wheel
away from the checkout. The wheel check completes an offline assessment, all report
formats, dashboard login and portable backup restoration. The digest-pinned container
completed the offline demonstration with networking disabled: 12 synthetic hosts
and 8 fictional candidate findings. Screenshots use synthetic records only and are
linked from [release operation](release.md).

Batches 1–5 each passed the existing six-job GitHub Actions workflow after pushing.
The delivery batch adds a dedicated Chromium job, consumes hash locks in every
Python job, and checks installed-wheel execution on Python 3.11/3.13/3.14. Its final
CI result must be read from the commit's Actions checks; local results do not stand
in for remote checks. Real Metasploit RPC evidence and genuine human benchmark
measurements remain pending.

## Historical baseline: September 8, 2026

Validated locally on September 8, 2026, using Python 3.14.4 in `/tmp/redops-venv`
and Python 3.13 in Docker.

- 165 local pytest cases passed: input validation, scope expiry/allowlists, CPE evidence,
  duplicate handling, SQL transaction rollback, report escaping, CLI workflows,
  dry-run side effects, path collision protection, benchmark arithmetic, and
  mocked MessagePack health requests, NVD response parsing, retry limits, cache
  expiry, provider injection, candidate limits, PDF contents, API authentication,
  pagination, storage failures, explicit offline behavior, scan planning, process
  deadlines and cleanup, output collision races, healthy lab HTTP routes, portable
  archives, concurrent-write snapshot consistency, migration rollback, restore
  constraint failures, retention boundaries, and audit failure reporting. The two
  PostgreSQL pytest cases skip locally unless `REDOPS_TEST_POSTGRES_URL` is set;
  both passed against a disposable PostgreSQL 17 database in Docker.
- Ruff lint and formatting checks passed.
- All Python source and test files parsed with Python 3.11 grammar. This is a
  syntax check, not a Python 3.11 runtime test; CI defines the runtime matrix.
- An actual `redops` console invocation imported the synthetic fixture, saved
  SQLite records, read inventory, and exported HTML, JSON, and PDF successfully.
- A real local API process rejected unauthenticated data access with 401 and
  served a valid PDF to an authenticated request. It was stopped after testing.
- A live NVD lookup for `CVE-2021-44228` returned a validated advisory and populated
  the test cache. No assessment target was contacted.
- The demonstration produced 12 hosts, 12 open services, 8 fictional candidate
  findings, and 10 services with a supported versioned CPE.
- Wheel and source-distribution builds succeeded. The source distribution
  includes documentation, demonstration inputs, Bash scripts, and the complete test suite.
- The pre-existing README prefix and its Windows line endings were preserved.

The generated local reports are `reports/demo.html`, `reports/demo.json`, and `reports/demo.pdf`.
They and the local assessment database/audit log are excluded from Git.

Windows Docker built the image and ran the workflow with networking disabled,
a read-only filesystem, dropped capabilities, and temporary writable mounts.
A temporary PostgreSQL 17 container on an internal network passed assessment
persistence, inventory retrieval, and history listing. The temporary database and
network were removed. Compose configuration validation also passed.

The PostgreSQL maintenance check restored a SQLite archive, inserted a new
assessment to verify serial sequences, upgraded a legacy schema, pruned an old
assessment with a preceding archive, and restored a PostgreSQL archive into
SQLite. Its temporary schema, database container, and internal network were
removed after the test. The SQLite concurrency test inserted another assessment
while a backup was being read and verified a consistent snapshot across tables.

CI includes actual Python 3.11/3.13/3.14 tests, a dedicated PostgreSQL integration
job, an isolated container workflow, and a running inventory lab check. A real
unprivileged Nmap TCP connect scan against the twelve healthy lab containers
returned twelve hosts with port 8080 open. No host ports were published; the lab
used an internal Docker network. At this earlier baseline, test dependencies emitted upstream
Starlette/httpx and AnyIO warnings; the delivery batch resolves them through tested constraints.

Live Metasploit RPC was not tested because no service or credentials were supplied;
its TLS policy, authentication sequence, logout, and error paths have mocked tests.
There is no payload/exploit automation or measured 60% improvement
claim. At this earlier baseline PDF escaped non-ASCII text; the reviewed-report
batch adds shaped Unicode fonts with explicit fallback for unsupported glyphs.
Deployment TLS, access controls, off-host backup storage, and retention schedules
require operator configuration. Portable archives exclude the audit log and
external files, and are limited to 64 MiB and 100,000 rows.
