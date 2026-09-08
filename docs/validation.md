# Validation record

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
used an internal Docker network. Current test dependencies emit upstream
Starlette/httpx and AnyIO deprecation warnings; these are not suppressed.

Live Metasploit RPC was not tested because no service or credentials were supplied;
its TLS policy, authentication sequence, logout, and error paths have mocked tests.
There is no payload/exploit automation or measured 60% improvement
claim. PDF displays non-ASCII text as Unicode escapes; JSON retains original text.
Deployment TLS, access controls, off-host backup storage, and retention schedules
require operator configuration. Portable archives exclude the audit log and
external files, and are limited to 64 MiB and 100,000 rows.
