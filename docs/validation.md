# Validation record

Validated locally on September 8, 2026, using Python 3.14.4 in `/tmp/redops-venv`
and Python 3.13 in Docker.

- 106 local pytest cases passed: input validation, scope expiry/allowlists, CPE evidence,
  duplicate handling, SQL transaction rollback, report escaping, CLI workflows,
  dry-run side effects, path collision protection, benchmark arithmetic, and
  mocked MessagePack health requests, NVD response parsing, retry limits, cache
  expiry, provider injection, candidate limits, PDF contents, API authentication,
  pagination, storage failures, and explicit offline behavior. The dedicated
  PostgreSQL pytest case skips locally unless `REDOPS_TEST_POSTGRES_URL` is set;
  a separate live PostgreSQL check passed in Docker.
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

CI includes actual Python 3.11/3.13/3.14 tests, a dedicated PostgreSQL integration
job, and an isolated container workflow. Current test dependencies emit upstream
Starlette/httpx and AnyIO deprecation warnings; these are not suppressed.

Live Metasploit RPC was not tested because no service or credentials were supplied;
its TLS policy, authentication sequence, logout, and error paths have mocked tests.
There is no active scanning, payload/exploit automation, or measured 60% improvement
claim. PDF displays non-ASCII text as Unicode escapes; JSON retains original text.
Deployment TLS, access controls, backups, migrations, and retention require operator
configuration.
