# Validation record

Validated locally on September 7, 2026, using Python 3.14.4 in an isolated
environment at `/tmp/redops-venv`.

- 88 pytest cases passed: input validation, scope expiry/allowlists, CPE evidence,
  duplicate handling, SQL transaction rollback, report escaping, CLI workflows,
  dry-run side effects, path collision protection, benchmark arithmetic, and
  mocked MessagePack health requests, NVD response parsing, retry limits, cache
  expiry, provider injection, and explicit offline behavior.
- Ruff lint and formatting checks passed.
- All Python source and test files parsed with Python 3.11 grammar. This is a
  syntax check, not a Python 3.11 runtime test; CI defines the runtime matrix.
- An actual `redops` console invocation imported the synthetic fixture, saved
  SQLite records, read inventory, and exported HTML and JSON successfully.
- The demonstration produced 12 hosts, 12 open services, 8 fictional candidate
  findings, and 10 services with a supported versioned CPE.
- Wheel and source-distribution builds succeeded. The source distribution
  includes documentation, demonstration inputs, and the complete test suite.
- The pre-existing README prefix and its Windows line endings were preserved.

The generated local reports are `reports/demo.html` and `reports/demo.json`.
They and the local assessment database/audit log are excluded from Git.

Docker's executable wrapper was present, but reported that Docker Desktop WSL
integration is unavailable in this distribution. Container build and execution
were therefore not validated. Live PostgreSQL and live Metasploit RPC were not
tested; no RPC service or credentials were available. There is no active scanning,
payload/exploit automation, or measured 60% improvement claim.
