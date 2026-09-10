# Installation and recovery acceptance

Use Linux/Kali with Python 3.11, 3.13 or 3.14. Windows users can run these Linux
instructions in WSL, or enable Docker Desktop's Linux container engine and run
the documented Compose commands from PowerShell or WSL. The supplied dependency
locks target Linux x86_64; a native Windows pip resolution is not a release gate.

## Clean installation

Clone the repository, create and activate a virtual environment with the chosen
Python, then select its matching lock (Python 3.13 shown):

```bash
python -m pip install --require-hashes -r requirements/linux-py3.13-dev.txt
python -m build --no-isolation
python -m pip install --no-deps dist/*.whl
python scripts/check_distribution.py
redops doctor
redops workflow run --scope labs/demo-scope.yaml --input labs/demo-nmap.xml \
  --catalog labs/demo-catalog.json --output-dir reports
```

`check_distribution.py` checks wheel/source assets and runs the installed wheel
from a temporary directory. It verifies the offline workflow, reports, dashboard
login and backup restore. The [RedOps logo](branding.md), fonts and notices are
bundled; rendering never downloads resources. A runtime-only install uses the
matching `-runtime.txt` and a previously built wheel. For air-gapped installation,
first download all locked wheels into a wheelhouse, transfer the wheelhouse and
RedOps wheel, then add
`--no-index --find-links /path/to/wheelhouse` to the locked install command.

`redops doctor` reports package/file availability, configuration syntax and local
SQLite schema compatibility without audit writes, storage creation or service
connections. Missing optional Nmap/RPC/dashboard configuration produces attention
items. Invalid configuration or missing required assets produces JSON diagnostics
and exit 2; otherwise it exits 0. Secrets and connection strings are omitted.
PostgreSQL and SQLite databases with active journals require separate live checks;
the command reports that limitation rather than opening a writable connection.

## Dashboard and token rotation

Configure `REDOPS_API_TOKEN` with a secret manager or a generated environment value,
then start `redops serve` and visit `http://127.0.0.1:8000/ui`. Keep one worker.
See [dashboard deployment](dashboard.md) for TLS/proxy configuration and cookie
requirements. Rotate by replacing the environment token and restarting the
application. Restart invalidates existing browser sessions immediately; API clients
must use the new token. Update `REDOPS_OPERATOR` to the intended attribution before
recording review decisions.

## Recovery rehearsal

Stop collection/review writers during planned maintenance. Create a fresh archive,
restore it to a separate empty destination, inspect assessment/review history, and
render an annotated report before switching application configuration:

```bash
redops database backup --output data/backups/recovery-rehearsal.json
redops --database sqlite:///data/rehearsal.db database restore \
  --input data/backups/recovery-rehearsal.json
redops --database sqlite:///data/rehearsal.db assessments
redops --database sqlite:///data/rehearsal.db report --include-reviews \
  --format pdf --output reports/restored.pdf
```

Archives include assessments, normalized observations, action records and review
history. Older archives restore with an empty review history. Protect and back up
the **separate audit JSONL, original XML/JSON inventory, scope declarations, evidence
catalogs, reports, NVD cache, secret-manager configuration and deployment settings**
according to engagement policy; the database archive does not contain them. Store
credentials separately from the repository and database archives.

For an old supported schema, run `redops database migrate --backup FILE`. Migration
backs up under the writer lock and commits its DDL/schema marker transactionally.
On interruption, check `database status` before retrying. An error after a successful
commit says so explicitly. Do not replay a completed action blindly. If recovery is
needed, restore the preserved archive into another empty database and validate it;
the tool refuses to overwrite existing records. Unsupported/corrupt schemas require
inspection and a known-good backup, not guessed SQL changes.

Retention always starts with a preview. Supply the exact engagement, cutoff and
minimum number to keep, inspect eligible IDs, then use `--apply --backup FILE` with
a new archive path. Dependent review rows are removed transactionally with their
assessments. See [database operation](database.md) for limits and failure behavior.

## Browser and release checks

```bash
python -m playwright install --with-deps chromium
REDOPS_BROWSER_TESTS=1 pytest tests/browser -W error
bash scripts/check.sh
```

Browser tests run against a disposable loopback server and synthetic assessments.
They cover centered login, keyboard navigation/review, desktop and 320/390/430-pixel
layouts, local assets, filters, pagination, escaped imports, session expiry and
all downloads through the export menu, including Escape and focus restoration.
They also exercise the responsive sidebar and verify that assessment summary
counts remain consistent after a review and when filtering the findings table.
Mobile checks include bottom navigation, repeated report access, long imported
values without horizontal scrolling, readable table semantics, and navigation
and report downloads with JavaScript disabled. Screenshot fixtures include mobile
history, inventory, findings, review, and the sidebar.
The [desktop assessment](images/dashboard-desktop.png),
[narrow assessment](images/dashboard-mobile.png),
[desktop review](images/review-desktop.png) and
[narrow review](images/review-mobile.png) images show those synthetic fixtures.

CI additionally validates all supported Python versions, PostgreSQL maintenance,
the installed wheel, the offline container and the twelve healthy inventory
services. Live Metasploit health and genuine paired benchmark evidence are separate
external acceptance gates. Passing these software checks does not fulfill the
excluded original offensive requirements in [the matrix](completion.md).
