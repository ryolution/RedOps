# RedOps
Offensive Automation Toolkit


RedOps provides scoped inventory and vulnerability evidence assessment. It imports
Nmap XML, correlates exact CPEs against reviewed evidence, retrieves NVD advisory
context, preserves assessment history, and produces JSON, HTML, and PDF reports.
An authenticated browser dashboard and API serve existing assessments and
append operator review decisions.

## Run the offline demonstration

Python 3.11 or newer is required. No Nmap installation, API key, Metasploit server,
or running target machine is needed for this demonstration.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
redops workflow run \
  --scope labs/demo-scope.yaml \
  --input labs/demo-nmap.xml \
  --catalog labs/demo-catalog.json \
  --output-dir reports
redops inventory
redops assessments
redops report --format pdf --output reports/latest.pdf
```

Expected result: 12 synthetic hosts and 8 fictional candidate findings. Reports
label the evidence as synthetic. Real assessment data requires an engagement's
scope declaration, previously collected Nmap XML, and reviewed evidence catalog.

## Implemented components

| Component | Functionality |
| --- | --- |
| Core | Scope declarations, expiry checks, audit events, dry-run, bounded input |
| Recon | Nmap XML import and bounded TCP inventory of scoped private lab hosts |
| Intelligence | Evidence correlation, CVSS ranking, NVD lookup, retries, cache |
| Database | SQLite/PostgreSQL history, portable backup/restore, migration, retention |
| Metasploit | Verified-TLS RPC health check and explicit offline mock |
| Reporting | JSON, HTML, paginated PDF, measured benchmark calculations |
| Dashboard / API | Browser sessions, filters, review history, report downloads, bearer API |
| Delivery | Regression tests, CI matrix, PostgreSQL and container integration jobs |

```bash
redops intelligence lookup --cve CVE-2021-44228
redops intelligence lookup --cve CVE-2021-44228 --offline
redops intelligence lookup --cve CVE-2099-0001 --mock
redops metasploit status --mock
```

NVD enrichment is optional and separate from applicability evidence. Findings
remain candidates requiring review. Dry-run writes audit events but never
contacts external services or writes database/report files.

## Documentation

- [Architecture and repository boundaries](docs/architecture.md)
- [Installation, CLI, configuration, and deployment](docs/installation.md)
- [Inventory evidence formats](docs/inventory.md)
- [Requirement and acceptance record](docs/completion.md)
- [Browser dashboard](docs/dashboard.md)
- [Finding reviews](docs/reviews.md)
- [Authenticated API](docs/api.md)
- [Database backup, restore, migration, and retention](docs/database.md)
- [Synthetic demonstration and benchmark protocol](labs/README.md)
- [Running twelve-service inventory lab](labs/inventory/README.md)
- [Validation record](docs/validation.md)

## Development

```bash
bash scripts/check.sh
docker compose run --rm redops
```

The optional scan command collects bounded TCP inventory in private labs. Its
healthy twelve-service Docker lab provides an isolated live check. Metasploit
integration reports health metadata. Exploit/module selection, payload preparation,
and exploitation are outside the implemented scope. The API uses a shared token
and OS-level storage controls, not multiuser roles. No time-reduction claim is made
without measurements.
