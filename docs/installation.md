# Installation and operation

Use a supported Linux Python (3.11, 3.13 or 3.14). Select the matching lock below;
this example uses Python 3.13. See [release and recovery](release.md) for Windows
Docker Desktop/WSL and installed-wheel instructions. From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r requirements/linux-py3.13-dev.txt
python -m pip install --no-deps --no-build-isolation -e .
redops --help
```

On Debian/Ubuntu, if venv reports that ensurepip is unavailable, install the
matching Python venv package through your system package manager first. On
Windows PowerShell activate with `.venv\Scripts\Activate.ps1`.

Run the complete offline demonstration:

```bash
redops workflow run \
  --scope labs/demo-scope.yaml \
  --input labs/demo-nmap.xml \
  --catalog labs/demo-catalog.json \
  --output-dir reports
redops inventory
redops report --format html --output reports/latest.html
```

The workflow exports JSON, HTML, and PDF reports. Open HTML directly in a browser,
or export a saved assessment using
`redops report --format pdf --output reports/latest.pdf`. PDF generation uses no
browser or remote resources. Bundled DejaVu Sans fonts support accented Latin
and shaped Arabic text. Unsupported glyphs appear as explicit Unicode escapes;
JSON retains the original text. PDF input is limited to 2 MiB of assessment data;
use HTML/JSON for larger documents.
Add `--include-reviews` to export subsequent operator decisions with an explicit
review revision and export timestamp; original observations remain unchanged.

Preview without database writes, report files, or network requests:

```bash
redops analyze \
  --scope labs/demo-scope.yaml \
  --input labs/demo-nmap.xml \
  --catalog labs/demo-catalog.json \
  --dry-run
```

Dry-run still writes audit events. `--output-dir` with `--dry-run` is rejected.
All successful commands emit JSON to stdout. Errors go to stderr and exit with
status 2. `--help` and `--about` do not initialize storage. Repeated assessments
produce distinct historical snapshots; they do not overwrite earlier inventories.
`inventory` and `report` default to the most recent assessment across engagements;
specify `--assessment UUID` when working with multiple engagements.

## Configuration

| Environment variable | Default / purpose |
| --- | --- |
| `REDOPS_DATABASE_URL` | `sqlite:///data/redops.db` |
| `REDOPS_AUDIT_PATH` | `data/audit.jsonl` |
| `REDOPS_MSF_URL` | `https://127.0.0.1:55553/api/1.0` |
| `REDOPS_MSF_USERNAME` | Required only for the health check |
| `REDOPS_MSF_PASSWORD` | Required only for the health check; supply through your secret store |
| `REDOPS_MSF_CA_FILE` | Optional trusted CA bundle for the health service |
| `REDOPS_NVD_API_KEY` | Optional NVD API key, sent only in the HTTPS request header |
| `REDOPS_NVD_CACHE` | `data/nvd-cache`; validated advisory cache |
| `REDOPS_API_TOKEN` | Required shared token for the dashboard and API |
| `REDOPS_OPERATOR` | Server-side review attribution; defaults to the OS account |
| `REDOPS_UI_ALLOW_HTTP` | Default `0`; explicit loopback Docker development only |

Global `--database`, `--audit`, and `--verbose` flags precede the subcommand. Environment
configuration is preferred for database URLs containing credentials. Protect the
database, scope declarations, reports, and audit log with OS access controls.
The CLI uses the OS account. The optional API uses shared-token authentication;
neither interface provides multiuser roles or per-engagement access control.
Input, database, audit, and report paths must be distinct; conflicting paths and
existing filesystem aliases are rejected before the relevant write.
Do not commit assessment data or secrets. Audit files use mode 0600 when created
on platforms that enforce POSIX permissions; mounted Windows paths may differ.

SQLite databases initialize automatically only after an assessment passes input
validation. `redops init` explicitly initializes an empty database. Use
`redops database status` to check compatibility and row counts. Backups, empty
database restores, explicit schema upgrades, and retention previews are available
through `redops database`; see [database maintenance](database.md). No automatic
schema upgrade or deletion runs.

For PostgreSQL, install `python -m pip install -e '.[postgres]'`, configure an
existing database via `REDOPS_DATABASE_URL=postgresql+psycopg://...`, then run
`redops init`. The SQLAlchemy models use portable types; live PostgreSQL deployment
must be tested for your deployment. The container includes the PostgreSQL driver.

## Evidence catalog

Follow `labs/demo-catalog.json`. For real data use `kind: "reviewed"` in JSON and
actual CVE identifiers, HTTPS advisory sources, remediation text, and an explicit
timezone-aware update timestamp. Records declare exact affected CPEs. CVSS may be
`null` when unavailable; unknown severity is retained instead of guessing.

Supported CPE inputs are simple `cpe:/` URI bindings and `cpe:2.3:` formatted
strings with concrete vendor, product, and version. Escaped components, ranges,
packed editions, and unspecified versions are not supported. Matching is exact
after binding normalization, including remaining CPE attributes. Product names,
service banners, and open ports alone do not create findings. Validate applicability,
distribution backports, runtime configuration, and catalog freshness during review.

NVD provides advisory context for existing CVEs. It does not replace the reviewed
local evidence needed to establish candidate applicability.

```bash
redops intelligence lookup --cve CVE-2021-44228
redops intelligence lookup --cve CVE-2021-44228 --offline
redops intelligence lookup --cve CVE-2099-0001 --mock
```

The mock identifier and response are fictional and marked `provider: mock`.
Live records are cached for 24 hours; offline cache misses and expiry fail
explicitly. Mock records cannot enter the live cache. Requests use verified TLS,
15-second timeouts, a 4 MiB response limit, six-second pacing per transport
instance, and at most three attempts for HTTP 429/500/502/503/504. Separate
processes must coordinate their API usage externally. Redirects are refused.

Add `--nvd online` or `--nvd offline` to a workflow using a reviewed catalog to
attach distinct CVE advisories to the report. `--cache DIRECTORY` overrides the
cache location. Enrichment preserves catalog-derived finding scores and stores
NVD scores, provider, and retrieval timestamps separately. Dry-run rejects `--nvd`;
it only uses the local catalog. Unknown or unavailable scores remain unknown.

## Metasploit health integration

After configuring credentials and a trusted TLS endpoint, run:

```bash
redops metasploit status
redops metasploit status --mock
```

For sanitized live records, use the [RPC validation procedure](rpc-validation.md).
Paired task measurements and their separate external acceptance gate are described
in [benchmark evaluation](benchmark.md).

The adapter uses the [Rapid7 MessagePack RPC contract](https://docs.rapid7.com/metasploit/rpc-api/)
to log in, request `core.version`, and log out. Only version, Ruby, and API metadata
are returned. Requests time out after 10 seconds, responses are bounded, and
redirects are refused. Self-signed certificates require a trusted CA file; there
is no option to disable verification. No live RPC server is bundled or required
for the offline assessment.

`AdvisoryProvider`, `NvdTransport`, `InventoryParser`, and `HealthProvider` expose
typed contracts. `MockAdvisoryProvider`, `MockInventoryParser`, and
`MockMetasploitClient` provide explicit offline implementations for tests and
demonstrations. `ScanRunner` and `MockScanRunner` provide the corresponding
execution boundary for the separate inventory command.

## Private lab TCP inventory

Install Nmap through your operating system package manager, or use the optional
`inventory` Docker build target. The command uses unprivileged TCP connect calls
and accepts only explicit private/loopback IPv4 addresses within a current scope.
Supply one to sixteen hosts and one to thirty-two distinct TCP ports:

```bash
redops scan --scope /path/to/current-scope.yaml --target 127.0.0.1 \
  --ports 8080 --output reports/local-inventory.xml --dry-run
redops scan --scope /path/to/current-scope.yaml --target 127.0.0.1 \
  --ports 8080 --output reports/local-inventory.xml
```

The example requires a declaration allowing `127.0.0.1/32` and a service you own.
Repeat `--target` or use `--targets-file` with one literal IP per line; blank lines
and lines starting with `#` are ignored. DNS names, CIDR expansion, arbitrary
Nmap arguments, scripts, and service fingerprinting are unavailable. The command
records reachability, with service names only guessed from the port table.
There is no automatic assessment, advisory lookup, or RPC action after scanning.
Existing XML output is never overwritten. Preview writes only audit events and
does not require Nmap. A completed result lists targets without observed open
ports explicitly; it is not a finding that these hosts are secure or absent.

See the [twelve-service inventory lab](../labs/inventory/README.md) for a running
Docker example isolated from external networks.

## Container demonstration

```bash
docker compose run --rm redops
docker compose run --rm redops inventory
```

The Compose service uses no network, runs as an unprivileged user, and stores
assessments/reports in named volumes. This runs the same synthetic workflow; it
does not deploy vulnerable services. CI and container builds consume hash-pinned dependency files. Container bases
are pinned by digest; see [dependency locks](../requirements/README.md). The included CI workflow
runs linting, regression tests, and a package build on Python 3.11, 3.13, and 3.14.

## Development checks

```bash
ruff check .
ruff format --check .
pytest
python -m build --no-isolation
python scripts/check_distribution.py
```

See [the local validation record](validation.md) for completed checks and the
external integrations that still require environment-specific validation.
