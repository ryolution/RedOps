# RedOps requirement and acceptance record

This matrix maps the supplied `project.txt` specification (sections 1–13 and its
final expected result) to the repository. The approved implementation scope is a
single-operator defensive assessment product. Excluded original requirements
remain unmet; they are never counted as completed. Test counts describe tested
behavior, not compliance with the complete offensive specification.

Statuses: **implemented** = delivered with automated checks; **awaiting validation**
= external acceptance evidence is still needed; **remaining** = approved work is
not delivered; **excluded** = outside the approved implementation scope.

## Original requirements

| ID / source | Requirement | Status | Implementation / automated evidence | External acceptance evidence |
| --- | --- | --- | --- | --- |
| O01 / 1, 5, 6, 8, 12 | Modular Python architecture, typed domains, documented interfaces | implemented | `redops/`, `docs/architecture.md`, provider tests | None |
| O02 / 1, 6, 8 | Bash entry points, Linux/Kali operation | implemented | `scripts/demo.sh`, `scripts/check.sh`, Docker CI | Fresh installation checklist |
| O03 / 2, 6, 12 | Configuration, exceptions, operational logging | implemented | `core/config.py`, `core/errors.py`, CLI tests | None |
| O04 / 2 | Scope declaration, authorization attribution, allowlists, expiry | implemented | `core/scope.py`, parser/scope and scan tests | Operator supplies current engagement scope; attribution is not identity verification |
| O05 / 2, 12 | Audit events, secret handling | implemented | `core/audit.py`, workflow/API failure tests | Deployment storage controls |
| O06 / 2 | Dry-run | implemented | Workflow and scan preview tests | None |
| O07 / 2, 4 | Operator approval before exploitation | excluded | No exploitation interface | Original requirement remains unmet |
| O08 / 3, 4.1 | Automatic CIDR host discovery | excluded | Scan requires explicit private/loopback IPs | Original requirement remains unmet |
| O09 / 4.1, 6.2 | Execute Nmap scans and record ports | implemented | `recon/nmap.py`, process tests, twelve-service lab CI | Live bounded TCP inventory passed |
| O10 / 4.1 | Active service/version/OS fingerprinting | excluded | No service probes or OS fingerprinting | Original requirement remains unmet |
| O11 / 4.1, 6.2 | Parse XML; normalize hosts, ports, services, versions and OS observations | implemented | `recon/parser.py`, parser tests | None |
| O12 / 4.2, 6.3 | Correlate explicit CPE identities with reviewed vulnerability evidence | implemented | `intelligence/cve.py`, `matcher.py`, intelligence tests | Review actual applicability in each engagement |
| O13 / 4.2 | Infer product identity/CPE automatically from ambiguous names and versions | excluded | Unknown identity stays unknown | Original requirement remains unmet |
| O14 / 4.2, 6.3 | CVE lookup, CVSS extraction/ranking, NVD and local cache | implemented | `intelligence/nvd.py`, NVD/cache tests | Live exact-CVE advisory lookup passed |
| O15 / 3, 4.2, 6.3 | Exploit-reference search, exploit/module matching and ranking | excluded | No exploit catalog or module selector | Original requirement remains unmet |
| O16 / 4.2 | Numeric confidence for exploit compatibility | excluded | No invented confidence scores | Original requirement remains unmet |
| O17 / 4.3, 6.4 | Metasploit RPC client abstraction and authentication | implemented | `metasploit/rpc.py`, `health.py`, mocked RPC tests | See O18 |
| O18 / 4.3 | Live Metasploit connection verification | awaiting validation | TLS/authentication/version/logout adapter | Operator-configured local RPC endpoint; successful sanitized health record |
| O19 / 4.3, 6.4 | Module search, metadata extraction, CVE matching, configuration | excluded | Health interface permits only login/version/logout | Original requirement remains unmet |
| O20 / 4.3, 4.5 | Execution monitoring and exploitation evidence collection | excluded | No execution or session control | Original requirement remains unmet |
| O21 / 4.4, 6.5, 8 | Payload templates/database, compatibility and generation interface | excluded | No payload module | Original requirement remains unmet |
| O22 / 4.5, 5, 9 | Assessment workflow orchestration | implemented | `core/workflow.py`, CLI/workflow tests | Offline end-to-end demonstration passed |
| O23 / 4.5 | Exploit preparation, approval and lab execution workflow | excluded | Assessment workflow has no offensive stages | Original requirement remains unmet |
| O24 / 6.6 | JSON, HTML and PDF assessment reports | implemented | `reporting/`, report/PDF/API tests | None |
| O25 / 6.6 | Recommended exploitation modules in reports | excluded | Reports contain candidate evidence and remediation | Original requirement remains unmet |
| O26 / 7 | SQLAlchemy, SQLite and PostgreSQL persistence | implemented | `database/`, transaction and live PostgreSQL tests | Disposable PostgreSQL round trips passed |
| O27 / 7 | Host, service, vulnerability and action records | implemented | Assessment-scoped normalized tables and immutable snapshots | None; schema is not an exact copy of the original sketch |
| O28 / 7 | Exploit-module table and execution-result fields | excluded | No exploit records | Original requirement remains unmet |
| O29 / 8, 9 | Installable repository and CLI command families | implemented | Packaging, CLI and CI checks | Fresh installation checklist |
| O30 / 5, 12 | Authenticated assessment API | implemented | `api/app.py`, authentication and download tests | Single operator; token accesses all engagements |
| O31 / 13 | Interactive assessment dashboard | remaining | Approved dashboard batch | Browser journey and screenshot evidence |
| O32 / 10 | Reproducible lab with at least ten vulnerable targets | excluded | Twelve healthy services are a separate inventory fixture | Original vulnerable-target requirement remains unmet |
| O33 / 11 | Benchmark calculation and comparison output | implemented | `reporting/benchmark.py`, arithmetic tests | Real measurements still required |
| O34 / 11, final | Demonstrated greater-than-60% time reduction | awaiting validation | No improvement claim; measurement protocol documented | Operator-recorded paired timings; original offensive benchmark remains excluded |
| O35 / 12 | Unit tests, mocks and real integration boundaries | implemented | Parser, advisory, health and scan interfaces; CI matrix | Live RPC evidence remains pending |
| O36 / 12 | Dockerfile, Compose and installation guide | implemented | Docker/lab CI, `docs/installation.md` | Fresh installation and recovery checklist |
| O37 / 13, final | Portfolio presentation and final validation evidence | remaining | README and current validation record | Final dashboard screenshots and acceptance record |

## Approved additions and completion work

| ID | Deliverable | Status | Evidence / gate |
| --- | --- | --- | --- |
| A01 | Portable backup/restore, explicit migration, retention | implemented | Maintenance and live PostgreSQL tests; `docs/database.md` |
| A02 | Normalized JSON inventory with provenance | remaining | XML/JSON equivalence and invalid-input tests |
| A03 | Catalog validation, freshness warnings and match explanation | remaining | Catalog CLI and coverage tests |
| A04 | Append-only finding reviews and stale-edit protection | remaining | CLI/API, migration, backup/retention and concurrency tests |
| A05 | Single-operator browser authentication and dashboard | remaining | Session/CSRF tests and browser acceptance |
| A06 | Optional reviewed reports and Unicode fonts | remaining | Old/new report compatibility and multilingual rendering |
| A07 | Offline diagnostics and reproducible release dependencies | remaining | No-side-effect doctor tests; locked CI/container installation |
| A08 | Paired-trial evaluation tooling | remaining | Cohort validation, unsuccessful-trial retention and arithmetic tests |
| A09 | Live RPC and real manual timing evidence | awaiting validation | Operator input; mocks cannot satisfy acceptance |

## Acceptance rules

The product remains named **RedOps**. Internal schema/package identifiers are
technical metadata. Existing immutable assessments and CLI/API behavior remain
compatible. New storage features require explicit migration, preceded by a backup.

Software acceptance requires passing regression, PostgreSQL, browser, package and
container checks for the included functionality. External acceptance additionally
requires a real local RPC health check and genuine manual/RedOps trials. Missing
external inputs are reported as pending, never replaced with generated evidence.
Excluded original requirements remain unmet even after software acceptance.

The separate audit log and original inventory/scope/report files are not included
in database archives. Deployment backup policies must cover those artifacts too.
