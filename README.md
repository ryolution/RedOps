# RedOps
Offensive Automation Toolkit


RedOps provides scoped inventory and vulnerability evidence
assessment for a local operator. It imports existing Nmap XML, correlates exact
versioned CPEs against reviewed local evidence, stores assessment history using
SQLAlchemy, and exports JSON and self-contained HTML reports. NVD advisory lookup
includes an offline cache and explicit mock providers for integration testing.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
redops workflow run --scope labs/demo-scope.yaml --input labs/demo-nmap.xml --catalog labs/demo-catalog.json --output-dir reports
redops inventory
```

- [Architecture and repository boundaries](docs/architecture.md)
- [Installation, CLI, configuration, and deployment](docs/installation.md)
- [Synthetic demonstration and benchmark protocol](labs/README.md)

The demonstration contains 12 synthetic hosts and fictional findings. No live
scan, exploitation, or measured time-reduction claim is included. Findings remain
candidates requiring human review. Metasploit integration is a separate verified-TLS
version health check; exploit/payload preparation and execution are outside this
implementation. A web API and automated PDF export are not
implemented.

Run `pytest`, `ruff check .`, and `ruff format --check .` for development checks.
