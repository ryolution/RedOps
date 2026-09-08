# Running inventory lab

This lab creates twelve healthy HTTP services on an internal Docker network.
They expose `/health` and `/metadata`, have no published host ports, run without
Linux capabilities, and use read-only filesystems. No intentionally vulnerable
software or vulnerability banners are included.

From the repository root, with Docker Compose available:

```bash
docker compose -f labs/inventory/compose.yaml up --build --wait
docker compose -f labs/inventory/compose.yaml run --build --rm scanner --about
docker compose -f labs/inventory/compose.yaml run --rm scanner scan \
  --scope labs/inventory/scope.yaml --targets-file labs/inventory/targets.txt \
  --ports 8080 --output /data/inventory.xml --dry-run
docker compose -f labs/inventory/compose.yaml run --rm scanner
```

The last command makes real TCP connections to the twelve services and stores
Nmap XML in the lab's `inventory-data` volume. The JSON result should contain
twelve hosts with TCP port 8080 open. Service names come from Nmap's port table;
they do not establish product versions, CPEs, or vulnerabilities. No service
probes, scripts, OS fingerprinting, CVE lookup, or RPC calls run during scanning.

The subnet is `172.30.77.0/24`; change the Compose addresses, scope, and target
file together if it conflicts with a local network. The sample scope authorizes
only the twelve fixture IPs and has a long expiry for reproducibility. Use it
only for these containers. Real engagements need their own current declaration.

An existing XML file is never overwritten. For another run, override the scanner
command with `scan ... --output /data/another-inventory.xml`, or choose a fresh
Compose project using `-p`. Copy results before removing volumes:

```bash
mkdir -p reports
docker compose -f labs/inventory/compose.yaml run --rm --entrypoint cat scanner \
  /data/inventory.xml > reports/inventory.xml
docker compose -f labs/inventory/compose.yaml down --volumes
```

`down --volumes` removes this lab's stored XML and audit data. The offline
synthetic assessment remains available independently via the main README.
