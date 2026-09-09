# Inventory evidence

`analyze` and `workflow run` accept `--input-format nmap-xml` (the default) or
`--input-format inventory-json`. Both validate scope before creating a database.
The JSON importer consumes operator-supplied observations; it makes no target
connections and does not infer software, versions, or OS from a port number.

```json
{
  "schema": "redops-inventory",
  "schema_version": 1,
  "collected_at": "2026-01-01T12:00:00Z",
  "source": "Operator-maintained inventory export",
  "hosts": [{
    "ip": "127.0.0.1",
    "addresses": ["127.0.0.1"],
    "hostname": "local-fixture",
    "os": "",
    "services": [{
      "port": {"number": 8080, "protocol": "tcp"},
      "name": "http",
      "product": "",
      "version": "",
      "cpes": []
    }]
  }]
}
```

All shown fields are required. Unknown text is an empty string; unknown CPEs use
an empty list. Unsupported CPE strings are retained as observations and counted
as coverage gaps. Collection times must include a timezone. Files are limited
to 8 MiB, 512 hosts, 128 addresses per host, 4096 services per host, and 100 CPEs
per service. Duplicate hosts/ports/JSON keys and unexpected fields are rejected.
Every address, including secondary addresses, must be inside the engagement scope.

Snapshots retain the input format, SHA-256, JSON source description and collection
time. Legacy XML snapshots retain their `nmap_sha256`; new JSON inputs do not
mislabel their hash as XML. Existing snapshots remain readable.

Validate a catalog independently:

```bash
redops intelligence catalog validate --input labs/demo-catalog.json
```

The response includes record/CPE counts and freshness warnings. Catalogs older
than thirty days, or with future update times, receive warnings. Records are
retained. Exact matched CPEs and catalog sources remain attached to each candidate;
ambiguous product identity is not automatically promoted into a match.
