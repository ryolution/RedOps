# Live RPC health evidence

Configure an operator-managed local Metasploit RPC service and its trusted HTTPS
certificate through `REDOPS_MSF_URL`, `REDOPS_MSF_USERNAME`, `REDOPS_MSF_PASSWORD`
and optionally `REDOPS_MSF_CA_FILE`. Keep credentials in environment/secret storage,
outside the repository and chat. RedOps verifies TLS and permits only
`auth.login`, `core.version` and `auth.logout`.

Record the actual service deployment and version in an environment manifest,
assign a nonsecret environment ID and operator pseudonym, then run:

```bash
redops metasploit status --evidence reports/rpc-health.json \
  --environment local-rpc-lab --operator-pseudonym operator-a
```

The destination must be new. Successful evidence includes UTC start/end times,
elapsed health-check duration, Python/platform metadata, sanitized RPC version
metadata, authentication/version/TLS/logout outcomes, and a hash of a configured
CA file. It omits endpoint URLs, credential values, session tokens and CA paths.
Known credential/session values reflected in server metadata are redacted.
The health duration is not a benchmark assessment timing.

A failed health check writes a sanitized failed record and exits 2. Unconfirmed
steps remain `not_confirmed`; partial success never becomes a passing record.
Inspect local service configuration and retry with a new output path. If version
retrieval and logout both fail, the error explicitly states that cleanup could
not be confirmed. Requests have a ten-second timeout and a 1 MiB response limit.
There is no TLS verification bypass or general RPC execution interface.

The existing `redops metasploit status` output and `--mock` demonstration remain
available. `--mock --evidence` is rejected: a mock cannot create live acceptance
evidence. The server's actual identity and environment require operator attestation;
a conforming RPC response alone does not prove it is the intended Metasploit instance.

Regression tests use a temporary controlled HTTPS server and generated test
certificate to verify trust, authentication, version retrieval and logout. They also
exercise invalid credentials, untrusted certificates, unavailable endpoints, malformed
and oversized responses, transport timeouts and cleanup failures. Those controlled
fixtures validate adapter behavior; they do not satisfy live Metasploit acceptance.

After a genuine run, inspect the sanitized record and environment manifest before
publishing them. Until both exist, the requirement matrix keeps live RPC validation
pending. No successful live Metasploit record is included in this repository.
