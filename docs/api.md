# Assessment API

The API reads assessments created by the CLI and appends operator review
annotations. Collection and database maintenance remain CLI operations.
See [finding reviews](reviews.md) for the authenticated annotation routes.

```bash
export REDOPS_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
redops serve
```

The default bind address is `127.0.0.1:8000`. Configure TLS and request-rate limits
at a reverse proxy before exposing it beyond a trusted local connection. Supply
the token through your secret manager for persistent deployments; rotating the
environment value and restarting the process revokes the previous token.

The service uses a single shared bearer token, not a multiuser identity provider.
Anyone holding that token can read all engagements in the configured database.
Tokens must contain 32–4096 characters and must not be supplied in query strings.
Invalid tokens return 401. Token values are never included in audit records.
The API disables request access logs and public OpenAPI/Swagger endpoints.

| Method / route | Authentication | Result |
| --- | --- | --- |
| `GET /health` | None | Process liveness only; no storage access |
| `GET /ready` | Bearer token | Database schema and audit readiness |
| `GET /assessments` | Bearer token | Paginated assessment summaries |
| `GET /assessments/{uuid}` | Bearer token | Complete assessment document |
| `GET /assessments/{uuid}/inventory` | Bearer token | Recorded hosts and services |
| `GET /assessments/{uuid}/report?format=json` | Bearer token | JSON, HTML, or PDF attachment |

`/assessments` accepts `engagement`, `limit` (1–100, default 50), and `offset`
(0–1,000,000). Records are ordered by creation time and ID, newest first. With no
engagement filter, results span all engagements. Unknown UUIDs return 404;
invalid parameters return 422; unavailable database or audit storage returns 503.

Example from Python without putting a secret in the command line:

```python
import json
import os
from urllib.request import Request, urlopen

request = Request(
    "http://127.0.0.1:8000/assessments?limit=10",
    headers={"Authorization": "Bearer " + os.environ["REDOPS_API_TOKEN"]},
)
with urlopen(request, timeout=10) as response:
    print(json.load(response))
```

The API has no cross-origin access policy enabled. Responses use `no-store` and
`nosniff`; reports download as attachments. PDF export is bounded to 2 MiB of
assessment data, while JSON/HTML support larger bounded assessment inputs.

With Docker available, first populate the shared database using the offline
Compose command, then launch `docker compose --profile api up --build api`.
The API profile publishes only on the host's loopback address, uses an internal
container network, and requires `REDOPS_API_TOKEN` in the environment. It does
not initialize an empty database; `/ready` remains unavailable until the CLI
has initialized storage.
