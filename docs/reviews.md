# Operator finding reviews

Assessment snapshots remain immutable. Review events record subsequent operator
judgments and are stored separately. A review never changes the original candidate
status, evidence, or CVSS score. Decisions are `needs_review`, `affected`,
`not_affected`, `accepted_risk`, or `remediated`. Decisions other than `needs_review`
require explanatory notes; notes are limited to 10,000 characters.

```bash
redops review list --assessment ASSESSMENT_UUID
redops review list --assessment ASSESSMENT_UUID --finding FINDING_KEY
redops review add --assessment ASSESSMENT_UUID --finding FINDING_KEY \
  --disposition not_affected --notes 'Installed backport verified against vendor evidence' \
  --expected-previous 0
```

The first command returns stable finding keys and their latest review. Keys derive
from the assessment ID, host, protocol, port, and vulnerability identifier. Use
`0` for an initial review, or the latest returned review ID for a subsequent
decision. A stale expected ID is rejected; reload the history before resubmitting.
Histories are newest-first and support `--limit` (1–100) and `--offset`.

The local CLI attributes reviews to the OS account. API reviews use the server's
`REDOPS_OPERATOR` value, defaulting to its OS account; the request cannot override
the actor. This is a single-operator application, not a multiuser identity system.

Both API routes require the existing bearer token:

| Method / route | Result |
| --- | --- |
| `GET /assessments/{uuid}/findings/{key}/reviews` | History, latest ID, pagination and write availability |
| `POST /assessments/{uuid}/findings/{key}/reviews` | Append a decision; HTTP 201 |

POST body: `{"disposition":"affected","notes":"Evidence reviewed","expected_previous":0}`.
Unknown fields are rejected. Stale edits return 409; unknown assessments/findings
return 404; invalid input returns 422. Storage, audit, or missing-migration errors
return 503. The review and its database action record commit together. A later
JSONL audit failure explicitly reports a completed operation.

New databases use schema 3. Existing schemas 1 and 2 remain readable and support
assessment storage. Reading review history returns an empty, non-writable history
until an explicit backed-up migration runs. `database migrate` chains the history
index and review-table upgrade in one transaction. Current backups include review
events; older archives restore with empty review history. Retention deletes review
events together with their parent assessment. No API deletes or rewrites reviews.
