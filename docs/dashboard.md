# Assessment dashboard

Populate the database with the documented offline workflow, configure
`REDOPS_API_TOKEN` through your environment or secret manager, then run:

```bash
redops serve
```

Open `http://127.0.0.1:8000/ui` and sign in with that token. The command enables
HTTP for its default loopback binding only. Existing databases can be browsed
before migration; review forms explain when `redops database migrate` is needed.
Back up the database before migrating; see [recovery instructions](database.md).

The sidebar opens assessment history. Selecting an assessment adds **Overview**,
**Inventory**, **Findings**, and **Reports** navigation for that assessment.
On narrow screens, **Open navigation** reveals the sidebar; Escape, an outside
click, or selecting a destination closes it. Navigation works by keyboard.

The history page filters by exact engagement name. Select an assessment to search
inventory, filter candidate findings by severity or latest review disposition,
and inspect scope, input provenance, evidence and coverage limitations. Lists
contain 25 records per page. Select a finding to append an attributable decision
and read its history. Concurrent edits return a conflict page that retains the
unsaved notes for copying before reloading. Open **Export** for JSON, HTML or PDF
downloads. The **Original** links export the immutable assessment. **Export with
reviews** adds the latest decisions with an export timestamp and review revision.
Press Escape or click outside the menu to close it. **Assessment details** contains
scope, provenance, and interpretation; a finding's **Technical details** contains
matched CPEs, catalog source, and remediation.

The severity and review-status charts always summarize **all candidates in the
assessment**, including when tables are filtered or paginated. Candidates without
a review, or with a latest `needs_review` disposition, count as needing review.
Every other latest disposition counts as a recorded decision; that count is not
a claim that a vulnerability has been fixed. Charts use the stored observations
and latest review records, with no synthetic activity trends added by the UI.

Controls have accessible labels, keyboard focus indicators, and a skip-to-content
link. Tables can be focused and scrolled within their panels on narrow screens.
The login card is centered in the viewport; the logo appears without a wordmark.
The interface uses flat charcoal panels and restrained accents. CSS and JavaScript are
packaged locally; browsing and report generation require no external assets.
Dashboard writes are limited to finding reviews. Collection, imports, migration,
backup and retention use the CLI.

See the [desktop history](images/history-desktop.png),
[mobile history](images/history-mobile.png), [mobile sidebar](images/sidebar-mobile.png),
and [branding guide](branding.md) for
the current layout and design references.

## Sessions and deployment

Run **one application worker**. Browser sessions live in bounded process memory
and expire 30 minutes after creation without renewal. Successful login rotates
the opaque session identifier. Logout, process restart and token rotation followed
by restart invalidate access. Cookies are HttpOnly and SameSite Strict, with
Secure enabled under HTTPS. The token is never stored in a cookie, browser storage
or URL. Browser forms require a session-bound CSRF token and reject foreign origins.
Five unsuccessful sign-ins from one peer within a minute trigger a short throttle.

Outside loopback development, terminate trusted TLS at your reverse proxy and
configure Uvicorn's proxy trust for that proxy only. Do not trust arbitrary
forwarded headers. Restrict direct access to the backend and add proxy rate limits.
`REDOPS_UI_ALLOW_HTTP=1` permits HTTP requests with a loopback hostname for the
Docker Compose API profile, whose published port binds to `127.0.0.1`. Keep that
binding when using this setting. HTTPS deployments leave it unset.

`REDOPS_OPERATOR` sets the server-side review attribution (default: OS account).
This is a single-operator product: the shared token grants access to every stored
engagement. Existing API clients continue to use bearer authentication; browser
cookies do not authenticate API routes. Expired sessions return to login, and
unavailable database/audit storage produces a diagnostic page without exposing
connection credentials.
