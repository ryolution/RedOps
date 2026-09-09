# Database maintenance

Maintenance runs through the local CLI under the operator's OS account. The dashboard/API append finding review annotations; maintenance remains CLI-only. SQLite and PostgreSQL use the same portable archive
format and maintenance commands:

```bash
redops database status
redops database backup --output data/backups/before-maintenance.json
redops --database sqlite:///data/restored.db database restore \
  --input data/backups/before-maintenance.json
redops --database sqlite:///data/restored.db assessments
```

Restore the archive into a separate empty database first and verify its reports.
The command refuses to replace existing RedOps records. Invalid archives are
rejected before opening the destination. A database constraint failure rolls back
all restored records; an empty initialized schema may remain. PostgreSQL serial
sequences are adjusted so subsequent assessments can be inserted normally.

## Backups

An archive contains all RedOps assessment snapshots, normalized observations,
findings, action records, append-only finding reviews, and the source schema marker. One consistent read
transaction covers all tables. SQLite uses an explicit snapshot transaction;
PostgreSQL uses repeatable-read isolation. Output is written completely before
being published, and an existing archive path is never overwritten.

Archives use JSON with a SHA-256 checksum over canonical content. Validation checks
the format, supported schema, table/column names, row types, snapshot attribution,
size, and checksum. Restore uses parameterized inserts into fixed application
tables and database constraints. It never executes SQL supplied by an archive.
The checksum detects corruption; it is not a signature or proof of provenance.
Restore only trusted backups produced by your deployment.

The limits are 64 MiB per archive and 100,000 total rows. Larger databases need
native database backup tooling. The archive covers RedOps application tables,
not other tables, database roles, grants, extensions, or server configuration.
It excludes the separate JSONL audit file, NVD cache, exported reports, inventory
XML/JSON, evidence catalogs, and scope files; include these in your deployment's backup policy separately.
Archives contain assessment data and are unencrypted. Store them with access
controls and encryption appropriate to the engagement; keep copies off the host.

## Schema upgrades

New databases initialize with schema 3. Existing schema 1 and 2 databases remain
readable and writable without an implicit upgrade. The explicit migration adds
a composite index on engagement, creation time, and assessment ID to support
filtered history queries, then adds the append-only finding review table.
It preserves all snapshots and observations:

```bash
redops database status
redops database migrate --backup data/backups/before-schema-upgrade.json
redops database status
```

The upgrade holds a writer lock, creates a backup, and applies the index and
schema marker together in a transaction. Running it on the current schema is a
no-op and creates no backup. Unknown schemas or missing/incompatible required
columns fail explicitly. Restoring a supported older archive initializes the
destination with the current schema; report snapshot formats are preserved.
There is no automatic downgrade.

## Retention

Retention is engagement-specific and previews changes by default. For example,
adjust the engagement and past cutoff to your actual retention policy:

```bash
redops database prune --engagement my-engagement \
  --before 2026-01-01T00:00:00Z --keep-latest 2
redops database prune --engagement my-engagement \
  --before 2026-01-01T00:00:00Z --keep-latest 2 \
  --apply --backup data/backups/before-retention.json
```

The command always retains at least the newest assessment in the engagement,
even if it predates the cutoff. Assessments exactly at the cutoff are retained.
Other engagements are unaffected. The preview lists eligible IDs and counts;
it appends audit events but creates no archive and deletes no database records.

Applying retention recomputes eligibility while holding a writer lock, saves a
complete backup, then removes the selected snapshots and dependent rows in one
transaction. A backup failure prevents deletion; a deletion failure rolls back
the entire batch. There are at most 1,000 deletions per invocation, and an
engagement can contain at most 10,000 assessments for this command. Repeat with
a new archive path if eligible records remain. A no-op deletes nothing and
creates no archive.

PostgreSQL maintenance uses a five-second lock timeout and thirty-second statement
timeout. SQLite uses its driver's lock timeout. Maintenance can temporarily delay
assessment writers; schedule it appropriately. The separate audit append is not
atomic with the database. Errors after successful commit explicitly report that
the operation completed. A failed operation may leave a complete backup archive;
archives are never automatically deleted.
