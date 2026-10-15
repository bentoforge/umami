# ADR 0002 — PostgreSQL as a second storage backend

- **Status:** accepted
- **Date:** 2026-10-14

## Context

umami stored everything in DynamoDB and its config catalog in S3. The services umami issues tokens
for are moving to PostgreSQL, and a deployment that already runs a database should not need an AWS
account just for its identity service. The storage seam (`UMAMI_STORAGE`, see `docs/SEAMS.md`) was
built for exactly this: one bundle of repository ports, one backend per
deployment.

## Decision

- **wasabi gets a `postgres` feature** (`wasabi::postgres`): a pooled `Database`
  (`deadpool-postgres` over `tokio-postgres`, TLS via rustls/aws-lc-rs), a thin `Record` + `Table`
  layer for insert / update / upsert / delete / select by column name, and declarative tables.
  Statements are built and bound by `sea-query` rather than by hand. The schema diff is wasabi's
  own: no Rust crate turns a declaration plus the live catalog into a list of changes, so
  `Database::schema_changes` does, as `SchemaChange { label, sql, data_loss_expected }`.
- **`ensure_exists` applies what cannot lose data and withholds the rest.** Creating tables,
  columns and indices and widening types happens on boot, like DynamoDB table creation; dropping a
  column or narrowing a type is logged with its SQL and left to an operator.
- **umami stores each entity whole as `data JSONB`**, with typed, indexed columns only for what
  queries filter or sort on (keys, lookups, `version`, `expires_at`). Reads come from `data`.
- **`UMAMI_STORAGE=postgres` and `UMAMI_CONFIG_STORE=postgres`** share one pool. A set
  `POSTGRES_URL` wins auto-detection for both.
- **The config catalog becomes a row in a `blobs` table**, written under a row lock.

## Alternatives

- **An ORM (SeaORM, Diesel) with versioned migrations.** Migrations as files are the right tool
  for a schema that a team evolves by hand; umami's tables follow from its code, and it already
  provisions DynamoDB tables from code on boot. Versioned migrations would add a second source of
  truth and a deploy step the DynamoDB backend does not have.
- **`sqlx`.** Its compile-time checked queries need a database at build time; the dynamic
  record API umami and dashi want would not use them.
- **Fully normalised tables (one column per entity field).** Every new entity field would become
  a schema change, and the two backends could drift in how they shape an entity. `JSONB` keeps the
  entity shape in one place — the serde struct.
- **Generic auto-migration that also drops.** Convenient until a typo in a column name deletes
  production data.

## Consequences

- The database user needs `CREATE` on its schema. Deployments sharing a database use one schema
  each (`options=-csearch_path`).
- Expiry is umami's job on Postgres: rows carry `expires_at`, reads filter, writes sweep.
- Config saves are now compare-and-swap across instances on Postgres, which S3 could not offer.
- umami needs wasabi 4.4.0 or later, the first release with the `postgres` feature.
