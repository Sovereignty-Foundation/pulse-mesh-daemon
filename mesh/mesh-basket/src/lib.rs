// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `mesh-basket`, tier 2: the SQLite capture store of published envelopes.
//!
//! A daemon started with `--basket-path` writes every published envelope
//! here, and `pms-query` and the MCP server's tools query it: by channel,
//! time window, type and origin, with aggregations, paginated. One SQLite
//! file, trimmed by a [`RetentionPolicy`] sweep on the daemon's timer; not
//! the envelope store, which is shared memory. `dev_functions::basket`
//! re-exports this crate.
//!
//! # What it keeps, and who can read it
//!
//! A row holds the whole envelope as it was published: its id, the time it
//! was captured, its channel, type and type name, its origin, a hash of its
//! payload and the payload's bytes, until the retention sweep drops it. The
//! basket is created for its owner alone, as the daemon's Unix socket is
//! ([`Basket::open`]): the file and SQLite's `-wal`, `-shm` and `-journal`
//! files beside it are mode `0600`, and a directory `open` creates for it is
//! `0700`. A file of an earlier version that grants others access is
//! narrowed to its owner when the basket opens it. A directory that exists
//! already is left as it is: the files' own mode keeps their contents to the
//! owner, while the directory's says who can see their names, so a basket
//! among other users' files belongs in a directory only its owner can
//! enter.
//!
//! In the book: <https://pulse-mesh.net/docs/daemon/architecture/mesh.html>.
#![forbid(unsafe_code)]

use pulse_canon::PulseEnvelope;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;
use thiserror::Error;

/// Errors returned by the basket API.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BasketError {
    /// The SQLite engine failed.
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Creating the basket file's directory, creating the file, or
    /// narrowing an existing file's permissions to its owner failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The [`QuerySpec`] is invalid: a time-bucket aggregate of zero
    /// seconds.
    #[error("invalid query: {0}")]
    InvalidQuery(String),
    /// A thread panicked holding the connection; surface the error rather
    /// than retry on this `Basket`.
    #[error("basket connection mutex poisoned (another thread panicked while holding it)")]
    Poisoned,
}

/// The routing context an insert records beside the envelope.
#[derive(Debug, Clone)]
pub struct CaptureMeta {
    /// Routing key the envelope was published on.
    pub channel: String,
    /// Producer's canonical node name (e.g. `ingest@7f3a`).
    pub origin: String,
    /// `captured_at_unix_nanos`; defaults to `now` if unset.
    pub captured_at_unix_nanos: Option<u128>,
}

impl CaptureMeta {
    /// Channel and origin, stamped with the time of the insert.
    pub fn new(channel: impl Into<String>, origin: impl Into<String>) -> Self {
        Self {
            channel: channel.into(),
            origin: origin.into(),
            captured_at_unix_nanos: None,
        }
    }
}

/// One captured envelope as a basket row.
#[derive(Debug, Clone)]
pub struct EnvelopeRow {
    /// Content-addressed envelope id (hex), the primary key.
    pub id: String,
    /// Wall-clock nanoseconds since the unix epoch at capture time.
    pub captured_at_unix_nanos: u128,
    /// Routing key the envelope was published on.
    pub channel: String,
    /// Numeric envelope type, a `u16` on the wire.
    pub envelope_type: u32,
    /// The type name, when the envelope was published with one.
    pub type_name: Option<String>,
    /// Producer origin string (e.g. `"ingest@7f3a"`).
    pub origin: String,
    /// The first 16 bytes of the payload's BLAKE3 hash, hex.
    pub payload_hash: String,
    /// Raw payload bytes. Encoding is type-dependent.
    pub payload_bytes: Vec<u8>,
}

/// A structured query against the basket: the filters set AND-combine, and
/// one left `None` admits every row.
#[derive(Debug, Clone, Default)]
pub struct QuerySpec {
    /// Rows on this channel.
    pub channel: Option<String>,
    /// Rows of this numeric type.
    pub envelope_type: Option<u32>,
    /// Rows with this type name.
    pub type_name: Option<String>,
    /// Rows from this origin.
    pub origin: Option<String>,
    /// Time window start (inclusive).
    pub since_unix_nanos: Option<u128>,
    /// Time window end (exclusive).
    pub until_unix_nanos: Option<u128>,
    /// Max rows: 0 means 50, and more than 5000 means 5000.
    pub limit: usize,
    /// Optional aggregation; if set, `rows` is empty and `aggregate` is filled.
    pub aggregate: Option<Aggregation>,
}

/// Aggregation modes for `QuerySpec::aggregate`.
#[derive(Debug, Clone)]
pub enum Aggregation {
    /// Total matching count.
    Count,
    /// `(channel, count)` for each distinct channel that matches.
    CountByChannel,
    /// Count grouped into time-buckets of `bucket_secs` seconds.
    TimeBucketCount {
        /// Bucket width in seconds, at least 1; buckets start at multiples
        /// of it from the Unix epoch.
        bucket_secs: u64,
    },
    /// Distinct channel names that match.
    DistinctChannels,
    /// Distinct type names that match.
    DistinctTypes,
}

/// Result of a query: rows + (optionally) aggregate values.
#[derive(Debug, Default)]
pub struct QueryResult {
    /// Empty when `QuerySpec::aggregate` is set.
    pub rows: Vec<EnvelopeRow>,
    /// Aggregate result, if requested.
    pub aggregate: Option<AggregateResult>,
    /// Pass as [`QuerySpec::until_unix_nanos`] for the next page.
    pub next_before: Option<u128>,
}

/// Aggregation values returned by `query` when `QuerySpec::aggregate` is set.
#[derive(Debug, Clone)]
pub enum AggregateResult {
    /// Total count of matching rows.
    Count(u64),
    /// One `(channel, count)` pair per distinct channel matched.
    CountByChannel(Vec<(String, u64)>),
    /// Per-bucket counts; see [`Aggregation::TimeBucketCount`].
    TimeBucketCount(Vec<TimeBucket>),
    /// Distinct channel names that matched.
    DistinctChannels(Vec<String>),
    /// Distinct type names that matched (omits rows with `null`
    /// `type_name`).
    DistinctTypes(Vec<String>),
}

/// One bucket of a [`AggregateResult::TimeBucketCount`].
#[derive(Debug, Clone)]
pub struct TimeBucket {
    /// The bucket's start, in Unix nanoseconds; it spans `bucket_secs` from
    /// here.
    pub bucket_start_unix_nanos: u128,
    /// Row count within the bucket.
    pub count: u64,
}

/// Retention policy for `Basket::retention_sweep`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RetentionPolicy {
    /// Drop rows older than this many seconds (0 disables).
    pub max_age_secs: u64,
    /// Cap total rows at this number (0 disables).
    pub max_rows: u64,
    /// Cap total payload bytes at this many (0 disables). Approximate: a
    /// sweep that finds the cap passed drops the oldest tenth of the rows,
    /// at least one.
    pub max_bytes: u64,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            max_age_secs: 24 * 60 * 60,
            max_rows: 100_000,
            max_bytes: 100 * 1024 * 1024,
        }
    }
}

/// The basket: one SQLite connection behind a mutex. One process (the
/// daemon) writes; others publish through it.
pub struct Basket {
    conn: Mutex<Connection>,
}

const SCHEMA_V1: &str = r#"
CREATE TABLE IF NOT EXISTS envelopes (
    id                       TEXT PRIMARY KEY,
    captured_at_unix_nanos   INTEGER NOT NULL,
    channel                  TEXT NOT NULL,
    envelope_type            INTEGER NOT NULL,
    type_name                TEXT,
    origin                   TEXT NOT NULL,
    payload_hash             TEXT NOT NULL,
    payload_bytes            BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_envelopes_captured  ON envelopes(captured_at_unix_nanos);
CREATE INDEX IF NOT EXISTS idx_envelopes_channel   ON envelopes(channel);
CREATE INDEX IF NOT EXISTS idx_envelopes_type      ON envelopes(envelope_type);
CREATE INDEX IF NOT EXISTS idx_envelopes_typename  ON envelopes(type_name);
"#;

/// The files SQLite keeps beside a database in the modes the basket uses.
const SIDECARS: [&str; 3] = ["-wal", "-shm", "-journal"];

/// Prepare `path` for a basket only its owner can read ([`Basket::open`]).
#[cfg(unix)]
fn owner_only(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }
    }
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => narrow(path)?,
        Err(e) => return Err(e),
    }
    for suffix in SIDECARS {
        let mut sidecar = path.as_os_str().to_owned();
        sidecar.push(suffix);
        match narrow(Path::new(&sidecar)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            other => other?,
        }
    }
    Ok(())
}

/// Elsewhere the basket's directory is created as it always was.
#[cfg(not(unix))]
fn owner_only(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

/// Take group and other users' bits off the file at `path`, if it has any.
#[cfg(unix)]
fn narrow(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o7700))?;
    }
    Ok(())
}

impl Basket {
    /// Open or create a basket at `path`, for its owner alone.
    ///
    /// On Unix, directories missing from `path` are created mode `0700`, and
    /// the file mode `0600` before SQLite opens it, so that the `-wal`,
    /// `-shm` and `-journal` files SQLite makes beside it take the same mode.
    /// A file or one of those that exists already and grants group or other
    /// users any access is narrowed to its owner's bits. A directory that
    /// exists already is not changed (see the crate's documentation).
    ///
    /// # Errors
    ///
    /// [`BasketError::Io`] if a directory or the file cannot be created, or
    /// an existing file's permissions cannot be narrowed;
    /// [`BasketError::Sqlite`] if SQLite cannot open the file, set its
    /// pragmas or create the schema.
    pub fn open(path: &Path) -> Result<Self, BasketError> {
        owner_only(path)?;
        let conn = Connection::open(path)?;
        // Reasonable pragmas for a write-heavy single-writer workload
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA temp_store = MEMORY;",
        )?;
        conn.execute_batch(SCHEMA_V1)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Insert an envelope. Inserting an id the basket holds changes
    /// nothing: the row keeps its first channel, origin and capture time.
    ///
    /// # Errors
    ///
    /// [`BasketError::Poisoned`], or [`BasketError::Sqlite`] if the insert
    /// fails.
    pub fn insert(&self, env: &PulseEnvelope, meta: CaptureMeta) -> Result<(), BasketError> {
        let id_hex = hex16(&env.id().0);
        let captured = meta.captured_at_unix_nanos.unwrap_or_else(now_unix_nanos);
        let envelope_type = env.envelope_type() as u32;
        let type_name = env.type_name();
        let payload_bytes = env.payload().to_bytes();
        let payload_hash = blake3_hex(&payload_bytes);

        let conn = self.conn.lock().map_err(|_| BasketError::Poisoned)?;
        conn.execute(
            "INSERT INTO envelopes
                (id, captured_at_unix_nanos, channel, envelope_type, type_name, origin, payload_hash, payload_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO NOTHING",
            params![
                id_hex,
                u128_to_sqlite(captured),
                meta.channel,
                envelope_type,
                type_name,
                meta.origin,
                payload_hash,
                payload_bytes,
            ],
        )?;
        Ok(())
    }

    /// Run a structured query; rows come newest first.
    ///
    /// # Errors
    ///
    /// [`BasketError::InvalidQuery`] for a time bucket of zero seconds;
    /// [`BasketError::Poisoned`]; [`BasketError::Sqlite`] if the query
    /// fails.
    pub fn query(&self, spec: &QuerySpec) -> Result<QueryResult, BasketError> {
        if let Some(Aggregation::TimeBucketCount { bucket_secs: 0 }) = spec.aggregate {
            return Err(BasketError::InvalidQuery(
                "a time-bucket aggregate needs bucket_secs of at least 1".into(),
            ));
        }
        let conn = self.conn.lock().map_err(|_| BasketError::Poisoned)?;
        if let Some(agg) = &spec.aggregate {
            let agg_result = run_aggregate(&conn, spec, agg)?;
            return Ok(QueryResult {
                rows: vec![],
                aggregate: Some(agg_result),
                next_before: None,
            });
        }

        let limit = clamp_limit(spec.limit);
        let (where_sql, params_vec) = build_where(spec);
        let sql = format!(
            "SELECT id, captured_at_unix_nanos, channel, envelope_type,
                    type_name, origin, payload_hash, payload_bytes
             FROM envelopes
             {}
             ORDER BY captured_at_unix_nanos DESC
             LIMIT {}",
            where_sql, limit
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows: Vec<EnvelopeRow> = stmt
            .query_map(rusqlite::params_from_iter(&params_vec), row_from_sqlite)?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let next_before = rows.last().map(|r| r.captured_at_unix_nanos);
        Ok(QueryResult {
            rows,
            aggregate: None,
            next_before,
        })
    }

    /// Apply a retention policy and return the number of rows deleted.
    ///
    /// # Errors
    ///
    /// [`BasketError::Poisoned`], or [`BasketError::Sqlite`] if a delete
    /// fails, which stops the sweep; rows it had deleted stay deleted,
    /// uncounted.
    pub fn retention_sweep(&self, policy: &RetentionPolicy) -> Result<usize, BasketError> {
        let conn = self.conn.lock().map_err(|_| BasketError::Poisoned)?;
        let now = now_unix_nanos();
        let mut deleted = 0;

        if policy.max_age_secs > 0 {
            let cutoff = now.saturating_sub((policy.max_age_secs as u128) * 1_000_000_000);
            let n = conn.execute(
                "DELETE FROM envelopes WHERE captured_at_unix_nanos < ?1",
                params![u128_to_sqlite(cutoff)],
            )?;
            deleted += n;
        }

        if policy.max_rows > 0 {
            let count: i64 = conn.query_row("SELECT COUNT(*) FROM envelopes", [], |r| r.get(0))?;
            if count as u64 > policy.max_rows {
                let to_drop = count as u64 - policy.max_rows;
                let n = conn.execute(
                    "DELETE FROM envelopes WHERE id IN (
                        SELECT id FROM envelopes
                        ORDER BY captured_at_unix_nanos ASC
                        LIMIT ?1
                    )",
                    params![to_drop as i64],
                )?;
                deleted += n;
            }
        }

        if policy.max_bytes > 0 {
            let total_bytes: i64 = conn.query_row(
                "SELECT COALESCE(SUM(LENGTH(payload_bytes)), 0) FROM envelopes",
                [],
                |r| r.get(0),
            )?;
            if total_bytes as u64 > policy.max_bytes {
                // The oldest tenth: the exact cut takes a running sum of sizes,
                // O(N) every sweep.
                let count: i64 =
                    conn.query_row("SELECT COUNT(*) FROM envelopes", [], |r| r.get(0))?;
                let to_drop = (count / 10).max(1);
                let n = conn.execute(
                    "DELETE FROM envelopes WHERE id IN (
                        SELECT id FROM envelopes
                        ORDER BY captured_at_unix_nanos ASC
                        LIMIT ?1
                    )",
                    params![to_drop],
                )?;
                deleted += n;
            }
        }

        Ok(deleted)
    }

    /// Total rows currently in the basket.
    ///
    /// # Errors
    ///
    /// [`BasketError::Poisoned`], or [`BasketError::Sqlite`] if the count
    /// fails.
    pub fn row_count(&self) -> Result<u64, BasketError> {
        let conn = self.conn.lock().map_err(|_| BasketError::Poisoned)?;
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM envelopes", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    /// The row with this hex envelope id, or `None`.
    ///
    /// # Errors
    ///
    /// [`BasketError::Poisoned`], or [`BasketError::Sqlite`] if the lookup
    /// fails.
    pub fn get(&self, id_hex: &str) -> Result<Option<EnvelopeRow>, BasketError> {
        let conn = self.conn.lock().map_err(|_| BasketError::Poisoned)?;
        let row = conn
            .query_row(
                "SELECT id, captured_at_unix_nanos, channel, envelope_type, type_name, origin, payload_hash, payload_bytes
                 FROM envelopes WHERE id = ?1",
                params![id_hex],
                row_from_sqlite,
            )
            .optional()?;
        Ok(row)
    }
}

// --- helpers --------------------------------------------------------------

fn build_where(spec: &QuerySpec) -> (String, Vec<Box<dyn rusqlite::ToSql>>) {
    let mut clauses = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    if let Some(ref c) = spec.channel {
        clauses.push("channel = ?".to_string());
        params.push(Box::new(c.clone()));
    }
    if let Some(t) = spec.envelope_type {
        clauses.push("envelope_type = ?".to_string());
        params.push(Box::new(t as i64));
    }
    if let Some(ref n) = spec.type_name {
        clauses.push("type_name = ?".to_string());
        params.push(Box::new(n.clone()));
    }
    if let Some(ref o) = spec.origin {
        clauses.push("origin = ?".to_string());
        params.push(Box::new(o.clone()));
    }
    if let Some(s) = spec.since_unix_nanos {
        clauses.push("captured_at_unix_nanos >= ?".to_string());
        params.push(Box::new(u128_to_sqlite(s)));
    }
    if let Some(u) = spec.until_unix_nanos {
        clauses.push("captured_at_unix_nanos < ?".to_string());
        params.push(Box::new(u128_to_sqlite(u)));
    }
    let where_sql = if clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", clauses.join(" AND "))
    };
    (where_sql, params)
}

fn run_aggregate(
    conn: &Connection,
    spec: &QuerySpec,
    agg: &Aggregation,
) -> Result<AggregateResult, BasketError> {
    let (where_sql, params) = build_where(spec);
    match agg {
        Aggregation::Count => {
            let sql = format!("SELECT COUNT(*) FROM envelopes {}", where_sql);
            let mut stmt = conn.prepare(&sql)?;
            let n: i64 = stmt.query_row(rusqlite::params_from_iter(&params), |r| r.get(0))?;
            Ok(AggregateResult::Count(n as u64))
        }
        Aggregation::CountByChannel => {
            let sql = format!(
                "SELECT channel, COUNT(*) FROM envelopes {} GROUP BY channel ORDER BY 2 DESC",
                where_sql
            );
            let mut stmt = conn.prepare(&sql)?;
            let rows: Vec<(String, u64)> = stmt
                .query_map(rusqlite::params_from_iter(&params), |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(AggregateResult::CountByChannel(rows))
        }
        Aggregation::TimeBucketCount { bucket_secs } => {
            let bucket_ns = (*bucket_secs as u128) * 1_000_000_000;
            let bucket_ns_i64 = bucket_ns.min(i64::MAX as u128) as i64;
            let sql = format!(
                "SELECT (captured_at_unix_nanos / ?) * ? AS bucket, COUNT(*)
                 FROM envelopes {}
                 GROUP BY bucket ORDER BY bucket ASC",
                where_sql
            );
            let mut bind: Vec<Box<dyn rusqlite::ToSql>> =
                vec![Box::new(bucket_ns_i64), Box::new(bucket_ns_i64)];
            bind.extend(params);
            let mut stmt = conn.prepare(&sql)?;
            let rows: Vec<TimeBucket> = stmt
                .query_map(rusqlite::params_from_iter(&bind), |r| {
                    let b: i64 = r.get(0)?;
                    let c: i64 = r.get(1)?;
                    Ok(TimeBucket {
                        bucket_start_unix_nanos: b as u128,
                        count: c as u64,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(AggregateResult::TimeBucketCount(rows))
        }
        Aggregation::DistinctChannels => {
            let sql = format!(
                "SELECT DISTINCT channel FROM envelopes {} ORDER BY channel",
                where_sql
            );
            let mut stmt = conn.prepare(&sql)?;
            let rows: Vec<String> = stmt
                .query_map(rusqlite::params_from_iter(&params), |r| {
                    r.get::<_, String>(0)
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(AggregateResult::DistinctChannels(rows))
        }
        Aggregation::DistinctTypes => {
            // `where_sql` is empty, or a `WHERE` clause to extend.
            let sql = if where_sql.is_empty() {
                "SELECT DISTINCT type_name FROM envelopes WHERE type_name IS NOT NULL ORDER BY type_name".to_string()
            } else {
                format!(
                    "SELECT DISTINCT type_name FROM envelopes {} AND type_name IS NOT NULL ORDER BY type_name",
                    where_sql
                )
            };
            let mut stmt = conn.prepare(&sql)?;
            let rows: Vec<String> = stmt
                .query_map(rusqlite::params_from_iter(&params), |r| {
                    r.get::<_, String>(0)
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(AggregateResult::DistinctTypes(rows))
        }
    }
}

fn row_from_sqlite(r: &rusqlite::Row) -> rusqlite::Result<EnvelopeRow> {
    Ok(EnvelopeRow {
        id: r.get(0)?,
        captured_at_unix_nanos: sqlite_to_u128(r.get(1)?),
        channel: r.get(2)?,
        envelope_type: r.get::<_, i64>(3)? as u32,
        type_name: r.get(4)?,
        origin: r.get(5)?,
        payload_hash: r.get(6)?,
        payload_bytes: r.get(7)?,
    })
}

fn clamp_limit(n: usize) -> usize {
    if n == 0 {
        50
    } else if n > 5000 {
        5000
    } else {
        n
    }
}

fn hex16(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn blake3_hex(bytes: &[u8]) -> String {
    let h = blake3::hash(bytes);
    h.as_bytes()
        .iter()
        .take(16)
        .map(|b| format!("{:02x}", b))
        .collect()
}

fn now_unix_nanos() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Clamp to SQLite's i64 integers; Unix nanoseconds fit until 2262.
fn u128_to_sqlite(n: u128) -> i64 {
    n.min(i64::MAX as u128) as i64
}

fn sqlite_to_u128(n: i64) -> u128 {
    if n < 0 {
        0
    } else {
        n as u128
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use pulse_canon::PulseEnvelope;
    use tempfile::TempDir;

    fn temp_basket() -> (TempDir, Basket) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("basket.db");
        let b = Basket::open(&path).unwrap();
        (dir, b)
    }

    #[test]
    fn open_creates_schema() {
        let (_d, b) = temp_basket();
        assert_eq!(b.row_count().unwrap(), 0);
        // tools/pms-query reads the file directly: the schema is its contract.
        let conn = b.conn.lock().unwrap();
        let mut stmt = conn.prepare("PRAGMA table_info(envelopes)").unwrap();
        let cols: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .map(|c| c.unwrap())
            .collect();
        assert_eq!(
            cols,
            [
                "id",
                "captured_at_unix_nanos",
                "channel",
                "envelope_type",
                "type_name",
                "origin",
                "payload_hash",
                "payload_bytes"
            ]
        );
    }

    #[test]
    fn insert_and_query() {
        let (_d, b) = temp_basket();
        let env = PulseEnvelope::typed("db/rows", b"hello".to_vec());
        b.insert(&env, CaptureMeta::new("db/rows", "ingest@7f3a"))
            .unwrap();
        assert_eq!(b.row_count().unwrap(), 1);

        let result = b
            .query(&QuerySpec {
                channel: Some("db/rows".into()),
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0].channel, "db/rows");
        assert_eq!(result.rows[0].payload_bytes, b"hello");
    }

    #[test]
    fn aggregate_count_by_channel() {
        let (_d, b) = temp_basket();
        // Distinct payloads, so distinct ids: no insert is a duplicate.
        for (i, ch) in [(1u8, "a"), (2, "a"), (3, "b")] {
            let env = PulseEnvelope::typed(ch, vec![i]);
            b.insert(&env, CaptureMeta::new(ch, "n@1")).unwrap();
        }
        let r = b
            .query(&QuerySpec {
                aggregate: Some(Aggregation::CountByChannel),
                ..Default::default()
            })
            .unwrap();
        match r.aggregate.unwrap() {
            AggregateResult::CountByChannel(rows) => {
                assert_eq!(rows.len(), 2);
                // ordered DESC by count
                assert_eq!(rows[0], ("a".into(), 2));
                assert_eq!(rows[1], ("b".into(), 1));
            }
            _ => panic!("wrong agg variant"),
        }
    }

    #[test]
    fn retention_drops_old_rows() {
        let (_d, b) = temp_basket();
        let now = now_unix_nanos();
        let old = now.saturating_sub(2 * 24 * 60 * 60 * 1_000_000_000);
        let env = PulseEnvelope::typed("x", vec![]);
        b.insert(
            &env,
            CaptureMeta {
                channel: "x".into(),
                origin: "n@1".into(),
                captured_at_unix_nanos: Some(old),
            },
        )
        .unwrap();
        let deleted = b
            .retention_sweep(&RetentionPolicy {
                max_age_secs: 60 * 60,
                max_rows: 0,
                max_bytes: 0,
            })
            .unwrap();
        assert!(deleted >= 1);
        assert_eq!(b.row_count().unwrap(), 0);
    }

    #[test]
    fn a_time_bucket_of_zero_seconds_is_an_invalid_query() {
        let (_d, b) = temp_basket();
        b.insert(
            &PulseEnvelope::typed("c", b"x".to_vec()),
            CaptureMeta::new("c", "n@1"),
        )
        .unwrap();
        let bucket = |bucket_secs| {
            b.query(&QuerySpec {
                aggregate: Some(Aggregation::TimeBucketCount { bucket_secs }),
                ..Default::default()
            })
        };
        match bucket(0) {
            Err(BasketError::InvalidQuery(reason)) => assert!(reason.contains("bucket_secs")),
            other => panic!("expected InvalidQuery, got {other:?}"),
        }
        match bucket(1).unwrap().aggregate {
            Some(AggregateResult::TimeBucketCount(buckets)) => {
                assert_eq!(buckets.len(), 1);
                assert_eq!(buckets[0].count, 1);
            }
            other => panic!("expected one bucket, got {other:?}"),
        }
    }

    #[test]
    fn inserting_an_envelope_again_changes_nothing() {
        let (_d, b) = temp_basket();
        let env = PulseEnvelope::typed("same/type", b"same payload".to_vec());
        let id = hex16(&env.id().0);
        let capture = |channel: &str, origin: &str, at| CaptureMeta {
            channel: channel.into(),
            origin: origin.into(),
            captured_at_unix_nanos: Some(at),
        };
        b.insert(&env, capture("chan-a", "first@1", 100)).unwrap();
        b.insert(&env, capture("chan-b", "second@2", 200)).unwrap();
        assert_eq!(b.row_count().unwrap(), 1);
        let row = b.get(&id).unwrap().expect("the row");
        assert_eq!(
            (
                row.channel.as_str(),
                row.origin.as_str(),
                row.captured_at_unix_nanos
            ),
            ("chan-a", "first@1", 100)
        );
        assert_eq!(row.payload_bytes, b"same payload");
    }
}
