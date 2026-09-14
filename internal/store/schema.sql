-- Schema for セキュファイル便.
--
-- Nothing in this database is enough to read a stored file. The data
-- encryption key exists only wrapped under the share password, and filenames
-- are sealed under that same key, so a dump of this file plus the blob
-- directory still discloses nothing but sizes and timestamps.

CREATE TABLE IF NOT EXISTS drops (
    id            INTEGER PRIMARY KEY,
    key           TEXT    NOT NULL UNIQUE,
    wrapped_dek   BLOB    NOT NULL,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    max_downloads INTEGER NOT NULL,
    downloads     INTEGER NOT NULL DEFAULT 0,
    total_bytes   INTEGER NOT NULL DEFAULT 0,
    status        TEXT    NOT NULL DEFAULT 'pending',
    uploader_hash BLOB,
    uploader_ip   TEXT,
    delete_allowed INTEGER NOT NULL DEFAULT 0,
    -- 'file' for an ordinary file share, 'text' for a secret message (a single
    -- file the recipient reads inline rather than downloads).
    kind          TEXT    NOT NULL DEFAULT 'file',
    -- SHA-256 of the sender's management token. Holding it lets the sender check
    -- download status and delete the share early; only the hash is stored, so a
    -- database dump cannot forge one. NULL when no management link was issued.
    manage_hash   BLOB
);

CREATE INDEX IF NOT EXISTS drops_expires_at ON drops (expires_at);
CREATE INDEX IF NOT EXISTS drops_status ON drops (status);
-- drops_manage_hash is created in migrate(), after the column is guaranteed to
-- exist on databases first created before the management link was added.

CREATE TABLE IF NOT EXISTS files (
    id        INTEGER PRIMARY KEY,
    drop_id   INTEGER NOT NULL REFERENCES drops (id) ON DELETE CASCADE,
    ordinal   INTEGER NOT NULL,
    name_enc  BLOB    NOT NULL,
    size      INTEGER NOT NULL,
    received  INTEGER NOT NULL DEFAULT 0,
    blob_path TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS files_drop_id ON files (drop_id, ordinal);

-- An upload session holds the data encryption key wrapped under the client's
-- upload token, so an interrupted upload can resume after a server restart
-- without the server ever being able to recover the key on its own.
CREATE TABLE IF NOT EXISTS upload_sessions (
    id         TEXT    PRIMARY KEY,
    drop_id    INTEGER NOT NULL REFERENCES drops (id) ON DELETE CASCADE,
    wrapped    BLOB    NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS upload_sessions_expires_at ON upload_sessions (expires_at);

-- A rights-infringement report. Filing one blocks the named share immediately
-- (see drops.blocked_at); the report itself is kept even after the share is
-- gone, so the record of who reported what, and when, survives a takedown.
-- drop_id goes NULL if the share is later deleted, but drop_key is retained.
CREATE TABLE IF NOT EXISTS reports (
    id          INTEGER PRIMARY KEY,
    drop_id     INTEGER REFERENCES drops (id) ON DELETE SET NULL,
    drop_key    TEXT    NOT NULL,
    reason      TEXT,
    reporter    TEXT,
    reporter_ip TEXT,
    created_at  INTEGER NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'open'
);

CREATE INDEX IF NOT EXISTS reports_status ON reports (status, created_at);

-- Per-day usage counters, for the operator's statistics view. This is the only
-- record that outlives a share: individual drops are deleted on expiry, so
-- lifetime usage is kept here as aggregate counts only — no key, no size of any
-- one share, nothing that could identify a file. Buckets are Japan-time dates.
CREATE TABLE IF NOT EXISTS usage_daily (
    day       TEXT    PRIMARY KEY,   -- YYYY-MM-DD in JST
    uploads   INTEGER NOT NULL DEFAULT 0,
    downloads INTEGER NOT NULL DEFAULT 0,
    bytes     INTEGER NOT NULL DEFAULT 0
);
