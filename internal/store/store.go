// Package store is the metadata layer for セキュファイル便.
//
// It deliberately holds no secret that is useful on its own: keys live here
// only wrapped under a password the server never sees, and filenames are
// stored sealed. Losing this database to an attacker loses sizes, counts and
// timestamps, not content.
package store

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

// ErrNotFound is returned when a drop, file or session does not exist, has
// expired, or has been exhausted. The cases are deliberately not
// distinguished: telling a caller that a key exists but is expired confirms
// the key was real, which is more than an unauthenticated caller should learn.
var ErrNotFound = errors.New("store: not found")

// Status values for a drop.
const (
	StatusPending = "pending" // upload in progress
	StatusReady   = "ready"   // finalized and downloadable
)

// Store is a handle to the metadata database.
type Store struct {
	db *sql.DB
}

// Drop is one share: a set of files behind one key and one password.
type Drop struct {
	ID            int64
	Key           string
	WrappedDEK    []byte
	CreatedAt     time.Time
	ExpiresAt     time.Time
	MaxDownloads  int
	Downloads     int
	TotalBytes    int64
	Status        string
	DeleteAllowed bool
	// Kind is "file" for an ordinary share or "text" for a secret message.
	Kind string
	// ManageHash is SHA-256 of the sender's management token, or nil. It is set
	// at creation and never returned to a recipient.
	ManageHash []byte
	// BlockedAt is set when a share has been blocked by a rights-infringement
	// report. A zero value means it is not blocked. A blocked share is served to
	// no one and is exempt from the expiry sweep, so it is retained for review
	// and for a sender-disclosure (発信者情報開示) request.
	BlockedAt time.Time
}

// Blocked reports whether the share has been taken down by a report.
func (d *Drop) Blocked() bool { return !d.BlockedAt.IsZero() }

// File is one uploaded file within a drop.
type File struct {
	ID       int64
	DropID   int64
	Ordinal  int
	NameEnc  []byte
	Size     int64
	Received int64
	BlobPath string
}

// Complete reports whether every byte of the file has been stored.
func (f *File) Complete() bool { return f.Received >= f.Size }

// UploadSession lets an interrupted upload resume.
type UploadSession struct {
	ID        string
	DropID    int64
	Wrapped   []byte
	ExpiresAt time.Time
}

// Open opens (creating if needed) the database at path and applies the schema.
func Open(ctx context.Context, path string) (*Store, error) {
	// WAL keeps readers from blocking on the sweeper's deletes; busy_timeout
	// turns the remaining lock contention into a short wait instead of an
	// immediate SQLITE_BUSY error under concurrent uploads.
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	// A single writer avoids SQLITE_BUSY churn; SQLite serialises writes anyway.
	db.SetMaxOpenConns(1)

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: ping %s: %w", path, err)
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: apply schema: %w", err)
	}
	// CREATE TABLE IF NOT EXISTS never alters an existing table, so columns
	// added after a database was first created are applied here. Each ALTER is
	// guarded by a column-existence check, making startup idempotent.
	if err := migrate(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// migrate adds columns introduced after the initial schema, for databases
// created by an earlier version.
func migrate(ctx context.Context, db *sql.DB) error {
	adds := []struct{ table, column, ddl string }{
		{"drops", "delete_allowed", "ALTER TABLE drops ADD COLUMN delete_allowed INTEGER NOT NULL DEFAULT 0"},
		{"drops", "uploader_ip", "ALTER TABLE drops ADD COLUMN uploader_ip TEXT"},
		{"drops", "blocked_at", "ALTER TABLE drops ADD COLUMN blocked_at INTEGER"},
		{"drops", "kind", "ALTER TABLE drops ADD COLUMN kind TEXT NOT NULL DEFAULT 'file'"},
		{"drops", "manage_hash", "ALTER TABLE drops ADD COLUMN manage_hash BLOB"},
	}
	for _, a := range adds {
		has, err := hasColumn(ctx, db, a.table, a.column)
		if err != nil {
			return err
		}
		if has {
			continue
		}
		if _, err := db.ExecContext(ctx, a.ddl); err != nil {
			return fmt.Errorf("store: migrate %s.%s: %w", a.table, a.column, err)
		}
	}
	// Indexes over migrated columns are created here, once the columns above are
	// guaranteed present, rather than in schema.sql where an older database would
	// not yet have the column when the schema runs.
	if _, err := db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS drops_manage_hash ON drops (manage_hash)`); err != nil {
		return fmt.Errorf("store: create manage_hash index: %w", err)
	}
	return nil
}

func hasColumn(ctx context.Context, db *sql.DB, table, column string) (bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return false, fmt.Errorf("store: inspect %s: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// DB exposes the underlying handle so the legacy migration layer can share one
// SQLite file and one connection with the main store.
func (s *Store) DB() *sql.DB { return s.db }

// CreateDrop inserts a pending drop and returns it with its assigned ID.
func (s *Store) CreateDrop(ctx context.Context, d *Drop, uploaderHash []byte, uploaderIP string) (*Drop, error) {
	kind := d.Kind
	if kind == "" {
		kind = "file"
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO drops (key, wrapped_dek, created_at, expires_at, max_downloads, status, uploader_hash, uploader_ip, delete_allowed, kind, manage_hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.Key, d.WrappedDEK, d.CreatedAt.Unix(), d.ExpiresAt.Unix(), d.MaxDownloads, StatusPending, uploaderHash, nullIfEmpty(uploaderIP), boolToInt(d.DeleteAllowed), kind, nilIfEmpty(d.ManageHash))
	if err != nil {
		return nil, fmt.Errorf("store: create drop: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("store: create drop id: %w", err)
	}
	out := *d
	out.ID = id
	out.Status = StatusPending
	out.Kind = kind
	return &out, nil
}

// DropByManageHash returns the drop whose management token hashes to hash. It
// is how a sender's management link is resolved without the server ever holding
// the token itself.
func (s *Store) DropByManageHash(ctx context.Context, hash []byte) (*Drop, error) {
	if len(hash) == 0 {
		return nil, ErrNotFound
	}
	return scanDrop(s.db.QueryRowContext(ctx,
		`SELECT `+dropColumns+` FROM drops WHERE manage_hash = ?`, hash))
}

func scanDrop(row interface{ Scan(...any) error }) (*Drop, error) {
	var d Drop
	var created, expires int64
	var deleteAllowed int
	var blocked sql.NullInt64
	err := row.Scan(&d.ID, &d.Key, &d.WrappedDEK, &created, &expires,
		&d.MaxDownloads, &d.Downloads, &d.TotalBytes, &d.Status, &deleteAllowed, &blocked,
		&d.Kind, &d.ManageHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: scan drop: %w", err)
	}
	d.CreatedAt = time.Unix(created, 0)
	d.ExpiresAt = time.Unix(expires, 0)
	d.DeleteAllowed = deleteAllowed != 0
	if blocked.Valid {
		d.BlockedAt = time.Unix(blocked.Int64, 0)
	}
	return &d, nil
}

const dropColumns = `id, key, wrapped_dek, created_at, expires_at, max_downloads, downloads, total_bytes, status, delete_allowed, blocked_at, kind, manage_hash`

// DropByKey returns a drop by its share key, whatever its status.
func (s *Store) DropByKey(ctx context.Context, key string) (*Drop, error) {
	return scanDrop(s.db.QueryRowContext(ctx,
		`SELECT `+dropColumns+` FROM drops WHERE key = ?`, key))
}

// DropByID returns a drop by its row ID.
func (s *Store) DropByID(ctx context.Context, id int64) (*Drop, error) {
	return scanDrop(s.db.QueryRowContext(ctx,
		`SELECT `+dropColumns+` FROM drops WHERE id = ?`, id))
}

// LiveDropByKey returns a drop only if it is ready, unexpired, and has
// downloads remaining. Anything else is reported as ErrNotFound.
func (s *Store) LiveDropByKey(ctx context.Context, key string, now time.Time) (*Drop, error) {
	return scanDrop(s.db.QueryRowContext(ctx,
		`SELECT `+dropColumns+` FROM drops
		 WHERE key = ? AND status = ? AND expires_at > ? AND downloads < max_downloads
		   AND blocked_at IS NULL`,
		key, StatusReady, now.Unix()))
}

// AddFile records a file belonging to a drop.
func (s *Store) AddFile(ctx context.Context, f *File) (*File, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO files (drop_id, ordinal, name_enc, size, blob_path) VALUES (?, ?, ?, ?, ?)`,
		f.DropID, f.Ordinal, f.NameEnc, f.Size, f.BlobPath)
	if err != nil {
		return nil, fmt.Errorf("store: add file: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("store: add file id: %w", err)
	}
	out := *f
	out.ID = id
	return &out, nil
}

// Files lists a drop's files in upload order.
func (s *Store) Files(ctx context.Context, dropID int64) ([]*File, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, drop_id, ordinal, name_enc, size, received, blob_path
		 FROM files WHERE drop_id = ? ORDER BY ordinal`, dropID)
	if err != nil {
		return nil, fmt.Errorf("store: list files: %w", err)
	}
	defer rows.Close()

	var out []*File
	for rows.Next() {
		var f File
		if err := rows.Scan(&f.ID, &f.DropID, &f.Ordinal, &f.NameEnc, &f.Size, &f.Received, &f.BlobPath); err != nil {
			return nil, fmt.Errorf("store: scan file: %w", err)
		}
		out = append(out, &f)
	}
	return out, rows.Err()
}

// FileByID returns one file, scoped to its drop so a caller holding a session
// for one drop cannot address another drop's file by guessing an ID.
func (s *Store) FileByID(ctx context.Context, dropID, fileID int64) (*File, error) {
	var f File
	err := s.db.QueryRowContext(ctx,
		`SELECT id, drop_id, ordinal, name_enc, size, received, blob_path
		 FROM files WHERE id = ? AND drop_id = ?`, fileID, dropID).
		Scan(&f.ID, &f.DropID, &f.Ordinal, &f.NameEnc, &f.Size, &f.Received, &f.BlobPath)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: scan file: %w", err)
	}
	return &f, nil
}

// SetBlobPath records where a file's ciphertext lives, relative to the blob
// root. It is set after insert because the path is derived from the row ID.
func (s *Store) SetBlobPath(ctx context.Context, fileID int64, path string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE files SET blob_path = ? WHERE id = ?`, path, fileID)
	if err != nil {
		return fmt.Errorf("store: set blob path: %w", err)
	}
	return nil
}

// SetReceived records how many plaintext bytes of a file are stored.
func (s *Store) SetReceived(ctx context.Context, fileID, received int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE files SET received = ? WHERE id = ?`, received, fileID)
	if err != nil {
		return fmt.Errorf("store: set received: %w", err)
	}
	return nil
}

// Finalize marks a drop downloadable and records its total size. It refuses if
// any file is still short of its declared size, so a half-uploaded drop can
// never be handed to a recipient as complete.
func (s *Store) Finalize(ctx context.Context, dropID int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin finalize: %w", err)
	}
	defer tx.Rollback()

	var incomplete int
	var total sql.NullInt64
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FILTER (WHERE received < size), SUM(size) FROM files WHERE drop_id = ?`, dropID).
		Scan(&incomplete, &total); err != nil {
		return fmt.Errorf("store: check completeness: %w", err)
	}
	if incomplete > 0 {
		return fmt.Errorf("store: finalize drop %d: %d file(s) incomplete", dropID, incomplete)
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE drops SET status = ?, total_bytes = ? WHERE id = ?`,
		StatusReady, total.Int64, dropID); err != nil {
		return fmt.Errorf("store: finalize: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM upload_sessions WHERE drop_id = ?`, dropID); err != nil {
		return fmt.Errorf("store: clear upload session: %w", err)
	}
	return tx.Commit()
}

// ClaimDownload consumes one of a drop's remaining downloads.
//
// The check and the decrement are one statement, so two recipients racing on
// the last remaining download cannot both win: SQLite serialises the writes
// and exactly one UPDATE reports a row affected.
func (s *Store) ClaimDownload(ctx context.Context, key string, now time.Time) (*Drop, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE drops SET downloads = downloads + 1
		 WHERE key = ? AND status = ? AND expires_at > ? AND downloads < max_downloads
		   AND blocked_at IS NULL`,
		key, StatusReady, now.Unix())
	if err != nil {
		return nil, fmt.Errorf("store: claim download: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("store: claim download rows: %w", err)
	}
	if n == 0 {
		return nil, ErrNotFound
	}
	return s.DropByKey(ctx, key)
}

// CreateUploadSession stores a resumable upload session.
func (s *Store) CreateUploadSession(ctx context.Context, sess *UploadSession) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO upload_sessions (id, drop_id, wrapped, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		sess.ID, sess.DropID, sess.Wrapped, time.Now().Unix(), sess.ExpiresAt.Unix())
	if err != nil {
		return fmt.Errorf("store: create upload session: %w", err)
	}
	return nil
}

// UploadSessionByID returns an unexpired upload session.
func (s *Store) UploadSessionByID(ctx context.Context, id string, now time.Time) (*UploadSession, error) {
	var sess UploadSession
	var expires int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id, drop_id, wrapped, expires_at FROM upload_sessions WHERE id = ? AND expires_at > ?`,
		id, now.Unix()).Scan(&sess.ID, &sess.DropID, &sess.Wrapped, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: scan upload session: %w", err)
	}
	sess.ExpiresAt = time.Unix(expires, 0)
	return &sess, nil
}

// Reapable lists drops that should be deleted: expired, exhausted, or left
// pending past their session window.
func (s *Store) Reapable(ctx context.Context, now time.Time, pendingCutoff time.Time) ([]*Drop, error) {
	// A blocked share is never reaped: it is held for review and for a possible
	// sender-disclosure request, even past its original expiry.
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+dropColumns+` FROM drops
		 WHERE blocked_at IS NULL AND (
		        expires_at <= ?
		     OR (status = ? AND downloads >= max_downloads)
		     OR (status = ? AND created_at <= ?))`,
		now.Unix(), StatusReady, StatusPending, pendingCutoff.Unix())
	if err != nil {
		return nil, fmt.Errorf("store: list reapable: %w", err)
	}
	defer rows.Close()

	var out []*Drop
	for rows.Next() {
		d, err := scanDrop(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeleteDrop removes a drop and, by cascade, its files and sessions. Blob
// files on disk are the caller's responsibility.
func (s *Store) DeleteDrop(ctx context.Context, id int64) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM drops WHERE id = ?`, id); err != nil {
		return fmt.Errorf("store: delete drop %d: %w", id, err)
	}
	return nil
}

// Stats summarises what the service is holding, for the status panel.
type Stats struct {
	Drops int64
	Files int64
	Bytes int64
}

// Stats reports totals across live drops.
func (s *Store) Stats(ctx context.Context, now time.Time) (Stats, error) {
	var st Stats
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(total_bytes), 0) FROM drops
		 WHERE status = ? AND expires_at > ? AND blocked_at IS NULL`, StatusReady, now.Unix()).
		Scan(&st.Drops, &st.Bytes)
	if err != nil {
		return st, fmt.Errorf("store: stats: %w", err)
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM files f JOIN drops d ON d.id = f.drop_id
		 WHERE d.status = ? AND d.expires_at > ? AND d.blocked_at IS NULL`, StatusReady, now.Unix()).
		Scan(&st.Files); err != nil {
		return st, fmt.Errorf("store: stats files: %w", err)
	}
	return st, nil
}

// BlockDrop marks a share blocked as of at. It is idempotent: re-blocking an
// already-blocked share keeps the original block time.
func (s *Store) BlockDrop(ctx context.Context, id int64, at time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE drops SET blocked_at = ? WHERE id = ? AND blocked_at IS NULL`, at.Unix(), id)
	if err != nil {
		return fmt.Errorf("store: block drop %d: %w", id, err)
	}
	return nil
}

// UnblockDrop lifts a block, restoring normal serving and expiry.
func (s *Store) UnblockDrop(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE drops SET blocked_at = NULL WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: unblock drop %d: %w", id, err)
	}
	return nil
}

// Report is a filed rights-infringement report.
type Report struct {
	DropID     sql.NullInt64
	DropKey    string
	Reason     string
	Reporter   string
	ReporterIP string
	CreatedAt  time.Time
	Status     string
}

// CreateReport records a report.
func (s *Store) CreateReport(ctx context.Context, r *Report) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO reports (drop_id, drop_key, reason, reporter, reporter_ip, created_at, status)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		r.DropID, r.DropKey, nullIfEmpty(r.Reason), nullIfEmpty(r.Reporter),
		nullIfEmpty(r.ReporterIP), r.CreatedAt.Unix(), r.Status)
	if err != nil {
		return fmt.Errorf("store: create report: %w", err)
	}
	return nil
}

// SetReportStatus updates a report's handling status (e.g. open -> resolved).
func (s *Store) SetReportStatus(ctx context.Context, id int64, status string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE reports SET status = ? WHERE id = ?`, status, id)
	if err != nil {
		return fmt.Errorf("store: set report status: %w", err)
	}
	return nil
}

// OpenReportCount counts reports that still need attention.
func (s *Store) OpenReportCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM reports WHERE status = 'open'`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: open report count: %w", err)
	}
	return n, nil
}

// ReportView is a report joined with the current state of its target share,
// for the admin screen.
type ReportView struct {
	ID          int64
	DropID      int64 // 0 if the share is gone
	DropKey     string
	Reason      string
	Reporter    string
	ReporterIP  string
	CreatedAt   time.Time
	Status      string
	DropExists  bool
	DropBlocked bool
}

// ListReports returns the most recent reports for the admin screen, newest
// first, joined with whether the target share still exists and is blocked.
func (s *Store) ListReports(ctx context.Context, limit int) ([]*ReportView, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT r.id, r.drop_key,
		        COALESCE(r.reason, ''), COALESCE(r.reporter, ''), COALESCE(r.reporter_ip, ''),
		        r.created_at, r.status,
		        d.id IS NOT NULL, COALESCE(d.blocked_at IS NOT NULL, 0), COALESCE(d.id, 0)
		 FROM reports r LEFT JOIN drops d ON d.id = r.drop_id
		 ORDER BY r.created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list reports: %w", err)
	}
	defer rows.Close()

	var out []*ReportView
	for rows.Next() {
		var v ReportView
		var created int64
		var exists, blocked int
		if err := rows.Scan(&v.ID, &v.DropKey, &v.Reason, &v.Reporter, &v.ReporterIP,
			&created, &v.Status, &exists, &blocked, &v.DropID); err != nil {
			return nil, fmt.Errorf("store: scan report: %w", err)
		}
		v.CreatedAt = time.Unix(created, 0)
		v.DropExists = exists != 0
		v.DropBlocked = blocked != 0
		out = append(out, &v)
	}
	return out, rows.Err()
}

// DropView summarises a share for the admin screen. It never carries anything
// that could decrypt content — filenames stay sealed even here — only the
// metadata an operator needs to act: counts, sizes, the uploader address kept
// for disclosure, and whether it is blocked.
type DropView struct {
	ID           int64
	Key          string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	MaxDownloads int
	Downloads    int
	TotalBytes   int64
	Status       string
	Blocked      bool
	UploaderIP   string
	FileCount    int
	ReportCount  int
}

// ListDrops returns shares for the admin screen, newest first.
func (s *Store) ListDrops(ctx context.Context, limit int) ([]*DropView, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT d.id, d.key, d.created_at, d.expires_at, d.max_downloads, d.downloads,
		        d.total_bytes, d.status, d.blocked_at IS NOT NULL, COALESCE(d.uploader_ip, ''),
		        (SELECT COUNT(*) FROM files f WHERE f.drop_id = d.id),
		        (SELECT COUNT(*) FROM reports r WHERE r.drop_id = d.id)
		 FROM drops d ORDER BY d.created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list drops: %w", err)
	}
	defer rows.Close()

	var out []*DropView
	for rows.Next() {
		var v DropView
		var created, expires int64
		var blocked int
		if err := rows.Scan(&v.ID, &v.Key, &created, &expires, &v.MaxDownloads, &v.Downloads,
			&v.TotalBytes, &v.Status, &blocked, &v.UploaderIP, &v.FileCount, &v.ReportCount); err != nil {
			return nil, fmt.Errorf("store: scan drop view: %w", err)
		}
		v.CreatedAt = time.Unix(created, 0)
		v.ExpiresAt = time.Unix(expires, 0)
		v.Blocked = blocked != 0
		out = append(out, &v)
	}
	return out, rows.Err()
}

// jstZone buckets usage by Japan-time date, matching how the admin screen shows
// every timestamp.
var jstZone = time.FixedZone("JST", 9*3600)

// DayKey returns the JST date bucket ("YYYY-MM-DD") a moment falls in.
func DayKey(t time.Time) string { return t.In(jstZone).Format("2006-01-02") }

// UsageTotal is the lifetime aggregate since counting began.
type UsageTotal struct {
	Uploads   int64
	Downloads int64
	Bytes     int64
	Since     string // earliest day recorded, "" when nothing yet
}

// DailyUsage is one day's counters.
type DailyUsage struct {
	Day       string
	Uploads   int64
	Downloads int64
	Bytes     int64
}

// LiveStats is a snapshot of what is stored right now, broken down for the
// operator. It counts only ready (finalised) shares unless noted.
type LiveStats struct {
	ReadyDrops        int64
	TextDrops         int64
	FileDrops         int64
	Files             int64
	Bytes             int64
	DownloadsConsumed int64
	Pending           int64
	Blocked           int64
}

// BumpUsage adds to a day's counters, creating the row on first use. It is
// best-effort accounting: callers treat a failure as non-fatal.
func (s *Store) BumpUsage(ctx context.Context, day string, uploads, downloads int, bytes int64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO usage_daily (day, uploads, downloads, bytes) VALUES (?, ?, ?, ?)
		 ON CONFLICT(day) DO UPDATE SET
		   uploads = uploads + excluded.uploads,
		   downloads = downloads + excluded.downloads,
		   bytes = bytes + excluded.bytes`,
		day, uploads, downloads, bytes)
	if err != nil {
		return fmt.Errorf("store: bump usage: %w", err)
	}
	return nil
}

// UsageTotals sums the counters across all recorded days.
func (s *Store) UsageTotals(ctx context.Context) (UsageTotal, error) {
	var t UsageTotal
	var since sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(uploads),0), COALESCE(SUM(downloads),0), COALESCE(SUM(bytes),0), MIN(day)
		 FROM usage_daily`).Scan(&t.Uploads, &t.Downloads, &t.Bytes, &since)
	if err != nil {
		return t, fmt.Errorf("store: usage totals: %w", err)
	}
	if since.Valid {
		t.Since = since.String
	}
	return t, nil
}

// UsageDaily returns the most recent days' counters, newest first.
func (s *Store) UsageDaily(ctx context.Context, days int) ([]DailyUsage, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT day, uploads, downloads, bytes FROM usage_daily ORDER BY day DESC LIMIT ?`, days)
	if err != nil {
		return nil, fmt.Errorf("store: usage daily: %w", err)
	}
	defer rows.Close()
	var out []DailyUsage
	for rows.Next() {
		var d DailyUsage
		if err := rows.Scan(&d.Day, &d.Uploads, &d.Downloads, &d.Bytes); err != nil {
			return nil, fmt.Errorf("store: scan usage: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// LiveBreakdown reports the current stored state in one pass: ready shares by
// kind, files and bytes, downloads consumed, and pending/blocked counts.
func (s *Store) LiveBreakdown(ctx context.Context, now time.Time) (LiveStats, error) {
	var st LiveStats
	err := s.db.QueryRowContext(ctx,
		`SELECT
		   COUNT(*) FILTER (WHERE status = ? AND expires_at > ? AND blocked_at IS NULL),
		   COUNT(*) FILTER (WHERE status = ? AND expires_at > ? AND blocked_at IS NULL AND kind = 'text'),
		   COUNT(*) FILTER (WHERE status = ? AND expires_at > ? AND blocked_at IS NULL AND kind != 'text'),
		   COALESCE(SUM(total_bytes) FILTER (WHERE status = ? AND expires_at > ? AND blocked_at IS NULL), 0),
		   COALESCE(SUM(downloads)   FILTER (WHERE status = ? AND expires_at > ? AND blocked_at IS NULL), 0),
		   COUNT(*) FILTER (WHERE status = ?),
		   COUNT(*) FILTER (WHERE blocked_at IS NOT NULL)
		 FROM drops`,
		StatusReady, now.Unix(), StatusReady, now.Unix(), StatusReady, now.Unix(),
		StatusReady, now.Unix(), StatusReady, now.Unix(), StatusPending).
		Scan(&st.ReadyDrops, &st.TextDrops, &st.FileDrops, &st.Bytes, &st.DownloadsConsumed, &st.Pending, &st.Blocked)
	if err != nil {
		return st, fmt.Errorf("store: live breakdown: %w", err)
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM files f JOIN drops d ON d.id = f.drop_id
		 WHERE d.status = ? AND d.expires_at > ? AND d.blocked_at IS NULL`, StatusReady, now.Unix()).
		Scan(&st.Files); err != nil {
		return st, fmt.Errorf("store: live breakdown files: %w", err)
	}
	return st, nil
}

// TotalReportCount counts all reports ever filed.
func (s *Store) TotalReportCount(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM reports`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: total report count: %w", err)
	}
	return n, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// nullIfEmpty stores NULL rather than an empty string, so a missing address
// is distinguishable from a recorded blank.
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nilIfEmpty stores NULL rather than an empty blob, so an absent management
// hash is a clean NULL the manage-hash lookup can never match by accident.
func nilIfEmpty(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}
