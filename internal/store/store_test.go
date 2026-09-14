package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.Context(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func newDrop(t *testing.T, s *Store, key string, maxDownloads int, ttl time.Duration) *Drop {
	t.Helper()
	now := time.Now()
	d, err := s.CreateDrop(t.Context(), &Drop{
		Key:          key,
		WrappedDEK:   []byte("wrapped"),
		CreatedAt:    now,
		ExpiresAt:    now.Add(ttl),
		MaxDownloads: maxDownloads,
	}, nil, "")
	if err != nil {
		t.Fatalf("CreateDrop: %v", err)
	}
	return d
}

func TestDropLifecycle(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	d := newDrop(t, s, "abc123", 3, time.Hour)

	f, err := s.AddFile(ctx, &File{DropID: d.ID, Ordinal: 0, NameEnc: []byte("sealed"), Size: 100, BlobPath: "a/b"})
	if err != nil {
		t.Fatalf("AddFile: %v", err)
	}

	// A pending drop must not be visible to recipients.
	if _, err := s.LiveDropByKey(ctx, "abc123", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("pending drop is live: got %v, want ErrNotFound", err)
	}

	// Finalizing with a short file must fail rather than publish a partial drop.
	if err := s.Finalize(ctx, d.ID); err == nil {
		t.Error("Finalize accepted a drop with an incomplete file")
	}

	if err := s.SetReceived(ctx, f.ID, 100); err != nil {
		t.Fatalf("SetReceived: %v", err)
	}
	if err := s.Finalize(ctx, d.ID); err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	live, err := s.LiveDropByKey(ctx, "abc123", time.Now())
	if err != nil {
		t.Fatalf("LiveDropByKey: %v", err)
	}
	if live.TotalBytes != 100 {
		t.Errorf("TotalBytes = %d, want 100", live.TotalBytes)
	}
	if live.Status != StatusReady {
		t.Errorf("Status = %q, want %q", live.Status, StatusReady)
	}
}

// TestClaimDownloadIsAtomic is the property that makes "download limit 1"
// mean one: concurrent claims must not exceed the cap.
func TestClaimDownloadIsAtomic(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	const limit = 5
	d := newDrop(t, s, "race01", limit, time.Hour)

	f, err := s.AddFile(ctx, &File{DropID: d.ID, NameEnc: []byte("x"), Size: 1, BlobPath: "p"})
	if err != nil {
		t.Fatalf("AddFile: %v", err)
	}
	if err := s.SetReceived(ctx, f.ID, 1); err != nil {
		t.Fatalf("SetReceived: %v", err)
	}
	if err := s.Finalize(ctx, d.ID); err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	granted := 0
	for range limit * 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.ClaimDownload(ctx, "race01", time.Now()); err == nil {
				mu.Lock()
				granted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if granted != limit {
		t.Errorf("granted %d downloads, want exactly %d", granted, limit)
	}
	if _, err := s.LiveDropByKey(ctx, "race01", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("exhausted drop is still live: got %v, want ErrNotFound", err)
	}
}

func TestExpiredDropIsNotLive(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	d := newDrop(t, s, "old001", 10, -time.Minute)

	f, _ := s.AddFile(ctx, &File{DropID: d.ID, NameEnc: []byte("x"), Size: 0, BlobPath: "p"})
	_ = f
	if err := s.Finalize(ctx, d.ID); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if _, err := s.LiveDropByKey(ctx, "old001", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired drop is live: got %v, want ErrNotFound", err)
	}
	if _, err := s.ClaimDownload(ctx, "old001", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("claimed a download on an expired drop: got %v, want ErrNotFound", err)
	}
}

func TestReapable(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	now := time.Now()

	expired := newDrop(t, s, "expire", 10, -time.Minute)
	stale := newDrop(t, s, "stale1", 10, time.Hour) // stays pending
	fresh := newDrop(t, s, "fresh1", 10, time.Hour)
	f, _ := s.AddFile(ctx, &File{DropID: fresh.ID, NameEnc: []byte("x"), Size: 0, BlobPath: "p"})
	_ = f
	if err := s.Finalize(ctx, fresh.ID); err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	got, err := s.Reapable(ctx, now, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Reapable: %v", err)
	}
	keys := map[string]bool{}
	for _, d := range got {
		keys[d.Key] = true
	}
	if !keys[expired.Key] {
		t.Error("expired drop was not reapable")
	}
	if !keys[stale.Key] {
		t.Error("stale pending drop was not reapable")
	}
	if keys[fresh.Key] {
		t.Error("fresh drop was reported as reapable")
	}
}

func TestFileByIDIsScopedToDrop(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	a := newDrop(t, s, "dropaa", 5, time.Hour)
	b := newDrop(t, s, "dropbb", 5, time.Hour)

	fb, err := s.AddFile(ctx, &File{DropID: b.ID, NameEnc: []byte("x"), Size: 1, BlobPath: "p"})
	if err != nil {
		t.Fatalf("AddFile: %v", err)
	}
	// Holding a session for drop A must not reach drop B's file.
	if _, err := s.FileByID(ctx, a.ID, fb.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("cross-drop file access: got %v, want ErrNotFound", err)
	}
}

func TestDeleteDropCascades(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	d := newDrop(t, s, "cascad", 5, time.Hour)
	if _, err := s.AddFile(ctx, &File{DropID: d.ID, NameEnc: []byte("x"), Size: 1, BlobPath: "p"}); err != nil {
		t.Fatalf("AddFile: %v", err)
	}
	if err := s.DeleteDrop(ctx, d.ID); err != nil {
		t.Fatalf("DeleteDrop: %v", err)
	}
	files, err := s.Files(ctx, d.ID)
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("after DeleteDrop, %d file rows remain", len(files))
	}
}

func TestUploadSession(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	d := newDrop(t, s, "sess01", 5, time.Hour)
	now := time.Now()

	sess := &UploadSession{ID: "tok", DropID: d.ID, Wrapped: []byte("w"), ExpiresAt: now.Add(time.Hour)}
	if err := s.CreateUploadSession(ctx, sess); err != nil {
		t.Fatalf("CreateUploadSession: %v", err)
	}
	got, err := s.UploadSessionByID(ctx, "tok", now)
	if err != nil {
		t.Fatalf("UploadSessionByID: %v", err)
	}
	if got.DropID != d.ID {
		t.Errorf("DropID = %d, want %d", got.DropID, d.ID)
	}
	if _, err := s.UploadSessionByID(ctx, "tok", now.Add(2*time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired session returned: got %v, want ErrNotFound", err)
	}
}

// TestMigrationAddsColumns checks that opening a database created without the
// newer columns transparently adds them, without losing data.
func TestMigrationAddsColumns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old.db")

	// Simulate an old database: create the drops table without the new columns.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	_, err = raw.Exec(`CREATE TABLE drops (
		id INTEGER PRIMARY KEY, key TEXT NOT NULL UNIQUE, wrapped_dek BLOB NOT NULL,
		created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, max_downloads INTEGER NOT NULL,
		downloads INTEGER NOT NULL DEFAULT 0, total_bytes INTEGER NOT NULL DEFAULT 0,
		status TEXT NOT NULL DEFAULT 'pending', uploader_hash BLOB);
		INSERT INTO drops (key, wrapped_dek, created_at, expires_at, max_downloads, status)
		VALUES ('oldkey12345678', x'00', 1, 9999999999, 5, 'ready');`)
	if err != nil {
		t.Fatalf("seed old db: %v", err)
	}
	raw.Close()

	// Opening through Store must add the columns and keep the row.
	s, err := Open(t.Context(), path)
	if err != nil {
		t.Fatalf("Open (migrate): %v", err)
	}
	defer s.Close()

	drop, err := s.DropByKey(t.Context(), "oldkey12345678")
	if err != nil {
		t.Fatalf("DropByKey after migrate: %v", err)
	}
	if drop.DeleteAllowed {
		t.Error("migrated row should default delete_allowed to false")
	}

	// Re-opening must be idempotent (no error from re-adding columns).
	s2, err := Open(t.Context(), path)
	if err != nil {
		t.Fatalf("re-open: %v", err)
	}
	s2.Close()
}

func TestUsageCounters(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)

	day1, day2 := "2026-09-13", "2026-09-14"
	// Two uploads and one download on day 1; one download on day 2.
	if err := s.BumpUsage(ctx, day1, 1, 0, 1000); err != nil {
		t.Fatalf("BumpUsage: %v", err)
	}
	if err := s.BumpUsage(ctx, day1, 1, 1, 2000); err != nil {
		t.Fatalf("BumpUsage: %v", err)
	}
	if err := s.BumpUsage(ctx, day2, 0, 1, 0); err != nil {
		t.Fatalf("BumpUsage: %v", err)
	}

	tot, err := s.UsageTotals(ctx)
	if err != nil {
		t.Fatalf("UsageTotals: %v", err)
	}
	if tot.Uploads != 2 || tot.Downloads != 2 || tot.Bytes != 3000 {
		t.Errorf("totals = %+v, want uploads 2, downloads 2, bytes 3000", tot)
	}
	if tot.Since != day1 {
		t.Errorf("Since = %q, want %q", tot.Since, day1)
	}

	daily, err := s.UsageDaily(ctx, 14)
	if err != nil {
		t.Fatalf("UsageDaily: %v", err)
	}
	if len(daily) != 2 || daily[0].Day != day2 { // newest first
		t.Fatalf("daily = %+v, want 2 rows newest first", daily)
	}
	if daily[1].Uploads != 2 || daily[1].Bytes != 3000 {
		t.Errorf("day1 row = %+v, want uploads 2, bytes 3000", daily[1])
	}
}

func TestLiveBreakdown(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	now := time.Now()

	// A ready file share, a ready text share, one pending, one blocked.
	mk := func(key, kind, status string, blocked bool) {
		d, err := s.CreateDrop(ctx, &Drop{
			Key: key, WrappedDEK: []byte("w"), CreatedAt: now,
			ExpiresAt: now.Add(time.Hour), MaxDownloads: 5, Kind: kind,
		}, nil, "")
		if err != nil {
			t.Fatalf("CreateDrop: %v", err)
		}
		if status == StatusReady {
			if _, err := s.AddFile(ctx, &File{DropID: d.ID, Ordinal: 0, NameEnc: []byte("n"), Size: 10, BlobPath: "p"}); err != nil {
				t.Fatalf("AddFile: %v", err)
			}
			if err := s.SetReceived(ctx, 0, 0); err == nil { /* ignore */
			}
			if _, err := s.db.ExecContext(ctx, `UPDATE files SET received = size WHERE drop_id = ?`, d.ID); err != nil {
				t.Fatalf("mark received: %v", err)
			}
			if err := s.Finalize(ctx, d.ID); err != nil {
				t.Fatalf("Finalize: %v", err)
			}
		}
		if blocked {
			if err := s.BlockDrop(ctx, d.ID, now); err != nil {
				t.Fatalf("BlockDrop: %v", err)
			}
		}
	}
	mk("filekey0000001", "file", StatusReady, false)
	mk("textkey0000001", "text", StatusReady, false)
	mk("pendingkey0001", "file", StatusPending, false)
	mk("blockedkey0001", "file", StatusReady, true)

	live, err := s.LiveBreakdown(ctx, now)
	if err != nil {
		t.Fatalf("LiveBreakdown: %v", err)
	}
	if live.ReadyDrops != 2 || live.FileDrops != 1 || live.TextDrops != 1 {
		t.Errorf("ready=%d file=%d text=%d, want 2/1/1", live.ReadyDrops, live.FileDrops, live.TextDrops)
	}
	if live.Pending != 1 || live.Blocked != 1 {
		t.Errorf("pending=%d blocked=%d, want 1/1", live.Pending, live.Blocked)
	}
	if live.Files != 2 {
		t.Errorf("files=%d, want 2 (blocked share excluded)", live.Files)
	}
}
