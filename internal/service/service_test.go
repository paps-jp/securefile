package service

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/paps-jp/securefile/internal/store"
)

func newService(t *testing.T, tweak func(*Config)) *Service {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(t.Context(), filepath.Join(dir, "meta.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	cfg := DefaultConfig(filepath.Join(dir, "blobs"))
	cfg.PartSize = 2 * chunkSize
	if tweak != nil {
		tweak(&cfg)
	}
	svc, err := New(st, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return svc
}

func body(n int) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(int64(n) * 7)).Read(b)
	return b
}

// uploadAll pushes a whole file through in part-sized pieces.
func uploadAll(t *testing.T, svc *Service, res *StartResult, fileID int64, data []byte) {
	t.Helper()
	for off := int64(0); off < int64(len(data)); off += res.PartSize {
		end := min(off+res.PartSize, int64(len(data)))
		got, err := svc.WriteParts(t.Context(), res.SessionID, res.Token, fileID, off, bytes.NewReader(data[off:end]))
		if err != nil {
			t.Fatalf("WriteParts at %d: %v", off, err)
		}
		if got != end {
			t.Fatalf("WriteParts at %d reported %d stored, want %d", off, got, end)
		}
	}
	if len(data) == 0 {
		if _, err := svc.WriteParts(t.Context(), res.SessionID, res.Token, fileID, 0, bytes.NewReader(nil)); err != nil {
			t.Fatalf("WriteParts empty: %v", err)
		}
	}
}

func TestUploadDownloadRoundTrip(t *testing.T) {
	ctx := t.Context()
	svc := newService(t, nil)

	docs := map[string][]byte{
		"報告書.pdf":    body(3*chunkSize + 517),
		"notes.txt":  body(42),
		"empty.dat":  {},
		"photo.jpeg": body(chunkSize),
	}
	req := StartRequest{Days: 7, MaxDownloads: 3}
	var order []string
	for name, data := range docs {
		req.Files = append(req.Files, FileRequest{Name: name, Size: int64(len(data))})
		order = append(order, name)
	}

	res, err := svc.StartUpload(ctx, req)
	if err != nil {
		t.Fatalf("StartUpload: %v", err)
	}
	if len(res.Password) == 0 {
		t.Fatal("StartUpload returned an empty password")
	}
	for i, f := range res.Files {
		uploadAll(t, svc, res, f.ID, docs[order[i]])
	}
	if _, err := svc.FinishUpload(ctx, res.SessionID, res.Token); err != nil {
		t.Fatalf("FinishUpload: %v", err)
	}

	// Before a password, the share reveals only that it exists.
	info, err := svc.Peek(ctx, res.Key)
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if info.FileCount != len(docs) {
		t.Errorf("Peek FileCount = %d, want %d", info.FileCount, len(docs))
	}

	if _, err := svc.Unlock(ctx, res.Key, "not-the-password"); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("Unlock with wrong password: got %v, want ErrWrongPassword", err)
	}

	un, err := svc.Unlock(ctx, res.Key, res.Password)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if len(un.Files) != len(docs) {
		t.Fatalf("Unlock returned %d files, want %d", len(un.Files), len(docs))
	}
	for _, f := range un.Files {
		want, ok := docs[f.Name]
		if !ok {
			t.Fatalf("Unlock returned unexpected file name %q", f.Name)
		}
		r, meta, err := svc.OpenFile(ctx, un.Token, f.ID, 0)
		if err != nil {
			t.Fatalf("OpenFile %q: %v", f.Name, err)
		}
		got, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatalf("read %q: %v", f.Name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%q: got %d bytes, want %d", f.Name, len(got), len(want))
		}
		if meta.Name != f.Name {
			t.Errorf("OpenFile name = %q, want %q", meta.Name, f.Name)
		}
	}
}

// TestResumeAfterInterruption is the reason this service exists in this shape:
// a transfer cut partway through must continue from where it stopped.
func TestResumeAfterInterruption(t *testing.T) {
	ctx := t.Context()
	svc := newService(t, nil)
	data := body(5*chunkSize + 900)

	res, err := svc.StartUpload(ctx, StartRequest{
		Files:        []FileRequest{{Name: "big.bin", Size: int64(len(data))}},
		Days:         3,
		MaxDownloads: 5,
	})
	if err != nil {
		t.Fatalf("StartUpload: %v", err)
	}
	fileID := res.Files[0].ID

	// Send two parts, then stop as if the connection dropped.
	for off := int64(0); off < 2*res.PartSize; off += res.PartSize {
		if _, err := svc.WriteParts(ctx, res.SessionID, res.Token, fileID, off,
			bytes.NewReader(data[off:off+res.PartSize])); err != nil {
			t.Fatalf("WriteParts at %d: %v", off, err)
		}
	}

	// A client that reconnects asks where to continue from.
	state, err := svc.UploadState(ctx, res.SessionID, res.Token)
	if err != nil {
		t.Fatalf("UploadState: %v", err)
	}
	resume := state.Files[0].Received
	if resume != 2*res.PartSize {
		t.Fatalf("resume offset = %d, want %d", resume, 2*res.PartSize)
	}

	// Appending at the wrong offset must be corrected, not silently accepted.
	var mismatch *OffsetMismatch
	_, err = svc.WriteParts(ctx, res.SessionID, res.Token, fileID, 0, bytes.NewReader(data))
	if !errors.As(err, &mismatch) {
		t.Fatalf("wrong-offset write: got %v, want *OffsetMismatch", err)
	}
	if mismatch.Expected != resume {
		t.Errorf("OffsetMismatch.Expected = %d, want %d", mismatch.Expected, resume)
	}

	for off := resume; off < int64(len(data)); off += res.PartSize {
		end := min(off+res.PartSize, int64(len(data)))
		if _, err := svc.WriteParts(ctx, res.SessionID, res.Token, fileID, off,
			bytes.NewReader(data[off:end])); err != nil {
			t.Fatalf("WriteParts resume at %d: %v", off, err)
		}
	}
	if _, err := svc.FinishUpload(ctx, res.SessionID, res.Token); err != nil {
		t.Fatalf("FinishUpload: %v", err)
	}

	un, err := svc.Unlock(ctx, res.Key, res.Password)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	r, _, err := svc.OpenFile(ctx, un.Token, un.Files[0].ID, 0)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer r.Close()
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Error("resumed upload did not reproduce the original bytes")
	}
}

func TestRangedDownload(t *testing.T) {
	ctx := t.Context()
	svc := newService(t, nil)
	data := body(3*chunkSize + 77)

	res, err := svc.StartUpload(ctx, StartRequest{
		Files: []FileRequest{{Name: "r.bin", Size: int64(len(data))}}, Days: 1, MaxDownloads: 9,
	})
	if err != nil {
		t.Fatalf("StartUpload: %v", err)
	}
	uploadAll(t, svc, res, res.Files[0].ID, data)
	if _, err := svc.FinishUpload(ctx, res.SessionID, res.Token); err != nil {
		t.Fatalf("FinishUpload: %v", err)
	}

	un, err := svc.Unlock(ctx, res.Key, res.Password)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	for _, off := range []int64{0, 1, chunkSize, chunkSize + 1000, int64(len(data)) - 5, int64(len(data))} {
		r, _, err := svc.OpenFile(ctx, un.Token, un.Files[0].ID, off)
		if err != nil {
			t.Fatalf("OpenFile at %d: %v", off, err)
		}
		got, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatalf("ReadAll at %d: %v", off, err)
		}
		if !bytes.Equal(got, data[off:]) {
			t.Errorf("range from %d: got %d bytes, want %d", off, len(got), len(data)-int(off))
		}
	}
}

// TestDownloadLimitCountsSessionsNotFiles checks the behaviour the UI
// promises: a limit of one lets one recipient fetch every file in the share.
func TestDownloadLimitCountsSessionsNotFiles(t *testing.T) {
	ctx := t.Context()
	svc := newService(t, nil)

	res, err := svc.StartUpload(ctx, StartRequest{
		Files: []FileRequest{
			{Name: "a.txt", Size: 10},
			{Name: "b.txt", Size: 20},
		},
		Days: 1, MaxDownloads: 1,
	})
	if err != nil {
		t.Fatalf("StartUpload: %v", err)
	}
	uploadAll(t, svc, res, res.Files[0].ID, body(10))
	uploadAll(t, svc, res, res.Files[1].ID, body(20))
	if _, err := svc.FinishUpload(ctx, res.SessionID, res.Token); err != nil {
		t.Fatalf("FinishUpload: %v", err)
	}

	un, err := svc.Unlock(ctx, res.Key, res.Password)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	for _, f := range un.Files {
		r, _, err := svc.OpenFile(ctx, un.Token, f.ID, 0)
		if err != nil {
			t.Fatalf("OpenFile %q within one session: %v", f.Name, err)
		}
		r.Close()
	}

	// The allowance is now spent: a second recipient gets nothing.
	if _, err := svc.Unlock(ctx, res.Key, res.Password); !errors.Is(err, ErrNotFound) {
		t.Errorf("second unlock after limit: got %v, want ErrNotFound", err)
	}
	if _, err := svc.Peek(ctx, res.Key); !errors.Is(err, ErrNotFound) {
		t.Errorf("Peek after limit: got %v, want ErrNotFound", err)
	}
}

func TestUnalignedNonFinalPartRejected(t *testing.T) {
	ctx := t.Context()
	svc := newService(t, nil)
	size := int64(4 * chunkSize)

	res, err := svc.StartUpload(ctx, StartRequest{
		Files: []FileRequest{{Name: "u.bin", Size: size}}, Days: 1, MaxDownloads: 1,
	})
	if err != nil {
		t.Fatalf("StartUpload: %v", err)
	}
	// A part that is neither the end of the file nor a whole number of chunks
	// would leave a stream that cannot be resumed or ranged over.
	_, err = svc.WriteParts(ctx, res.SessionID, res.Token, res.Files[0].ID, 0, bytes.NewReader(body(chunkSize+5)))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("unaligned part: got %v, want ErrInvalid", err)
	}

	// The file must be left at a resumable length, not a torn one.
	state, err := svc.UploadState(ctx, res.SessionID, res.Token)
	if err != nil {
		t.Fatalf("UploadState: %v", err)
	}
	if state.Files[0].Received != 0 {
		t.Errorf("after a rejected part, Received = %d, want 0", state.Files[0].Received)
	}
}

func TestFinishRejectsIncompleteUpload(t *testing.T) {
	ctx := t.Context()
	svc := newService(t, nil)

	res, err := svc.StartUpload(ctx, StartRequest{
		Files: []FileRequest{{Name: "partial.bin", Size: 4 * chunkSize}}, Days: 1, MaxDownloads: 1,
	})
	if err != nil {
		t.Fatalf("StartUpload: %v", err)
	}
	if _, err := svc.WriteParts(ctx, res.SessionID, res.Token, res.Files[0].ID, 0,
		bytes.NewReader(body(2*chunkSize))); err != nil {
		t.Fatalf("WriteParts: %v", err)
	}
	if _, err := svc.FinishUpload(ctx, res.SessionID, res.Token); !errors.Is(err, ErrInvalid) {
		t.Errorf("FinishUpload on a partial file: got %v, want ErrInvalid", err)
	}
	if _, err := svc.Peek(ctx, res.Key); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unfinished share is visible: got %v, want ErrNotFound", err)
	}
}

func TestExpiredShareIsGone(t *testing.T) {
	ctx := t.Context()
	svc := newService(t, nil)

	res, err := svc.StartUpload(ctx, StartRequest{
		Files: []FileRequest{{Name: "x.txt", Size: 5}}, Days: 1, MaxDownloads: 5,
	})
	if err != nil {
		t.Fatalf("StartUpload: %v", err)
	}
	uploadAll(t, svc, res, res.Files[0].ID, body(5))
	if _, err := svc.FinishUpload(ctx, res.SessionID, res.Token); err != nil {
		t.Fatalf("FinishUpload: %v", err)
	}

	svc.setNow(func() time.Time { return time.Now().AddDate(0, 0, 2) })
	if _, err := svc.Peek(ctx, res.Key); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired share is still visible: got %v, want ErrNotFound", err)
	}
	if _, err := svc.Unlock(ctx, res.Key, res.Password); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired share still unlocks: got %v, want ErrNotFound", err)
	}
}

func TestLimitsRejected(t *testing.T) {
	ctx := t.Context()
	svc := newService(t, func(c *Config) {
		c.MaxFiles = 2
		c.MaxTotalBytes = 1000
		c.MaxDays = 30
		c.MaxDownloads = 10
	})

	cases := []struct {
		name string
		req  StartRequest
		want error
	}{
		{"no files", StartRequest{Days: 1, MaxDownloads: 1}, ErrInvalid},
		{"too many files", StartRequest{Files: []FileRequest{{Name: "a", Size: 1}, {Name: "b", Size: 1}, {Name: "c", Size: 1}}, Days: 1, MaxDownloads: 1}, ErrTooLarge},
		{"too many bytes", StartRequest{Files: []FileRequest{{Name: "a", Size: 2000}}, Days: 1, MaxDownloads: 1}, ErrTooLarge},
		{"retention too long", StartRequest{Files: []FileRequest{{Name: "a", Size: 1}}, Days: 90, MaxDownloads: 1}, ErrInvalid},
		{"download limit too high", StartRequest{Files: []FileRequest{{Name: "a", Size: 1}}, Days: 1, MaxDownloads: 99}, ErrInvalid},
		{"empty name", StartRequest{Files: []FileRequest{{Name: "", Size: 1}}, Days: 1, MaxDownloads: 1}, ErrInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := svc.StartUpload(ctx, c.req); !errors.Is(err, c.want) {
				t.Errorf("got %v, want %v", err, c.want)
			}
		})
	}
}

func TestCancelUploadRemovesEverything(t *testing.T) {
	ctx := t.Context()
	svc := newService(t, nil)

	res, err := svc.StartUpload(ctx, StartRequest{
		Files: []FileRequest{{Name: "gone.bin", Size: 2 * chunkSize}}, Days: 1, MaxDownloads: 1,
	})
	if err != nil {
		t.Fatalf("StartUpload: %v", err)
	}
	if _, err := svc.WriteParts(ctx, res.SessionID, res.Token, res.Files[0].ID, 0,
		bytes.NewReader(body(2*chunkSize))); err != nil {
		t.Fatalf("WriteParts: %v", err)
	}
	if err := svc.CancelUpload(ctx, res.SessionID, res.Token); err != nil {
		t.Fatalf("CancelUpload: %v", err)
	}
	if _, err := svc.UploadState(ctx, res.SessionID, res.Token); !errors.Is(err, ErrNotFound) {
		t.Errorf("session survived cancel: got %v, want ErrNotFound", err)
	}
	if _, err := svc.Peek(ctx, res.Key); !errors.Is(err, ErrNotFound) {
		t.Errorf("share survived cancel: got %v, want ErrNotFound", err)
	}
}

// TestBadUploadTokenRejected checks that knowing a session ID is not enough:
// the token is what proves the caller started the upload.
func TestBadUploadTokenRejected(t *testing.T) {
	ctx := t.Context()
	svc := newService(t, nil)

	res, err := svc.StartUpload(ctx, StartRequest{
		Files: []FileRequest{{Name: "a.bin", Size: 10}}, Days: 1, MaxDownloads: 1,
	})
	if err != nil {
		t.Fatalf("StartUpload: %v", err)
	}
	if _, err := svc.WriteParts(ctx, res.SessionID, "wrong-token", res.Files[0].ID, 0,
		bytes.NewReader(body(10))); !errors.Is(err, ErrNotFound) {
		t.Errorf("write with a bad token: got %v, want ErrNotFound", err)
	}
}

// TestMaxUploadBytesCurve checks the size cap shrinks with retention and
// download count, matching the configured anchors.
func TestMaxUploadBytesCurve(t *testing.T) {
	cfg := DefaultConfig(t.TempDir())
	// Anchors: 1 day -> 10 GiB, 100 days -> 500 MiB.
	if got := cfg.MaxUploadBytes(1, 1); got != 10<<30 {
		t.Errorf("at 1 day/1 dl: got %d, want %d", got, int64(10<<30))
	}
	if got := cfg.MaxUploadBytes(100, 1); got != 500<<20 {
		t.Errorf("at 100 days/1 dl: got %d, want %d", got, int64(500<<20))
	}
	// A mid retention is between the two, and monotonically decreasing.
	a := cfg.MaxUploadBytes(1, 1)
	b := cfg.MaxUploadBytes(30, 1)
	c := cfg.MaxUploadBytes(100, 1)
	if !(a > b && b > c) {
		t.Errorf("cap should decrease with days: %d, %d, %d", a, b, c)
	}
	// Downloads tighten it too: the smaller of the two dimensions wins.
	if got := cfg.MaxUploadBytes(1, 500); got != 500<<20 {
		t.Errorf("at 1 day/500 dl: got %d, want %d (downloads should bind)", got, int64(500<<20))
	}
}

// TestUploadRejectedOverDynamicLimit checks the service enforces the curve.
func TestUploadRejectedOverDynamicLimit(t *testing.T) {
	svc := newService(t, nil) // DefaultConfig anchors
	// 100 days caps at 500 MiB; ask for 600 MiB.
	_, err := svc.StartUpload(t.Context(), StartRequest{
		Files:        []FileRequest{{Name: "big.bin", Size: 600 << 20}},
		Days:         100,
		MaxDownloads: 1,
	})
	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("600 MiB at 100 days: got %v, want ErrTooLarge", err)
	}
	// The same size is fine at 1 day (cap 10 GiB).
	res, err := svc.StartUpload(t.Context(), StartRequest{
		Files:        []FileRequest{{Name: "big.bin", Size: 600 << 20}},
		Days:         1,
		MaxDownloads: 1,
	})
	if err != nil {
		t.Errorf("600 MiB at 1 day: unexpected error %v", err)
	}
	if res != nil {
		svc.CancelUpload(t.Context(), res.SessionID, res.Token)
	}
}

// TestTextShareAndManage covers a secret-message share and the sender's
// management link: kind flows through Peek, and the management token can read
// status and delete the share while a wrong token discloses nothing.
func TestTextShareAndManage(t *testing.T) {
	ctx := t.Context()
	svc := newService(t, nil)

	msg := []byte("これは秘密のメッセージ / a secret")
	res, err := svc.StartUpload(ctx, StartRequest{
		Files:        []FileRequest{{Name: "message.txt", Size: int64(len(msg))}},
		Days:         7,
		MaxDownloads: 3,
		Kind:         "text",
		Manage:       true,
	})
	if err != nil {
		t.Fatalf("StartUpload: %v", err)
	}
	if res.ManageToken == "" {
		t.Fatal("StartUpload with Manage returned no management token")
	}
	uploadAll(t, svc, res, res.Files[0].ID, msg)
	if _, err := svc.FinishUpload(ctx, res.SessionID, res.Token); err != nil {
		t.Fatalf("FinishUpload: %v", err)
	}

	// Peek reports the share as a text message.
	info, err := svc.Peek(ctx, res.Key)
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if info.Kind != "text" {
		t.Errorf("Peek Kind = %q, want text", info.Kind)
	}

	// A text share must carry exactly one item.
	if _, err := svc.StartUpload(ctx, StartRequest{
		Files:        []FileRequest{{Name: "a.txt", Size: 1}, {Name: "b.txt", Size: 1}},
		Days:         7,
		MaxDownloads: 1,
		Kind:         "text",
	}); !errors.Is(err, ErrInvalid) {
		t.Errorf("text share with two files: got %v, want ErrInvalid", err)
	}

	// The management token reads status; a wrong token is indistinguishable
	// from a missing share.
	view, err := svc.ManageStatus(ctx, res.ManageToken)
	if err != nil {
		t.Fatalf("ManageStatus: %v", err)
	}
	if view.Kind != "text" || view.MaxDownloads != 3 || view.Downloads != 0 {
		t.Errorf("ManageStatus = %+v, want text/3/0", view)
	}
	if _, err := svc.ManageStatus(ctx, "not-a-real-token-000000000000000"); !errors.Is(err, ErrNotFound) {
		t.Errorf("ManageStatus wrong token: got %v, want ErrNotFound", err)
	}

	// A download shows up in the management view.
	un, err := svc.Unlock(ctx, res.Key, res.Password)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	r, _, err := svc.OpenFile(ctx, un.Token, un.Files[0].ID, 0)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	got, _ := io.ReadAll(r)
	r.Close()
	if !bytes.Equal(got, msg) {
		t.Errorf("message content = %q, want %q", got, msg)
	}
	if view, err = svc.ManageStatus(ctx, res.ManageToken); err != nil {
		t.Fatalf("ManageStatus after download: %v", err)
	}
	if view.Downloads != 1 {
		t.Errorf("Downloads after one fetch = %d, want 1", view.Downloads)
	}

	// The sender deletes the share; afterwards nothing resolves.
	if err := svc.ManageDelete(ctx, res.ManageToken); err != nil {
		t.Fatalf("ManageDelete: %v", err)
	}
	if _, err := svc.Peek(ctx, res.Key); !errors.Is(err, ErrNotFound) {
		t.Errorf("Peek after delete: got %v, want ErrNotFound", err)
	}
	if _, err := svc.ManageStatus(ctx, res.ManageToken); !errors.Is(err, ErrNotFound) {
		t.Errorf("ManageStatus after delete: got %v, want ErrNotFound", err)
	}
}
