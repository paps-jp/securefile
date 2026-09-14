package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/paps-jp/securefile/internal/cryptobox"
	"github.com/paps-jp/securefile/internal/store"
)

// DropInfo is what a recipient sees before entering a password: enough to know
// the link is live, and nothing about what it holds.
type DropInfo struct {
	Key           string
	ExpiresAt     time.Time
	Remaining     int
	FileCount     int
	TotalSize     int64
	DeleteAllowed bool
	// Kind is "file" or "text"; a text share is rendered inline as a message.
	Kind string
}

// Unlocked is a share after a correct password.
type Unlocked struct {
	Token         string
	ExpiresAt     time.Time
	Files         []UnlockedFile
	DeleteAllowed bool
}

// UnlockedFile is one file with its decrypted name.
type UnlockedFile struct {
	ID   int64
	Name string
	Size int64
}

// Peek reports that a share exists and is live, without revealing filenames.
//
// Sizes and counts are disclosed here because the download page has to say
// something useful before a password is entered, but names stay sealed: a
// filename frequently gives away more than the file's existence does.
func (s *Service) Peek(ctx context.Context, key string) (*DropInfo, error) {
	drop, err := s.st.LiveDropByKey(ctx, key, s.now())
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	files, err := s.st.Files(ctx, drop.ID)
	if err != nil {
		return nil, err
	}
	return &DropInfo{
		Key:           drop.Key,
		ExpiresAt:     drop.ExpiresAt,
		Remaining:     drop.MaxDownloads - drop.Downloads,
		FileCount:     len(files),
		TotalSize:     drop.TotalBytes,
		DeleteAllowed: drop.DeleteAllowed,
		Kind:          drop.Kind,
	}, nil
}

// Unlock verifies a share password and opens a download session.
//
// Unlocking does not consume one of the share's downloads. A recipient who
// mistypes, reloads, or simply checks that a link works should not burn the
// allowance; the count is spent when bytes actually move.
func (s *Service) Unlock(ctx context.Context, key, password string) (*Unlocked, error) {
	drop, err := s.st.LiveDropByKey(ctx, key, s.now())
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	dek, err := cryptobox.UnwrapKey(drop.WrappedDEK, password)
	if errors.Is(err, cryptobox.ErrWrongPassword) {
		return nil, ErrWrongPassword
	}
	if err != nil {
		return nil, err
	}

	records, err := s.st.Files(ctx, drop.ID)
	if err != nil {
		return nil, err
	}
	files := make([]UnlockedFile, 0, len(records))
	for _, f := range records {
		name, err := cryptobox.Open(dek, f.NameEnc)
		if err != nil {
			return nil, fmt.Errorf("service: decrypt file name: %w", err)
		}
		files = append(files, UnlockedFile{ID: f.ID, Name: string(name), Size: f.Size})
	}

	token, err := cryptobox.NewToken()
	if err != nil {
		return nil, err
	}
	expires := s.now().Add(s.cfg.DownloadTTL)
	s.down.put(token, &downloadSession{
		dropKey: drop.Key, dropID: drop.ID, dek: dek, expiresAt: expires,
	})
	return &Unlocked{Token: token, ExpiresAt: expires, Files: files, DeleteAllowed: drop.DeleteAllowed}, nil
}

// Lock ends a download session early.
func (s *Service) Lock(token string) { s.down.delete(token) }

// SessionFiles lists an unlocked session's files, for a page reload that still
// holds a valid token.
func (s *Service) SessionFiles(ctx context.Context, token string) (*Unlocked, error) {
	sess, ok := s.down.get(token, s.now())
	if !ok {
		return nil, ErrNotFound
	}
	records, err := s.st.Files(ctx, sess.dropID)
	if err != nil {
		return nil, err
	}
	files := make([]UnlockedFile, 0, len(records))
	for _, f := range records {
		name, err := cryptobox.Open(sess.dek, f.NameEnc)
		if err != nil {
			return nil, fmt.Errorf("service: decrypt file name: %w", err)
		}
		files = append(files, UnlockedFile{ID: f.ID, Name: string(name), Size: f.Size})
	}
	return &Unlocked{Token: token, ExpiresAt: sess.expiresAt, Files: files}, nil
}

// OpenFile returns a reader over one file's plaintext, starting at offset.
//
// The first call in a session consumes one download from the share's
// allowance; later calls in the same session are free, so a five-file share
// with a limit of one can still be fetched in full by its recipient.
func (s *Service) OpenFile(ctx context.Context, token string, fileID, offset int64) (io.ReadCloser, *UnlockedFile, error) {
	sess, ok := s.down.get(token, s.now())
	if !ok {
		return nil, nil, ErrNotFound
	}
	if err := s.down.claimOnce(sess, func() error {
		_, err := s.st.ClaimDownload(ctx, sess.dropKey, s.now())
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		// Count the download for statistics; best-effort, never fatal.
		_ = s.st.BumpUsage(ctx, store.DayKey(s.now()), 0, 1, 0)
		return nil
	}); err != nil {
		return nil, nil, err
	}

	file, err := s.st.FileByID(ctx, sess.dropID, fileID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	if offset < 0 || offset > file.Size {
		return nil, nil, fmt.Errorf("%w: offset %d outside file of %d bytes", ErrInvalid, offset, file.Size)
	}

	name, err := cryptobox.Open(sess.dek, file.NameEnc)
	if err != nil {
		return nil, nil, fmt.Errorf("service: decrypt file name: %w", err)
	}

	f, err := os.Open(s.blobPath(file.BlobPath))
	if err != nil {
		return nil, nil, fmt.Errorf("service: open blob: %w", err)
	}
	// An offset at exactly EOF is a valid empty range; OpenAt would fail
	// trying to read past the last chunk, so short-circuit it.
	if offset == file.Size {
		f.Close()
		return io.NopCloser(strings.NewReader("")), &UnlockedFile{ID: file.ID, Name: string(name), Size: file.Size}, nil
	}
	r, err := cryptobox.OpenAt(f, sess.dek, offset)
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("service: decrypt blob: %w", err)
	}
	return &fileReader{Reader: r, closer: f}, &UnlockedFile{ID: file.ID, Name: string(name), Size: file.Size}, nil
}

// fileReader pairs a decrypting reader with the underlying file handle so the
// caller closes both with one call.
type fileReader struct {
	io.Reader
	closer io.Closer
}

func (r *fileReader) Close() error { return r.closer.Close() }

// DeleteDrop removes a share's database rows and its stored bytes, and cuts
// off any session that had already unlocked it.
func (s *Service) DeleteDrop(ctx context.Context, drop *store.Drop) error {
	s.down.deleteByDrop(drop.ID)

	dir := filepath.Join(s.cfg.BlobRoot, drop.Key[:2], drop.Key)
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("service: remove blobs for %s: %w", drop.Key, err)
	}
	// The shard directory is removed only when it empties out; a non-empty
	// directory is the normal case and not an error.
	_ = os.Remove(filepath.Join(s.cfg.BlobRoot, drop.Key[:2]))

	return s.st.DeleteDrop(ctx, drop.ID)
}

// Stats reports what the service is currently holding.
func (s *Service) Stats(ctx context.Context) (store.Stats, error) {
	return s.st.Stats(ctx, s.now())
}

// StatTicket returns a ticket's file metadata without consuming one of the
// share's downloads.
//
// The transport layer needs the size before it can answer a range request, and
// a HEAD request needs nothing else at all. Charging a download for either
// would let a download manager's probe silently spend a recipient's single
// allowed retrieval.
func (s *Service) StatTicket(ctx context.Context, ticketID string) (*UnlockedFile, error) {
	token, fileID, err := s.redeem(ticketID)
	if err != nil {
		return nil, err
	}
	if fileID == ZipTicket {
		return nil, ErrInvalid
	}
	sess, ok := s.down.get(token, s.now())
	if !ok {
		return nil, ErrNotFound
	}
	file, err := s.st.FileByID(ctx, sess.dropID, fileID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	name, err := cryptobox.Open(sess.dek, file.NameEnc)
	if err != nil {
		return nil, fmt.Errorf("service: decrypt file name: %w", err)
	}
	return &UnlockedFile{ID: file.ID, Name: string(name), Size: file.Size}, nil
}

// DeleteBySession lets a recipient delete a share they have unlocked, but only
// if the uploader allowed it. It is the manual counterpart to expiry: once the
// recipient has what they came for, they can remove the files immediately
// rather than leaving them until the retention clock runs out.
func (s *Service) DeleteBySession(ctx context.Context, token string) error {
	sess, ok := s.down.get(token, s.now())
	if !ok {
		return ErrNotFound
	}
	drop, err := s.st.DropByID(ctx, sess.dropID)
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if !drop.DeleteAllowed {
		// The uploader did not permit recipient deletion; do not disclose more.
		return ErrNotFound
	}
	return s.DeleteDrop(ctx, drop)
}
