package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/paps-jp/securefile/internal/cryptobox"
	"github.com/paps-jp/securefile/internal/store"
)

// UploadState is what a client needs to resume: how much of each file the
// server already holds.
type UploadState struct {
	Key      string
	PartSize int64
	Files    []FileProgress
}

// FileProgress is one file's stored length.
type FileProgress struct {
	ID       int64
	Size     int64
	Received int64
}

// resolveSession loads an upload session and recovers the data encryption key
// from the client's token. The key is reconstructed per request and never
// cached, so it exists on the server only while a part is being written.
func (s *Service) resolveSession(ctx context.Context, sessionID, token string) (*store.UploadSession, []byte, error) {
	sess, err := s.st.UploadSessionByID(ctx, sessionID, s.now())
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	dek, err := cryptobox.UnwrapKeyWithToken(sess.Wrapped, token, "upload")
	if err != nil {
		// A bad token is indistinguishable from a missing session on purpose.
		return nil, nil, ErrNotFound
	}
	return sess, dek, nil
}

// UploadState reports how far each file in a session has got.
func (s *Service) UploadState(ctx context.Context, sessionID, token string) (*UploadState, error) {
	sess, _, err := s.resolveSession(ctx, sessionID, token)
	if err != nil {
		return nil, err
	}
	drop, err := s.st.DropByID(ctx, sess.DropID)
	if err != nil {
		return nil, err
	}
	files, err := s.st.Files(ctx, sess.DropID)
	if err != nil {
		return nil, err
	}
	out := &UploadState{Key: drop.Key, PartSize: s.cfg.PartSize}
	for _, f := range files {
		out.Files = append(out.Files, FileProgress{ID: f.ID, Size: f.Size, Received: f.Received})
	}
	return out, nil
}

// WriteParts appends one upload part to a file and returns the new stored
// length.
//
// offset must equal what the server already holds; a mismatch returns
// *OffsetMismatch carrying the expected value so a client that lost track — a
// retried request, a reconnect after a dropped link — can seek and continue
// instead of starting the file again.
func (s *Service) WriteParts(ctx context.Context, sessionID, token string, fileID, offset int64, body io.Reader) (int64, error) {
	sess, dek, err := s.resolveSession(ctx, sessionID, token)
	if err != nil {
		return 0, err
	}
	file, err := s.st.FileByID(ctx, sess.DropID, fileID)
	if errors.Is(err, store.ErrNotFound) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	if file.Received >= file.Size {
		return file.Received, nil // already complete; a duplicate part is harmless
	}
	if offset != file.Received {
		return 0, &OffsetMismatch{FileID: fileID, Expected: file.Received, Got: offset}
	}

	path := s.blobPath(file.BlobPath)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return 0, fmt.Errorf("service: open blob: %w", err)
	}
	defer f.Close()

	w, err := s.writerAt(f, dek, offset)
	if err != nil {
		return 0, err
	}

	// Cap the read at what the file still needs, so a client that sends more
	// than it declared cannot grow the share past its accounted size.
	remaining := file.Size - offset
	n, err := io.Copy(w, io.LimitReader(body, remaining))
	if err != nil {
		return 0, fmt.Errorf("service: store part: %w", err)
	}

	newLen := offset + n
	if newLen >= file.Size {
		// Final part: seal with the end-of-stream marker.
		if err := w.Close(); err != nil {
			return 0, fmt.Errorf("service: seal file: %w", err)
		}
	} else if err := w.FlushFull(); err != nil {
		// A non-final part that is not chunk-aligned cannot be resumed from.
		// Reject it and keep the file at its previous length.
		if err := f.Truncate(ciphertextLenFor(offset)); err != nil {
			return 0, fmt.Errorf("service: roll back unaligned part: %w", err)
		}
		return 0, fmt.Errorf("%w: a non-final part must be a multiple of %d bytes", ErrInvalid, chunkSize)
	}

	if err := f.Sync(); err != nil {
		return 0, fmt.Errorf("service: sync blob: %w", err)
	}
	if err := s.st.SetReceived(ctx, fileID, newLen); err != nil {
		return 0, err
	}
	return newLen, nil
}

// ciphertextLenFor returns the on-disk length holding exactly n plaintext
// bytes as whole sealed chunks, with no end-of-stream chunk.
func ciphertextLenFor(n int64) int64 {
	chunks := n / chunkSize
	return headerLen + chunks*(chunkSize+cryptobox.TagSize)
}

// headerLen mirrors the cryptobox stream header size.
const headerLen = 12

// writerAt returns a writer positioned to append plaintext at offset, either
// starting a fresh stream or resuming an existing one.
func (s *Service) writerAt(f *os.File, dek []byte, offset int64) (*cryptobox.Writer, error) {
	if offset == 0 {
		if err := f.Truncate(0); err != nil {
			return nil, fmt.Errorf("service: reset blob: %w", err)
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return nil, fmt.Errorf("service: seek blob: %w", err)
		}
		return cryptobox.NewWriter(f, dek)
	}

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("service: stat blob: %w", err)
	}
	// Drop any torn trailing chunk from an interrupted write before resuming.
	aligned := cryptobox.AlignDown(info.Size())
	if aligned != info.Size() {
		if err := f.Truncate(aligned); err != nil {
			return nil, fmt.Errorf("service: truncate torn chunk: %w", err)
		}
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("service: seek blob: %w", err)
	}
	st, err := cryptobox.InspectPartial(f, aligned)
	if err != nil {
		return nil, fmt.Errorf("service: inspect partial blob: %w", err)
	}
	if st.PlaintextLen != offset {
		return nil, &OffsetMismatch{Expected: st.PlaintextLen, Got: offset}
	}
	if _, err := f.Seek(aligned, io.SeekStart); err != nil {
		return nil, fmt.Errorf("service: seek to resume point: %w", err)
	}
	return cryptobox.NewResumeWriter(f, dek, st)
}

// FinishUpload publishes a share once every file is complete.
func (s *Service) FinishUpload(ctx context.Context, sessionID, token string) (*store.Drop, error) {
	sess, _, err := s.resolveSession(ctx, sessionID, token)
	if err != nil {
		return nil, err
	}
	if err := s.st.Finalize(ctx, sess.DropID); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalid, err)
	}
	drop, err := s.st.DropByID(ctx, sess.DropID)
	if err != nil {
		return nil, err
	}
	// Record the completed upload for the operator's statistics. Accounting is
	// best-effort: a stats hiccup must never fail a finished upload.
	_ = s.st.BumpUsage(ctx, store.DayKey(s.now()), 1, 0, drop.TotalBytes)
	return drop, nil
}

// CancelUpload discards an in-progress share and its stored bytes.
func (s *Service) CancelUpload(ctx context.Context, sessionID, token string) error {
	sess, _, err := s.resolveSession(ctx, sessionID, token)
	if err != nil {
		return err
	}
	drop, err := s.st.DropByID(ctx, sess.DropID)
	if err != nil {
		return err
	}
	if drop.Status != store.StatusPending {
		// Finished shares are removed by expiry, not by the upload session.
		return ErrNotFound
	}
	return s.DeleteDrop(ctx, drop)
}

// Now overrides the clock, for tests.
func (s *Service) setNow(f func() time.Time) { s.now = f }
