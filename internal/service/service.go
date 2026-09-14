// Package service implements セキュファイル便: resumable encrypted upload,
// password-gated download, and expiry.
//
// The design rule throughout is that the server can move bytes but cannot read
// them. A data encryption key is generated per share, wrapped under the share
// password, and then dropped from memory. Between upload and download nothing
// on the host — database, blob directory, backups — can reconstruct it.
package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/paps-jp/securefile/internal/cryptobox"
	"github.com/paps-jp/securefile/internal/store"
)

const chunkSize = cryptobox.ChunkSize

// Errors surfaced to the transport layer.
var (
	// ErrNotFound covers every "you cannot have this" case — missing,
	// expired, exhausted, wrong drop — so responses do not confirm which.
	ErrNotFound = errors.New("service: not found")
	// ErrWrongPassword is returned when a share password does not unwrap.
	ErrWrongPassword = errors.New("service: wrong password")
	// ErrTooLarge reports a request over a configured limit (this one share is
	// too big for its own days/downloads setting).
	ErrTooLarge = errors.New("service: over limit")
	// ErrStorageFull reports that the server's storage budget is exhausted, so a
	// new upload cannot be accepted right now. It is distinct from ErrTooLarge:
	// the share itself may be within its limit, but there is no room on the
	// server until expiring shares are swept.
	ErrStorageFull = errors.New("service: storage full")
	// ErrInvalid reports a malformed request.
	ErrInvalid = errors.New("service: invalid request")
)

// OffsetMismatch reports that a client tried to append at the wrong place. It
// carries the offset the server actually expects, so the client can re-sync
// and continue rather than restarting the whole file.
type OffsetMismatch struct {
	FileID   int64
	Expected int64
	Got      int64
}

func (e *OffsetMismatch) Error() string {
	return fmt.Sprintf("service: file %d expects offset %d, got %d", e.FileID, e.Expected, e.Got)
}

// Service ties the metadata store, the blob directory and the in-memory
// session tables together.
type Service struct {
	st      *store.Store
	cfg     Config
	down    *sessionTable
	tickets *ticketTable
	now     func() time.Time
}

// New returns a Service backed by st.
func New(st *store.Store, cfg Config) (*Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.BlobRoot, 0o700); err != nil {
		return nil, fmt.Errorf("service: create blob root: %w", err)
	}
	return &Service{
		st:      st,
		cfg:     cfg,
		down:    newSessionTable(),
		tickets: newTicketTable(),
		now:     time.Now,
	}, nil
}

// Config exposes the limits, for rendering them in the UI.
func (s *Service) Config() Config { return s.cfg }

// blobPath returns the on-disk path for a file's ciphertext. Keys are sharded
// two characters deep so a directory never accumulates more entries than a
// filesystem handles comfortably.
func (s *Service) blobPath(rel string) string {
	return filepath.Join(s.cfg.BlobRoot, filepath.FromSlash(rel))
}

func blobRel(dropKey string, fileID int64) string {
	return fmt.Sprintf("%s/%s/%d", dropKey[:2], dropKey, fileID)
}

// FileRequest describes one file a client intends to upload.
type FileRequest struct {
	Name string
	Size int64
}

// StartRequest is the parameters of a new share.
type StartRequest struct {
	Files []FileRequest
	// Days is the requested retention in days.
	Days int
	// MaxDownloads is the requested download allowance.
	MaxDownloads int
	// Password, if empty, is generated.
	Password string
	// AllowDelete lets the recipient delete the share from the server after
	// downloading. Off by default.
	AllowDelete bool
	// Kind is "file" (default) or "text" for a secret message. A text share
	// must carry exactly one file, which the recipient reads inline.
	Kind string
	// Manage requests a sender management link, returned as ManageToken.
	Manage bool
	// UploaderHash identifies the uploader for abuse handling (repeat-uploader
	// detection) without needing the address in the clear.
	UploaderHash []byte
	// UploaderIP is the uploader's address, retained for sender-disclosure
	// (発信者情報開示) requests from lawyers or law enforcement.
	UploaderIP string
}

// StartedFile is a file the server has allocated storage for.
type StartedFile struct {
	ID   int64
	Name string
	Size int64
}

// StartResult is what a client needs to perform and then share an upload.
type StartResult struct {
	Key       string
	Password  string
	SessionID string
	Token     string
	PartSize  int64
	ExpiresAt time.Time
	Files     []StartedFile
	// ManageToken is the sender's management-link secret, empty unless requested.
	// It is returned exactly once, here; only its hash is stored.
	ManageToken string
}

// StartUpload validates a request, allocates a share, and opens a resumable
// upload session.
func (s *Service) StartUpload(ctx context.Context, req StartRequest) (*StartResult, error) {
	if err := s.validateStart(ctx, req); err != nil {
		return nil, err
	}

	password := req.Password
	if password == "" {
		var err error
		if password, err = cryptobox.NewPassword(); err != nil {
			return nil, err
		}
	}

	dek, err := cryptobox.NewKey()
	if err != nil {
		return nil, err
	}
	wrapped, err := cryptobox.WrapKey(dek, password)
	if err != nil {
		return nil, err
	}

	key, err := s.uniqueKey(ctx)
	if err != nil {
		return nil, err
	}

	// A management link is optional; when asked for, the token is returned to the
	// sender below and only its hash is persisted.
	var manageToken string
	var manageHash []byte
	if req.Manage {
		if manageToken, err = cryptobox.NewManageToken(); err != nil {
			return nil, err
		}
		manageHash = cryptobox.ManageTokenHash(manageToken)
	}

	kind := req.Kind
	if kind == "" {
		kind = "file"
	}

	now := s.now()
	drop, err := s.st.CreateDrop(ctx, &store.Drop{
		Key:           key,
		WrappedDEK:    wrapped,
		CreatedAt:     now,
		ExpiresAt:     now.AddDate(0, 0, req.Days),
		MaxDownloads:  req.MaxDownloads,
		DeleteAllowed: req.AllowDelete,
		Kind:          kind,
		ManageHash:    manageHash,
	}, req.UploaderHash, req.UploaderIP)
	if err != nil {
		return nil, err
	}

	files := make([]StartedFile, 0, len(req.Files))
	for i, fr := range req.Files {
		nameEnc, err := cryptobox.Seal(dek, []byte(fr.Name))
		if err != nil {
			return nil, err
		}
		// The row is inserted first so the ID is available for the blob path,
		// then the path is written back.
		rec, err := s.st.AddFile(ctx, &store.File{
			DropID: drop.ID, Ordinal: i, NameEnc: nameEnc, Size: fr.Size, BlobPath: "",
		})
		if err != nil {
			return nil, err
		}
		rel := blobRel(key, rec.ID)
		if err := s.st.SetBlobPath(ctx, rec.ID, rel); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(s.blobPath(rel)), 0o700); err != nil {
			return nil, fmt.Errorf("service: create blob dir: %w", err)
		}
		// A zero-byte file has no part for the client to send, but it still
		// needs a sealed (empty) stream on disk or the download would find no
		// blob at all. Write it now so the upload has nothing left to do.
		if fr.Size == 0 {
			if err := s.writeEmptyBlob(rel, dek); err != nil {
				return nil, err
			}
		}
		files = append(files, StartedFile{ID: rec.ID, Name: fr.Name, Size: fr.Size})
	}

	token, err := cryptobox.NewToken()
	if err != nil {
		return nil, err
	}
	sessionWrapped, err := cryptobox.WrapKeyWithToken(dek, token, "upload")
	if err != nil {
		return nil, err
	}
	sessionID, err := cryptobox.NewToken()
	if err != nil {
		return nil, err
	}
	expires := now.Add(s.cfg.UploadTTL)
	if err := s.st.CreateUploadSession(ctx, &store.UploadSession{
		ID: sessionID, DropID: drop.ID, Wrapped: sessionWrapped, ExpiresAt: expires,
	}); err != nil {
		return nil, err
	}

	return &StartResult{
		Key:         key,
		Password:    password,
		SessionID:   sessionID,
		Token:       token,
		PartSize:    s.cfg.PartSize,
		ExpiresAt:   expires,
		Files:       files,
		ManageToken: manageToken,
	}, nil
}

func (s *Service) validateStart(ctx context.Context, req StartRequest) error {
	if len(req.Files) == 0 {
		return fmt.Errorf("%w: no files", ErrInvalid)
	}
	if len(req.Files) > s.cfg.MaxFiles {
		return fmt.Errorf("%w: %d files exceeds the limit of %d", ErrTooLarge, len(req.Files), s.cfg.MaxFiles)
	}
	if req.Kind == "text" && len(req.Files) != 1 {
		return fmt.Errorf("%w: a message share holds exactly one item", ErrInvalid)
	}
	if req.Days < 1 || req.Days > s.cfg.MaxDays {
		return fmt.Errorf("%w: retention must be 1-%d days, got %d", ErrInvalid, s.cfg.MaxDays, req.Days)
	}
	if req.MaxDownloads < 1 || req.MaxDownloads > s.cfg.MaxDownloads {
		return fmt.Errorf("%w: download limit must be 1-%d, got %d", ErrInvalid, s.cfg.MaxDownloads, req.MaxDownloads)
	}

	var total int64
	for _, f := range req.Files {
		if f.Name == "" {
			return fmt.Errorf("%w: file name is empty", ErrInvalid)
		}
		if f.Size < 0 {
			return fmt.Errorf("%w: negative file size", ErrInvalid)
		}
		total += f.Size
	}
	limit := s.cfg.MaxUploadBytes(req.Days, req.MaxDownloads)
	if total > limit {
		return fmt.Errorf("%w: %d bytes exceeds the limit of %d for %d days / %d downloads",
			ErrTooLarge, total, limit, req.Days, req.MaxDownloads)
	}

	if s.cfg.DiskQuotaBytes > 0 {
		st, err := s.st.Stats(ctx, s.now())
		if err != nil {
			return err
		}
		if st.Bytes+total > s.cfg.DiskQuotaBytes {
			return fmt.Errorf("%w: storage quota would be exceeded", ErrStorageFull)
		}
	}
	return nil
}

// uniqueKey draws share keys until one is unused. Collisions are vanishingly
// unlikely at 14 characters, but a silent overwrite of someone else's share
// would be severe enough to be worth checking for.
func (s *Service) uniqueKey(ctx context.Context) (string, error) {
	for range 8 {
		key, err := cryptobox.NewDropKey()
		if err != nil {
			return "", err
		}
		_, err = s.st.DropByKey(ctx, key)
		if errors.Is(err, store.ErrNotFound) {
			return key, nil
		}
		if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("service: could not find an unused share key")
}

// writeEmptyBlob seals a zero-length stream so a file the user selected but
// which contains no bytes still downloads as an empty file rather than a
// missing one.
func (s *Service) writeEmptyBlob(rel string, dek []byte) error {
	f, err := os.OpenFile(s.blobPath(rel), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("service: create empty blob: %w", err)
	}
	defer f.Close()

	w, err := cryptobox.NewWriter(f, dek)
	if err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("service: seal empty blob: %w", err)
	}
	return f.Sync()
}
