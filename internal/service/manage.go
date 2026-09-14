package service

import (
	"context"
	"errors"
	"time"

	"github.com/paps-jp/securefile/internal/cryptobox"
	"github.com/paps-jp/securefile/internal/store"
)

// ManageView is what a sender sees on their management link: enough to judge
// whether the share has been picked up and whether to remove it early. It
// carries no filename and nothing that could decrypt content — the management
// token proves the sender created the share, not that they still hold the
// password.
type ManageView struct {
	Key          string
	Kind         string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	MaxDownloads int
	Downloads    int
	Remaining    int
	TotalSize    int64
	FileCount    int
	Status       string // "ready", "pending"
	Blocked      bool
	Expired      bool
	Exhausted    bool
}

// resolveManage loads the drop a management token controls.
func (s *Service) resolveManage(ctx context.Context, token string) (*store.Drop, error) {
	if token == "" {
		return nil, ErrNotFound
	}
	drop, err := s.st.DropByManageHash(ctx, cryptobox.ManageTokenHash(token))
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return drop, nil
}

// ManageStatus reports a share's delivery state to the sender who holds its
// management token.
func (s *Service) ManageStatus(ctx context.Context, token string) (*ManageView, error) {
	drop, err := s.resolveManage(ctx, token)
	if err != nil {
		return nil, err
	}
	files, err := s.st.Files(ctx, drop.ID)
	if err != nil {
		return nil, err
	}
	now := s.now()
	return &ManageView{
		Key:          drop.Key,
		Kind:         drop.Kind,
		CreatedAt:    drop.CreatedAt,
		ExpiresAt:    drop.ExpiresAt,
		MaxDownloads: drop.MaxDownloads,
		Downloads:    drop.Downloads,
		Remaining:    max(drop.MaxDownloads-drop.Downloads, 0),
		TotalSize:    drop.TotalBytes,
		FileCount:    len(files),
		Status:       drop.Status,
		Blocked:      drop.Blocked(),
		Expired:      !drop.ExpiresAt.After(now),
		Exhausted:    drop.Downloads >= drop.MaxDownloads,
	}, nil
}

// ManageDelete removes a share on the sender's request. Unlike recipient
// deletion it needs no uploader opt-in: the management token is proof the
// caller is the sender.
func (s *Service) ManageDelete(ctx context.Context, token string) error {
	drop, err := s.resolveManage(ctx, token)
	if err != nil {
		return err
	}
	return s.DeleteDrop(ctx, drop)
}
