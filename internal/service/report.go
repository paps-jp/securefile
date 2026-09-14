package service

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/paps-jp/securefile/internal/store"
)

// This file is the public abuse-report intake. Filing a report blocks the named
// share on sight; it is part of every build. The operator-facing review
// operations (list, manual block, usage) live in admin.go, behind the `admin`
// build tag.

// keyFromInput pulls a share key out of whatever a reporter pasted: a full URL
// (with or without a #password fragment or query), or the bare key. It keeps
// only the last path segment and the characters a key is made of, so a stray
// URL cannot smuggle anything into the lookup.
func keyFromInput(in string) string {
	s := strings.TrimSpace(in)
	if i := strings.IndexAny(s, "#?"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimRight(s, "/")
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	// Keep only key-shaped characters (the alphabet used by NewDropKey), so a
	// pasted fragment or trailing punctuation cannot widen the lookup.
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		default:
			return -1
		}
	}, s)
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

// Report files a rights-infringement report and, if the named share exists,
// blocks it immediately. Blocking stops all downloads at once and exempts the
// share from expiry, so it is retained for review and for a possible
// sender-disclosure (発信者情報開示) request. The report is recorded whether or
// not the share was found, so an operator can see attempts against unknown keys.
//
// It never reveals whether the key matched: to a reporter, and to anyone
// probing, the outcome looks the same.
func (s *Service) Report(ctx context.Context, keyOrURL, reason, reporter, reporterIP string) error {
	key := keyFromInput(keyOrURL)
	if key == "" {
		return ErrInvalid
	}

	rep := &store.Report{
		DropKey:    key,
		Reason:     reason,
		Reporter:   reporter,
		ReporterIP: reporterIP,
		CreatedAt:  s.now(),
		Status:     "open",
	}

	drop, err := s.st.DropByKey(ctx, key)
	if err == nil {
		rep.DropID = sql.NullInt64{Int64: drop.ID, Valid: true}
		if err := s.st.BlockDrop(ctx, drop.ID, s.now()); err != nil {
			return err
		}
		// Cut off anyone who had already unlocked it before the block.
		s.down.deleteByDrop(drop.ID)
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}

	return s.st.CreateReport(ctx, rep)
}
