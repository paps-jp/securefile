package service

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/paps-jp/securefile/internal/cryptobox"
)

// ticketTTL is how long a download ticket stays usable. It has to outlive a
// browser's retries and range requests for one file, but not a coffee break.
const ticketTTL = 10 * time.Minute

// ZipTicket is the file ID used for a whole-share archive.
const ZipTicket int64 = -1

// ticket authorises exactly one download, so the session token never has to
// appear in a URL.
//
// Browsers download by navigating, which means whatever authorises the
// transfer ends up in the address bar, the history, the Referer of any page it
// redirects to, and the access log. A ticket is short-lived and scoped to one
// file, so a leaked one is worth far less than a session token that unlocks
// the whole share for half an hour.
type ticket struct {
	sessionToken string
	fileID       int64
	expiresAt    time.Time
}

type ticketTable struct {
	mu sync.Mutex
	m  map[string]*ticket
}

func newTicketTable() *ticketTable {
	return &ticketTable{m: make(map[string]*ticket)}
}

func (t *ticketTable) sweep(now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for id, tk := range t.m {
		if now.After(tk.expiresAt) {
			delete(t.m, id)
			n++
		}
	}
	return n
}

// IssueTicket mints a download ticket for a file the session may read.
//
// Pass ZipTicket as fileID for a whole-share archive.
func (s *Service) IssueTicket(ctx context.Context, sessionToken string, fileID int64) (string, time.Time, error) {
	sess, ok := s.down.get(sessionToken, s.now())
	if !ok {
		return "", time.Time{}, ErrNotFound
	}
	if fileID != ZipTicket {
		if _, err := s.st.FileByID(ctx, sess.dropID, fileID); err != nil {
			return "", time.Time{}, ErrNotFound
		}
	}

	id, err := cryptobox.NewToken()
	if err != nil {
		return "", time.Time{}, err
	}
	expires := s.now().Add(ticketTTL)
	s.tickets.mu.Lock()
	s.tickets.m[id] = &ticket{sessionToken: sessionToken, fileID: fileID, expiresAt: expires}
	s.tickets.mu.Unlock()
	return id, expires, nil
}

// redeem resolves a ticket to its session token and file.
func (s *Service) redeem(id string) (string, int64, error) {
	s.tickets.mu.Lock()
	tk, ok := s.tickets.m[id]
	if ok && s.now().After(tk.expiresAt) {
		delete(s.tickets.m, id)
		ok = false
	}
	s.tickets.mu.Unlock()
	if !ok {
		return "", 0, ErrNotFound
	}
	return tk.sessionToken, tk.fileID, nil
}

// OpenTicket streams the file a ticket refers to, starting at offset.
func (s *Service) OpenTicket(ctx context.Context, ticketID string, offset int64) (io.ReadCloser, *UnlockedFile, error) {
	token, fileID, err := s.redeem(ticketID)
	if err != nil {
		return nil, nil, err
	}
	if fileID == ZipTicket {
		return nil, nil, ErrInvalid
	}
	return s.OpenFile(ctx, token, fileID, offset)
}

// TicketSession returns the session a ticket belongs to, for the archive
// endpoint which needs the whole file list rather than one file.
func (s *Service) TicketSession(ticketID string) (string, int64, error) {
	return s.redeem(ticketID)
}
