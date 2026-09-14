package service

import (
	"sync"
	"time"
)

// downloadSession is an unlocked share. It holds the recovered data
// encryption key in memory only — never on disk, never in a cookie — so the
// key survives exactly as long as the recipient's session and disappears on
// restart. Losing it costs a recipient one password re-entry; storing it would
// cost the guarantee that the host cannot read files at rest.
type downloadSession struct {
	dropKey   string
	dropID    int64
	dek       []byte
	expiresAt time.Time

	// claimed records whether this session has already consumed one of the
	// share's downloads, so fetching five files counts once.
	claimed bool
}

type sessionTable struct {
	mu sync.Mutex
	m  map[string]*downloadSession
}

func newSessionTable() *sessionTable {
	return &sessionTable{m: make(map[string]*downloadSession)}
}

func (t *sessionTable) put(token string, s *downloadSession) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.m[token] = s
}

// get returns a live session, dropping it if it has expired.
func (t *sessionTable) get(token string, now time.Time) (*downloadSession, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.m[token]
	if !ok {
		return nil, false
	}
	if now.After(s.expiresAt) {
		delete(t.m, token)
		return nil, false
	}
	return s, true
}

func (t *sessionTable) delete(token string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.m, token)
}

// deleteByDrop removes every session for a share, so revoking or reaping a
// share also cuts off recipients who already unlocked it.
func (t *sessionTable) deleteByDrop(dropID int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for token, s := range t.m {
		if s.dropID == dropID {
			delete(t.m, token)
		}
	}
}

// sweep drops expired sessions. Without it, keys for abandoned sessions would
// sit in memory until the process restarted.
func (t *sessionTable) sweep(now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for token, s := range t.m {
		if now.After(s.expiresAt) {
			delete(t.m, token)
			n++
		}
	}
	return n
}

// claimOnce runs claim the first time it is called for a session and reports
// whether the session is permitted to proceed.
func (t *sessionTable) claimOnce(s *downloadSession, claim func() error) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if s.claimed {
		return nil
	}
	if err := claim(); err != nil {
		return err
	}
	s.claimed = true
	return nil
}
