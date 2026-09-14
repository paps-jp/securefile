package service

import (
	"context"
	"fmt"
	"log/slog"
)

// SweepResult summarises one expiry pass.
type SweepResult struct {
	DropsDeleted    int
	SessionsExpired int
	TicketsExpired  int
	Errors          int
}

// Sweep deletes shares that have expired, been fully downloaded, or were
// abandoned mid-upload, and clears stale in-memory sessions.
//
// Retention here is a promise, not a cleanup chore: a user who chose "3 days"
// is told the file will be gone, so this runs on a timer rather than lazily at
// access time. A share nobody ever opens still has to disappear on schedule.
func (s *Service) Sweep(ctx context.Context, log *slog.Logger) (SweepResult, error) {
	now := s.now()
	var res SweepResult

	res.SessionsExpired = s.down.sweep(now)
	res.TicketsExpired = s.tickets.sweep(now)

	// Uploads abandoned past their resume window are reclaimed too, so a
	// cancelled 2 GB transfer does not sit on disk until its retention runs out.
	drops, err := s.st.Reapable(ctx, now, now.Add(-s.cfg.UploadTTL))
	if err != nil {
		return res, fmt.Errorf("service: list reapable: %w", err)
	}
	for _, d := range drops {
		if err := s.DeleteDrop(ctx, d); err != nil {
			// One unreadable directory should not stop the rest of the pass;
			// the next run will try again.
			res.Errors++
			log.Error("delete expired share", "key", d.Key, "err", err)
			continue
		}
		res.DropsDeleted++
	}
	return res, nil
}
