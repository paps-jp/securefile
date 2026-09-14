//go:build !legacy

package httpd

import "database/sql"

// initLegacy is a no-op in a non-legacy build: the imported-shares subsystem is
// not compiled in, so s.legacy stays nil and every legacy hook is inert.
func (s *Server) initLegacy(db *sql.DB, dir string) error { return nil }
