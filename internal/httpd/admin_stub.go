//go:build !admin

package httpd

// registerAdmin is a no-op in the public build: the admin dashboard is not
// compiled in, so there are no /admin routes to register. The abuse-report
// intake (abuse.go) is unaffected and remains available.
func (s *Server) registerAdmin() {}
