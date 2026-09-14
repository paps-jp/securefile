package httpd

import (
	"net/http"
	"testing"
)

func mustResolver(t *testing.T, cidrs []string, realIPHeader string) *clientIPResolver {
	t.Helper()
	r, err := newClientIPResolver(cidrs, realIPHeader)
	if err != nil {
		t.Fatalf("newClientIPResolver: %v", err)
	}
	return r
}

func reqFrom(remote string, headers map[string]string) *http.Request {
	req := &http.Request{RemoteAddr: remote, Header: http.Header{}}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// TestCloudflareRealIP checks the Cloudflare Tunnel case: cloudflared is the
// trusted local peer and CF-Connecting-IP carries the real client.
func TestCloudflareRealIP(t *testing.T) {
	r := mustResolver(t, []string{"127.0.0.1/32", "::1/128"}, "CF-Connecting-IP")

	got := r.resolve(reqFrom("127.0.0.1:44321", map[string]string{
		"CF-Connecting-IP": "203.0.113.7",
		"X-Forwarded-For":  "203.0.113.7, 172.71.0.1", // cloudflared also sets this
	}))
	if got.String() != "203.0.113.7" {
		t.Errorf("got %s, want 203.0.113.7 (from CF-Connecting-IP)", got)
	}
}

// TestRealIPHeaderIgnoredFromUntrustedPeer is the security property: a caller
// that is not a trusted proxy cannot spoof the client IP via the header.
func TestRealIPHeaderIgnoredFromUntrustedPeer(t *testing.T) {
	r := mustResolver(t, []string{"127.0.0.1/32"}, "CF-Connecting-IP")

	got := r.resolve(reqFrom("198.51.100.9:5000", map[string]string{
		"CF-Connecting-IP": "10.0.0.1", // attacker-supplied
	}))
	if got.String() != "198.51.100.9" {
		t.Errorf("got %s, want the real peer 198.51.100.9 (spoofed header must be ignored)", got)
	}
}

// TestMalformedRealIPFallsBack checks that a garbage header does not blank out
// the client IP; it falls through to the peer.
func TestMalformedRealIPFallsBack(t *testing.T) {
	r := mustResolver(t, []string{"127.0.0.1/32"}, "CF-Connecting-IP")

	got := r.resolve(reqFrom("127.0.0.1:60000", map[string]string{
		"CF-Connecting-IP": "not-an-ip",
	}))
	if got.String() != "127.0.0.1" {
		t.Errorf("got %s, want 127.0.0.1 (fallback on malformed header)", got)
	}
}

// TestXForwardedForStillWorks confirms the pre-existing XFF path is intact when
// no real-IP header is configured.
func TestXForwardedForStillWorks(t *testing.T) {
	r := mustResolver(t, []string{"10.0.0.0/8"}, "")

	got := r.resolve(reqFrom("10.0.0.2:1234", map[string]string{
		"X-Forwarded-For": "203.0.113.50, 10.0.0.9",
	}))
	if got.String() != "203.0.113.50" {
		t.Errorf("got %s, want 203.0.113.50 (from XFF)", got)
	}
}

// TestDirectPeerNoProxy checks that with no trusted proxies, the peer address
// is used verbatim and headers are ignored.
func TestDirectPeerNoProxy(t *testing.T) {
	r := mustResolver(t, nil, "CF-Connecting-IP")

	got := r.resolve(reqFrom("192.0.2.44:9999", map[string]string{
		"CF-Connecting-IP": "1.2.3.4",
		"X-Forwarded-For":  "1.2.3.4",
	}))
	if got.String() != "192.0.2.44" {
		t.Errorf("got %s, want 192.0.2.44 (direct peer, headers ignored)", got)
	}
}
