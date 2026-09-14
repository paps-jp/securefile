package httpd

import (
	"crypto/hmac"
	"crypto/sha256"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// clientIPResolver works out who a request came from when the service runs
// behind a reverse proxy.
//
// X-Forwarded-For is trusted only when the immediate peer is a configured
// proxy. Trusting it unconditionally would let anyone set the header and
// defeat both rate limiting and abuse attribution, which is precisely what
// those two things exist to prevent.
type clientIPResolver struct {
	trusted []netip.Prefix
	// realIPHeader, if set, carries the true client address as a single value
	// (e.g. Cloudflare's CF-Connecting-IP). It is read only when the immediate
	// peer is trusted, so an outside caller cannot spoof it.
	realIPHeader string
}

func newClientIPResolver(cidrs []string, realIPHeader string) (*clientIPResolver, error) {
	r := &clientIPResolver{realIPHeader: realIPHeader}
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return nil, err
		}
		r.trusted = append(r.trusted, p)
	}
	return r, nil
}

func (r *clientIPResolver) trusts(addr netip.Addr) bool {
	for _, p := range r.trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// resolve returns the effective client address for req.
func (r *clientIPResolver) resolve(req *http.Request) netip.Addr {
	peer := peerAddr(req.RemoteAddr)
	if !peer.IsValid() || !r.trusts(peer) {
		return peer
	}
	// A single-value real-IP header (Cloudflare's CF-Connecting-IP) is the
	// authoritative client address when we sit behind a tunnel: cloudflared is
	// the trusted peer, and Cloudflare sets this header to the true client. It
	// is preferred over X-Forwarded-For, which cloudflared also fills but which
	// is a list that is fiddlier to interpret.
	if r.realIPHeader != "" {
		if a, err := netip.ParseAddr(strings.TrimSpace(req.Header.Get(r.realIPHeader))); err == nil {
			return a.Unmap()
		}
	}
	// Walk X-Forwarded-For from the right, skipping hops we run ourselves; the
	// first address that is not one of our proxies is the real client.
	hops := strings.Split(req.Header.Get("X-Forwarded-For"), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			continue
		}
		if !r.trusts(a) {
			return a
		}
	}
	return peer
}

func peerAddr(remoteAddr string) netip.Addr {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

// hashIP returns a keyed hash of an address, for recording who uploaded
// something without keeping the address itself.
//
// Abuse reports need the operator to be able to recognise a repeat uploader,
// but a database of plaintext addresses of people using a service for
// survivors of image-based abuse is a liability in its own right. A keyed hash
// answers "same uploader as this other share?" and nothing else.
func hashIP(key []byte, addr netip.Addr) []byte {
	if !addr.IsValid() {
		return nil
	}
	m := hmac.New(sha256.New, key)
	m.Write(addr.AsSlice())
	return m.Sum(nil)
}
