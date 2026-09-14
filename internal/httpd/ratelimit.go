package httpd

import (
	"net/netip"
	"sync"
	"time"
)

// limiter is a token bucket keyed by client address.
//
// The bucket that matters most guards password attempts on a share. A share
// password is 16 characters from a 54-character alphabet, so online guessing
// is hopeless anyway — but a limiter also keeps a flood of attempts from
// pinning the CPU on Argon2, which is the real denial-of-service risk when
// every wrong guess costs 64 MiB and a few hundred milliseconds.
type limiter struct {
	mu      sync.Mutex
	buckets map[netip.Addr]*bucket

	capacity float64
	refill   float64 // tokens per second
	now      func() time.Time
}

type bucket struct {
	tokens float64
	seen   time.Time
}

func newLimiter(capacity float64, per time.Duration) *limiter {
	return &limiter{
		buckets:  make(map[netip.Addr]*bucket),
		capacity: capacity,
		refill:   capacity / per.Seconds(),
		now:      time.Now,
	}
}

// allow consumes one token for addr, reporting whether the request may proceed.
func (l *limiter) allow(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true // nothing to key on; the transport layer is misconfigured
	}
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[addr]
	if !ok {
		b = &bucket{tokens: l.capacity, seen: now}
		l.buckets[addr] = b
	}
	b.tokens = min(l.capacity, b.tokens+now.Sub(b.seen).Seconds()*l.refill)
	b.seen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweep drops buckets that have refilled completely, so the map does not grow
// without bound on a busy instance.
func (l *limiter) sweep() {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	for addr, b := range l.buckets {
		if b.tokens+now.Sub(b.seen).Seconds()*l.refill >= l.capacity {
			delete(l.buckets, addr)
		}
	}
}
