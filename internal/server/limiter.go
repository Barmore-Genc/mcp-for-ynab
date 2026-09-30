package server

import (
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// The login form guards someone's home with one password, so it gets a
// brute-force speed bump: a handful of tries per caller, then a cooldown. The
// per-caller window resets on a successful sign-in. On top of that, the whole
// server accepts only maxGlobalAttempts sign-in attempts per window, which is
// what bounds a guesser spread across many addresses. The price is that such
// an attack also keeps the owner out until it stops.
const (
	maxAttempts       = 5
	maxGlobalAttempts = 20
	attemptWindow     = time.Minute
	// maxTracked bounds the per-caller map. The global cap already keeps it
	// far below this, so reaching it means something is wrong and new callers
	// are refused rather than evicting callers that are being slowed down.
	maxTracked = 4096
)

type limiter struct {
	mu        sync.Mutex
	now       func() time.Time
	attempts  map[netip.Addr]attempt
	nextSweep time.Time
	// recent holds the times of the last maxGlobalAttempts attempts as a ring;
	// oldest is the slot the next attempt overwrites.
	recent [maxGlobalAttempts]time.Time
	oldest int
}

type attempt struct {
	count int
	until time.Time
}

func newLimiter() *limiter {
	return &limiter{now: time.Now, attempts: map[netip.Addr]attempt{}}
}

// allow records an attempt by key and reports whether it may proceed.
func (l *limiter) allow(key netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if t := l.recent[l.oldest]; !t.IsZero() && now.Sub(t) < attemptWindow {
		return false
	}
	if now.After(l.nextSweep) {
		for k, a := range l.attempts {
			if now.After(a.until) {
				delete(l.attempts, k)
			}
		}
		l.nextSweep = now.Add(attemptWindow)
	}
	a, tracked := l.attempts[key]
	if now.After(a.until) {
		a = attempt{}
	}
	if a.count >= maxAttempts {
		return false
	}
	if !tracked && len(l.attempts) >= maxTracked {
		return false
	}
	l.attempts[key] = attempt{count: a.count + 1, until: now.Add(attemptWindow)}
	l.recent[l.oldest] = now
	l.oldest = (l.oldest + 1) % maxGlobalAttempts
	return true
}

func (l *limiter) reset(key netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, key)
}

// clientAddr identifies a caller for rate limiting. The connecting address is
// used unless it is a trusted proxy; only then is X-Forwarded-For read, from
// the right, skipping further trusted proxies. The leftmost entries are
// whatever the caller chose to send and cannot be believed.
func (s *Server) clientAddr(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	addr := ap.Addr().Unmap()
	if s.trustedProxy(addr) {
		hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
		for i := len(hops) - 1; i >= 0; i-- {
			hop, ok := parseHop(hops[i])
			if !ok {
				break
			}
			addr = hop
			if !s.trustedProxy(hop) {
				break
			}
		}
	}
	return limiterKey(addr)
}

func (s *Server) trustedProxy(a netip.Addr) bool {
	for _, p := range s.cfg.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func parseHop(v string) (netip.Addr, bool) {
	v = strings.TrimSpace(v)
	if a, err := netip.ParseAddr(v); err == nil {
		return a.Unmap(), true
	}
	if ap, err := netip.ParseAddrPort(v); err == nil {
		return ap.Addr().Unmap(), true
	}
	return netip.Addr{}, false
}

// limiterKey groups IPv6 callers by /64, the smallest block a home or VPS is
// normally given, so rotating through one's own addresses buys no attempts.
func limiterKey(a netip.Addr) netip.Addr {
	if a.Is6() {
		return netip.PrefixFrom(a, 64).Masked().Addr()
	}
	return a
}
