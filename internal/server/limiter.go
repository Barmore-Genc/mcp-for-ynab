package server

import (
	"sync"
	"time"
)

// The login form guards a real bank-adjacent account with one password, so it
// gets a brute-force speed bump: a handful of tries, then a cooldown. The
// window is per caller and resets on a successful sign-in.
const (
	maxAttempts   = 5
	attemptWindow = time.Minute
)

type limiter struct {
	mu       sync.Mutex
	attempts map[string]attempt
}

type attempt struct {
	count int
	until time.Time
}

func newLimiter() *limiter { return &limiter{attempts: map[string]attempt{}} }

// allow records an attempt by key and reports whether it may proceed.
func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for k, a := range l.attempts {
		if now.After(a.until) {
			delete(l.attempts, k)
		}
	}
	a := l.attempts[key]
	if now.After(a.until) {
		a = attempt{}
	}
	if a.count >= maxAttempts {
		return false
	}
	l.attempts[key] = attempt{count: a.count + 1, until: now.Add(attemptWindow)}
	return true
}

func (l *limiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, key)
}
