package ynab

import (
	"sync"
	"time"
)

// YNAB allows 200 requests per hour per access token and, since v1.73.0, sends
// no header saying how many are left. The count has to be kept here, and it has
// to be kept honestly: a request that is refused locally costs nothing, while
// one that YNAB refuses still burns latency and returns an error an agent may
// decide to retry.
//
// The reserve is what keeps a single greedy tool call from spending the whole
// hour: a caller is refused before the request goes out, with the time until
// the window opens again.
const (
	requestsPerHour = 200
	rateWindow      = time.Hour
)

type rateCounter struct {
	mu    sync.Mutex
	times []time.Time
}

func newRateCounter() *rateCounter { return &rateCounter{} }

// reserve records a request and reports whether it may go out. When it may not,
// it returns how long until the oldest request in the window ages out.
func (r *rateCounter) reserve() (time.Duration, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := time.Now().Add(-rateWindow)
	kept := r.times[:0]
	for _, t := range r.times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	r.times = kept
	if len(r.times) >= requestsPerHour {
		return time.Until(r.times[0].Add(rateWindow)), false
	}
	r.times = append(r.times, time.Now())
	return 0, true
}

// remaining is what the tools report so an agent can pace itself.
func (r *rateCounter) remaining() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := time.Now().Add(-rateWindow)
	n := 0
	for _, t := range r.times {
		if t.After(cutoff) {
			n++
		}
	}
	return requestsPerHour - n
}
