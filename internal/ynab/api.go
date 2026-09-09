package ynab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// BaseURL is where the generated client points. It comes from the spec's
// `servers` entry.
const BaseURL = "https://api.ynab.com/v1"

// PlanLastUsed is the alias YNAB accepts in place of a plan id. Every tool
// defaults to it, so a caller with one budget never has to name it. The other
// alias, "default", only works for OAuth apps and not for the personal access
// token this server uses, so it is never sent.
const PlanLastUsed = "last-used"

// API is the YNAB client the tools call. It owns the rate-limit accounting,
// because YNAB's budget of 200 requests an hour is per token and this server
// holds exactly one token.
type API struct {
	c     *Client
	rate  *rateCounter
	cache *cache
}

func NewAPI(token string) (*API, error) { return NewAPIAt(token, BaseURL) }

// NewAPIAt points the client at a different base URL. It exists for tests and
// for anyone running YNAB's API behind a proxy of their own.
func NewAPIAt(token, baseURL string) (*API, error) {
	c, err := NewClient(baseURL, WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		return nil
	}), WithHTTPClient(&http.Client{Timeout: 30 * time.Second}))
	if err != nil {
		return nil, err
	}
	return &API{c: c, rate: newRateCounter(), cache: newCache()}, nil
}

// Error is a YNAB API failure translated into something an agent can act on.
// Retryable marks the one case (a 5xx) where trying again is right; everything
// else is either the caller's mistake or terminal until an operator intervenes.
type Error struct {
	Status    int
	ID        string
	Message   string
	Retryable bool
}

func (e *Error) Error() string { return e.Message }

// call runs one request through the rate counter and decodes the JSON envelope
// into T. Every YNAB response is `{"data": {...}}` or `{"error": {...}}`, so one
// helper covers all 44 operations.
func call[T any](ctx context.Context, a *API, do func(context.Context) (*http.Response, error)) (*T, error) {
	if wait, ok := a.rate.reserve(); !ok {
		return nil, &Error{
			Status: http.StatusTooManyRequests,
			ID:     "429",
			Message: fmt.Sprintf("YNAB's rate limit of %d requests per hour is used up. "+
				"Do not retry: wait about %d minutes before making another request.",
				requestsPerHour, int(wait.Minutes())+1),
		}
	}
	resp, err := do(ctx)
	if err != nil {
		return nil, fmt.Errorf("calling YNAB: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("reading the YNAB response: %w", err)
	}
	if resp.StatusCode >= 300 {
		return nil, apiError(resp.StatusCode, body)
	}
	var out T
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decoding the YNAB response: %w", err)
	}
	return &out, nil
}

// apiError maps YNAB's error ids onto text that says what to do next. The ids
// are documented in the spec; an unknown one falls through to YNAB's own detail
// string, which is usually a usable validation message.
func apiError(status int, body []byte) error {
	var env ErrorResponse
	_ = json.Unmarshal(body, &env)
	e := &Error{Status: status, ID: env.Error.Id}
	switch env.Error.Id {
	case "401":
		e.Message = "The YNAB access token is missing, invalid or revoked. The operator has to set YNAB_ACCESS_TOKEN and restart the server; retrying will not help."
	case "403.1":
		e.Message = "This YNAB subscription has lapsed, so the API is blocked until it is renewed."
	case "403.2":
		e.Message = "This YNAB trial has expired, so the API is blocked."
	case "403.3":
		e.Message = "This YNAB token cannot make changes, only read. Ask the operator for a token with write access."
	case "403.4":
		e.Message = "This budget has hit YNAB's data limit."
	case "404.2":
		e.Message = "No such item in this budget. The id may belong to a different budget, or the item may have been deleted; list it again to get a current id."
	case "409":
		e.Message = "A transaction with that import id already exists on that account, so nothing was created."
	case "429":
		e.Message = "YNAB's rate limit of 200 requests per hour is used up. Do not retry immediately; wait a few minutes."
	default:
		switch {
		case status >= 500:
			e.Message = fmt.Sprintf("The YNAB API is unavailable (HTTP %d). Retry in a minute.", status)
			e.Retryable = true
		case env.Error.Detail != "":
			e.Message = "YNAB rejected the request: " + env.Error.Detail
		default:
			e.Message = fmt.Sprintf("The YNAB API returned HTTP %d.", status)
		}
	}
	return e
}

// AsError reports whether err is a mapped YNAB API error.
func AsError(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}
