package ynab

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// Accounts, categories and payees change slowly and are read on almost every
// tool call — every name the agent passes has to be resolved against them — so
// they are cached for a few minutes. This is about the request budget rather
// than latency: without it, one "categorize my uncategorized transactions" turn
// would spend a double-digit share of the hourly 200 on re-reading the same
// payee list.
//
// A delta request (last_knowledge_of_server) would cut the bytes but not the
// request count, which is the scarce resource, so the cache is a plain TTL with
// explicit invalidation after a write instead.
const cacheTTL = 5 * time.Minute

type cache struct {
	mu      sync.Mutex
	entries map[string]entry
}

type entry struct {
	value any
	until time.Time
}

func newCache() *cache { return &cache{entries: map[string]entry{}} }

func (c *cache) invalidate(keys ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range keys {
		delete(c.entries, k)
	}
}

// cached returns the value for key, calling load on a miss or an expiry.
func cached[T any](ctx context.Context, c *cache, key string, load func(context.Context) (T, error)) (T, error) {
	c.mu.Lock()
	e, ok := c.entries[key]
	c.mu.Unlock()
	if ok && time.Now().Before(e.until) {
		if v, ok := e.value.(T); ok {
			return v, nil
		}
	}
	v, err := load(ctx)
	if err != nil {
		return v, err
	}
	c.mu.Lock()
	c.entries[key] = entry{value: v, until: time.Now().Add(cacheTTL)}
	c.mu.Unlock()
	return v, nil
}

// Plans lists the user's budgets. YNAB calls them plans; the tools call them
// budgets, because that is the word every YNAB user uses.
func (a *API) Plans(ctx context.Context) ([]PlanSummary, string, error) {
	res, err := cached(ctx, a.cache, "plans", func(ctx context.Context) (*PlanSummaryResponse, error) {
		return call[PlanSummaryResponse](ctx, a, func(ctx context.Context) (*http.Response, error) {
			return a.c.GetPlans(ctx, &GetPlansParams{})
		})
	})
	if err != nil {
		return nil, "", err
	}
	var defaultID string
	if res.Data.DefaultPlan != nil {
		defaultID = res.Data.DefaultPlan.Id.String()
	}
	return res.Data.Plans, defaultID, nil
}

func (a *API) Accounts(ctx context.Context, plan string) ([]Account, error) {
	res, err := cached(ctx, a.cache, "accounts:"+plan, func(ctx context.Context) (*AccountsResponse, error) {
		return call[AccountsResponse](ctx, a, func(ctx context.Context) (*http.Response, error) {
			return a.c.GetAccounts(ctx, plan, &GetAccountsParams{})
		})
	})
	if err != nil {
		return nil, err
	}
	return undeleted(res.Data.Accounts, func(v Account) bool { return v.Deleted }), nil
}

func (a *API) CategoryGroups(ctx context.Context, plan string) ([]CategoryGroupWithCategories, error) {
	res, err := cached(ctx, a.cache, "categories:"+plan, func(ctx context.Context) (*CategoriesResponse, error) {
		return call[CategoriesResponse](ctx, a, func(ctx context.Context) (*http.Response, error) {
			return a.c.GetCategories(ctx, plan, &GetCategoriesParams{})
		})
	})
	if err != nil {
		return nil, err
	}
	return undeleted(res.Data.CategoryGroups, func(v CategoryGroupWithCategories) bool { return v.Deleted }), nil
}

func (a *API) Payees(ctx context.Context, plan string) ([]Payee, error) {
	res, err := cached(ctx, a.cache, "payees:"+plan, func(ctx context.Context) (*PayeesResponse, error) {
		return call[PayeesResponse](ctx, a, func(ctx context.Context) (*http.Response, error) {
			return a.c.GetPayees(ctx, plan, &GetPayeesParams{})
		})
	})
	if err != nil {
		return nil, err
	}
	return undeleted(res.Data.Payees, func(v Payee) bool { return v.Deleted }), nil
}

// InvalidateTransactions drops what a transaction write can have changed:
// account balances and category activity both move when a transaction does.
func (a *API) InvalidateTransactions(plan string) {
	a.cache.invalidate("accounts:"+plan, "categories:"+plan, "payees:"+plan)
}

func (a *API) InvalidateCategories(plan string) { a.cache.invalidate("categories:" + plan) }

// Remaining is how many YNAB requests are left in the current hour.
func (a *API) Remaining() int { return a.rate.remaining() }

// undeleted drops the tombstones YNAB includes in delta responses. They never
// appear in a full read, but filtering unconditionally means a later switch to
// delta reads cannot leak them into a tool's output.
func undeleted[T any](in []T, deleted func(T) bool) []T {
	out := make([]T, 0, len(in))
	for _, v := range in {
		if !deleted(v) {
			out = append(out, v)
		}
	}
	return out
}
