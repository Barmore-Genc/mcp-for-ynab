package ynab

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Tools accept a name wherever YNAB wants a uuid, because an agent that has to
// look up an id before every write spends two requests on every one it needs.
// A reference is matched, in order, as a full uuid, as the short id the
// renderer prints, as an exact name, and finally as a substring — so the
// obvious thing works and the ambiguous thing fails loudly with the candidates
// rather than silently picking one.

// ShortIDLen is how much of a uuid the renderer prints and this resolver
// accepts back. Eight hex characters is enough to be unique across a budget's
// few thousand entities, and saves 28 characters on every line of every list.
const ShortIDLen = 8

// AmbiguousError is returned when a name matches more than one thing. Listing
// the candidates is what makes it recoverable in one turn.
type AmbiguousError struct {
	Kind       string
	Query      string
	Candidates []string
}

func (e *AmbiguousError) Error() string {
	return fmt.Sprintf("%q matches more than one %s: %s. Use the exact name or the id.",
		e.Query, e.Kind, strings.Join(e.Candidates, ", "))
}

type NotFoundError struct {
	Kind  string
	Query string
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("no %s in this budget matches %q", e.Kind, e.Query)
}

// Named is anything a reference can point at.
type Named struct {
	ID   string
	Name string
	// Group is the category group a category belongs to, used to disambiguate
	// the duplicate category names YNAB allows across groups.
	Group string
}

func (n Named) label() string {
	if n.Group != "" {
		return n.Group + " / " + n.Name
	}
	return n.Name
}

// resolve picks the one entry matching q, or explains why it cannot.
func resolve(kind, q string, in []Named) (Named, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return Named{}, &NotFoundError{Kind: kind, Query: q}
	}
	lower := strings.ToLower(q)
	var byID, exact, prefix, contains []Named
	for _, n := range in {
		id := strings.ToLower(n.ID)
		name := strings.ToLower(n.Name)
		switch {
		case id == lower || (len(lower) >= ShortIDLen && strings.HasPrefix(id, lower)):
			byID = append(byID, n)
		case name == lower || strings.ToLower(n.label()) == lower:
			exact = append(exact, n)
		case strings.HasPrefix(name, lower):
			prefix = append(prefix, n)
		case strings.Contains(name, lower):
			contains = append(contains, n)
		}
	}
	for _, tier := range [][]Named{byID, exact, prefix, contains} {
		switch len(tier) {
		case 0:
			continue
		case 1:
			return tier[0], nil
		default:
			labels := make([]string, 0, len(tier))
			for _, n := range tier {
				labels = append(labels, fmt.Sprintf("%s [%s]", n.label(), ShortID(n.ID)))
			}
			sort.Strings(labels)
			if len(labels) > 8 {
				labels = append(labels[:8], "…")
			}
			return Named{}, &AmbiguousError{Kind: kind, Query: q, Candidates: labels}
		}
	}
	return Named{}, &NotFoundError{Kind: kind, Query: q}
}

// ShortID truncates a uuid to what the renderer prints.
func ShortID(id string) string {
	if len(id) <= ShortIDLen {
		return id
	}
	return id[:ShortIDLen]
}

func (a *API) ResolveAccount(ctx context.Context, plan, q string) (Named, error) {
	accounts, err := a.Accounts(ctx, plan)
	if err != nil {
		return Named{}, err
	}
	in := make([]Named, 0, len(accounts))
	for _, v := range accounts {
		in = append(in, Named{ID: v.Id.String(), Name: v.Name})
	}
	return resolve("account", q, in)
}

func (a *API) ResolvePayee(ctx context.Context, plan, q string) (Named, error) {
	payees, err := a.Payees(ctx, plan)
	if err != nil {
		return Named{}, err
	}
	in := make([]Named, 0, len(payees))
	for _, v := range payees {
		in = append(in, Named{ID: v.Id.String(), Name: v.Name})
	}
	return resolve("payee", q, in)
}

// ResolveCategory searches the categories a user can budget to. YNAB's internal
// groups are skipped: they hold "Inflow: Ready to Assign" and the
// hidden-category bucket, neither of which can be assigned to. Hidden groups
// are kept, because a hidden category is still a real one someone may name.
func (a *API) ResolveCategory(ctx context.Context, plan, q string) (Named, error) {
	groups, err := a.CategoryGroups(ctx, plan)
	if err != nil {
		return Named{}, err
	}
	var in []Named
	for _, g := range groups {
		if g.Internal {
			continue
		}
		for _, c := range g.Categories {
			if c.Deleted {
				continue
			}
			in = append(in, Named{ID: c.Id.String(), Name: c.Name, Group: g.Name})
		}
	}
	return resolve("category", q, in)
}

func (a *API) ResolveCategoryGroup(ctx context.Context, plan, q string) (Named, error) {
	groups, err := a.CategoryGroups(ctx, plan)
	if err != nil {
		return Named{}, err
	}
	in := make([]Named, 0, len(groups))
	for _, g := range groups {
		in = append(in, Named{ID: g.Id.String(), Name: g.Name})
	}
	return resolve("category group", q, in)
}
