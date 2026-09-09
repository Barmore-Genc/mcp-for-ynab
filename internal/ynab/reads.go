package ynab

import (
	"context"
	"net/http"

	openapi_types "github.com/oapi-codegen/runtime/types"
)

// Month is one month's budget, including every category's amounts for that
// month. It is not cached: it is the one read that changes as soon as anything
// is assigned or spent, and a stale answer to "what is left in Groceries" is
// worse than a spent request.
//
// The month is always a concrete date rather than YNAB's "current" alias, which
// resolves in UTC and so names the wrong month for part of every month-end.
func (a *API) Month(ctx context.Context, plan string, month openapi_types.Date) (*MonthDetail, error) {
	res, err := call[MonthDetailResponse](ctx, a, func(ctx context.Context) (*http.Response, error) {
		return a.c.GetPlanMonth(ctx, plan, month)
	})
	if err != nil {
		return nil, err
	}
	return &res.Data.Month, nil
}

func (a *API) ScheduledTransactions(ctx context.Context, plan string) ([]ScheduledTransactionDetail, error) {
	res, err := call[ScheduledTransactionsResponse](ctx, a, func(ctx context.Context) (*http.Response, error) {
		return a.c.GetScheduledTransactions(ctx, plan, &GetScheduledTransactionsParams{})
	})
	if err != nil {
		return nil, err
	}
	return undeleted(res.Data.ScheduledTransactions, func(v ScheduledTransactionDetail) bool { return v.Deleted }), nil
}

func (a *API) Transaction(ctx context.Context, plan, id string) (*TransactionDetail, error) {
	res, err := call[TransactionResponse](ctx, a, func(ctx context.Context) (*http.Response, error) {
		return a.c.GetTransactionById(ctx, plan, id)
	})
	if err != nil {
		return nil, err
	}
	return &res.Data.Transaction, nil
}

// TransactionScope says which of YNAB's five transaction list endpoints to use.
// They take the same filters and differ only in what they are scoped to, so the
// tool takes a filter and this picks the narrowest endpoint for it — fewer rows
// over the wire, and the same one request either way.
type TransactionScope struct {
	AccountID  string
	CategoryID string
	PayeeID    string
	Month      *openapi_types.Date
	SinceDate  *openapi_types.Date
	UntilDate  *openapi_types.Date
	// Type is YNAB's own filter, which only takes "uncategorized" or
	// "unapproved".
	Type string
}

// Txn is the shape the tools render. The five endpoints return two
// different schemas — the scoped ones return hybrids that can be one leg of a
// split — so both are flattened into this.
type Txn struct {
	ID           string
	Date         openapi_types.Date
	Amount       int64
	AmountText   *string
	PayeeName    string
	CategoryName string
	CategoryID   string
	AccountName  string
	AccountID    string
	Cleared      string
	Approved     bool
	FlagColor    string
	Memo         string
	// IsSplitPart marks a row that is one leg of a split rather than a whole
	// transaction. Only the scoped endpoints return these.
	IsSplitPart bool
}

func (a *API) Transactions(ctx context.Context, plan string, sc TransactionScope) ([]Txn, error) {
	switch {
	case sc.AccountID != "":
		res, err := call[TransactionsResponse](ctx, a, func(ctx context.Context) (*http.Response, error) {
			return a.c.GetTransactionsByAccount(ctx, plan, sc.AccountID, &GetTransactionsByAccountParams{
				SinceDate: sc.SinceDate, UntilDate: sc.UntilDate, Type: paramType[GetTransactionsByAccountParamsType](sc.Type),
			})
		})
		if err != nil {
			return nil, err
		}
		return fromDetails(res.Data.Transactions), nil
	case sc.CategoryID != "":
		res, err := call[HybridTransactionsResponse](ctx, a, func(ctx context.Context) (*http.Response, error) {
			return a.c.GetTransactionsByCategory(ctx, plan, sc.CategoryID, &GetTransactionsByCategoryParams{
				SinceDate: sc.SinceDate, UntilDate: sc.UntilDate, Type: paramType[GetTransactionsByCategoryParamsType](sc.Type),
			})
		})
		if err != nil {
			return nil, err
		}
		return fromHybrids(res.Data.Transactions), nil
	case sc.PayeeID != "":
		res, err := call[HybridTransactionsResponse](ctx, a, func(ctx context.Context) (*http.Response, error) {
			return a.c.GetTransactionsByPayee(ctx, plan, sc.PayeeID, &GetTransactionsByPayeeParams{
				SinceDate: sc.SinceDate, UntilDate: sc.UntilDate, Type: paramType[GetTransactionsByPayeeParamsType](sc.Type),
			})
		})
		if err != nil {
			return nil, err
		}
		return fromHybrids(res.Data.Transactions), nil
	case sc.Month != nil:
		res, err := call[HybridTransactionsResponse](ctx, a, func(ctx context.Context) (*http.Response, error) {
			return a.c.GetTransactionsByMonth(ctx, plan, sc.Month.Format("2006-01-02"), &GetTransactionsByMonthParams{
				SinceDate: sc.SinceDate, UntilDate: sc.UntilDate, Type: paramType[GetTransactionsByMonthParamsType](sc.Type),
			})
		})
		if err != nil {
			return nil, err
		}
		return fromHybrids(res.Data.Transactions), nil
	default:
		res, err := call[TransactionsResponse](ctx, a, func(ctx context.Context) (*http.Response, error) {
			return a.c.GetTransactions(ctx, plan, &GetTransactionsParams{
				SinceDate: sc.SinceDate, UntilDate: sc.UntilDate, Type: paramType[GetTransactionsParamsType](sc.Type),
			})
		})
		if err != nil {
			return nil, err
		}
		return fromDetails(res.Data.Transactions), nil
	}
}

// paramType exists because the generator gives each endpoint its own named
// string type for the same two-value enum.
func paramType[T ~string](v string) *T {
	if v == "" {
		return nil
	}
	t := T(v)
	return &t
}

func fromDetails(in []TransactionDetail) []Txn {
	out := make([]Txn, 0, len(in))
	for _, t := range in {
		if t.Deleted {
			continue
		}
		out = append(out, Txn{
			ID: t.Id, Date: t.Date, Amount: t.Amount, AmountText: t.AmountFormatted,
			PayeeName: strValue(t.PayeeName), CategoryName: strValue(t.CategoryName),
			CategoryID: uuidValue(t.CategoryId), AccountName: t.AccountName, AccountID: t.AccountId.String(),
			Cleared: string(t.Cleared), Approved: t.Approved, FlagColor: flag(t.FlagColor),
			Memo: strValue(t.Memo),
		})
	}
	return out
}

func fromHybrids(in []HybridTransaction) []Txn {
	out := make([]Txn, 0, len(in))
	for _, t := range in {
		if t.Deleted {
			continue
		}
		out = append(out, Txn{
			ID: t.Id, Date: t.Date, Amount: t.Amount, AmountText: t.AmountFormatted,
			PayeeName: strValue(t.PayeeName), CategoryName: strValue(t.CategoryName),
			CategoryID: uuidValue(t.CategoryId), AccountName: t.AccountName, AccountID: t.AccountId.String(),
			Cleared: string(t.Cleared), Approved: t.Approved, FlagColor: flag(t.FlagColor),
			Memo: strValue(t.Memo), IsSplitPart: t.Type == "subtransaction",
		})
	}
	return out
}

func strValue(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func uuidValue(p *openapi_types.UUID) string {
	if p == nil {
		return ""
	}
	return p.String()
}

func flag(p *TransactionFlagColor) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
