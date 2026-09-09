package ynab

import (
	"context"
	"net/http"

	openapi_types "github.com/oapi-codegen/runtime/types"
)

// Every write invalidates what it can have changed, because the alternative is
// an agent making a change and then reading its own stale cache back.

func (a *API) CreateTransactions(ctx context.Context, plan string, txns []NewTransaction) (*SaveTransactionsResponse, error) {
	res, err := call[SaveTransactionsResponse](ctx, a, func(ctx context.Context) (*http.Response, error) {
		return a.c.CreateTransaction(ctx, plan, PostTransactionsWrapper{Transactions: &txns})
	})
	if err != nil {
		return nil, err
	}
	a.InvalidateTransactions(plan)
	return res, nil
}

func (a *API) UpdateTransactions(ctx context.Context, plan string, txns []SaveTransactionWithIdOrImportId) (*SaveTransactionsResponse, error) {
	res, err := call[SaveTransactionsResponse](ctx, a, func(ctx context.Context) (*http.Response, error) {
		return a.c.UpdateTransactions(ctx, plan, PatchTransactionsWrapper{Transactions: txns})
	})
	if err != nil {
		return nil, err
	}
	a.InvalidateTransactions(plan)
	return res, nil
}

func (a *API) DeleteTransaction(ctx context.Context, plan, id string) (*TransactionDetail, error) {
	res, err := call[TransactionResponse](ctx, a, func(ctx context.Context) (*http.Response, error) {
		return a.c.DeleteTransaction(ctx, plan, id)
	})
	if err != nil {
		return nil, err
	}
	a.InvalidateTransactions(plan)
	return &res.Data.Transaction, nil
}

// SetBudgeted assigns an absolute amount to one category for one month. This is
// YNAB's only way to move money: there is no "move from A to B" endpoint, so a
// move is two of these.
func (a *API) SetBudgeted(ctx context.Context, plan string, month openapi_types.Date, categoryID string, milli int64) (*Category, error) {
	res, err := call[SaveCategoryResponse](ctx, a, func(ctx context.Context) (*http.Response, error) {
		return a.c.UpdateMonthCategory(ctx, plan, month, categoryID, PatchMonthCategoryWrapper{
			Category: SaveMonthCategory{Budgeted: milli},
		})
	})
	if err != nil {
		return nil, err
	}
	a.InvalidateCategories(plan)
	return &res.Data.Category, nil
}

func (a *API) CreateScheduledTransaction(ctx context.Context, plan string, t SaveScheduledTransaction) (*ScheduledTransactionDetail, error) {
	res, err := call[ScheduledTransactionResponse](ctx, a, func(ctx context.Context) (*http.Response, error) {
		return a.c.CreateScheduledTransaction(ctx, plan, PostScheduledTransactionWrapper{ScheduledTransaction: t})
	})
	if err != nil {
		return nil, err
	}
	return &res.Data.ScheduledTransaction, nil
}

func (a *API) UpdateScheduledTransaction(ctx context.Context, plan, id string, t SaveScheduledTransaction) (*ScheduledTransactionDetail, error) {
	res, err := call[ScheduledTransactionResponse](ctx, a, func(ctx context.Context) (*http.Response, error) {
		return a.c.UpdateScheduledTransaction(ctx, plan, id, PutScheduledTransactionWrapper{ScheduledTransaction: t})
	})
	if err != nil {
		return nil, err
	}
	return &res.Data.ScheduledTransaction, nil
}

func (a *API) DeleteScheduledTransaction(ctx context.Context, plan, id string) (*ScheduledTransactionDetail, error) {
	res, err := call[ScheduledTransactionResponse](ctx, a, func(ctx context.Context) (*http.Response, error) {
		return a.c.DeleteScheduledTransaction(ctx, plan, id)
	})
	if err != nil {
		return nil, err
	}
	return &res.Data.ScheduledTransaction, nil
}

func (a *API) CreateCategory(ctx context.Context, plan string, c NewCategory) (*Category, error) {
	res, err := call[SaveCategoryResponse](ctx, a, func(ctx context.Context) (*http.Response, error) {
		return a.c.CreateCategory(ctx, plan, PostCategoryWrapper{Category: c})
	})
	if err != nil {
		return nil, err
	}
	a.InvalidateCategories(plan)
	return &res.Data.Category, nil
}

func (a *API) UpdateCategory(ctx context.Context, plan, id string, c ExistingCategory) (*Category, error) {
	res, err := call[SaveCategoryResponse](ctx, a, func(ctx context.Context) (*http.Response, error) {
		return a.c.UpdateCategory(ctx, plan, id, PatchCategoryWrapper{Category: c})
	})
	if err != nil {
		return nil, err
	}
	a.InvalidateCategories(plan)
	return &res.Data.Category, nil
}

func (a *API) CreateCategoryGroup(ctx context.Context, plan, name string) (*CategoryGroup, error) {
	res, err := call[SaveCategoryGroupResponse](ctx, a, func(ctx context.Context) (*http.Response, error) {
		return a.c.CreateCategoryGroup(ctx, plan, PostCategoryGroupWrapper{CategoryGroup: SaveCategoryGroup{Name: name}})
	})
	if err != nil {
		return nil, err
	}
	a.InvalidateCategories(plan)
	return &res.Data.CategoryGroup, nil
}

func (a *API) UpdateCategoryGroup(ctx context.Context, plan, id, name string) (*CategoryGroup, error) {
	res, err := call[SaveCategoryGroupResponse](ctx, a, func(ctx context.Context) (*http.Response, error) {
		return a.c.UpdateCategoryGroup(ctx, plan, id, PatchCategoryGroupWrapper{CategoryGroup: SaveCategoryGroup{Name: name}})
	})
	if err != nil {
		return nil, err
	}
	a.InvalidateCategories(plan)
	return &res.Data.CategoryGroup, nil
}
