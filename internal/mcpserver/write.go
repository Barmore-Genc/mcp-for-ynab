package mcpserver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Barmore-Genc/mcp-for-ynab/internal/ynab"
	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	openapi_types "github.com/oapi-codegen/runtime/types"
)

// YNAB has no undo and no trash. A deleted transaction is gone, and an assigned
// amount overwritten is not recoverable either. So the write tools are bounded
// (a batch is tens of rows, not thousands), they echo what they changed, and
// the two that cannot be walked back — deleting a transaction, deleting a
// schedule — take an explicit confirm.
const (
	maxBatch       = 50
	maxAssignments = 20
)

func (s *Server) addWriteTools(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ynab_create_transactions",
		Annotations: writeTool(false),
		Description: "Record one or more transactions. Amounts are in the budget's currency and spending is " +
			"NEGATIVE — -12.40 for a $12.40 purchase, positive only for income. A payee name that does not exist " +
			"yet is created. Dates in the future are refused by YNAB; use manage_scheduled_transaction for those. " +
			"Pass dry_run to see exactly what would be recorded without recording it.",
	}, s.createTransactions)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ynab_update_transactions",
		Annotations: writeTool(true),
		Description: "Change existing transactions: categorize them, approve them, mark them cleared, or fix a " +
			"payee, amount or memo. Only the fields you pass are changed, and the old value of each is echoed " +
			"back. This is the tool for clearing out what ynab_search_transactions(status:'uncategorized') or " +
			"status:'unapproved' returned. Amount and date cannot be changed on a split transaction and are " +
			"ignored there.",
	}, s.updateTransactions)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ynab_delete_transaction",
		Annotations: writeTool(true),
		Description: "Delete one transaction. YNAB has no undo, so this cannot be reversed — confirm with the " +
			"person first, and pass confirm:true. One transaction per call, on purpose. The deleted transaction " +
			"is echoed back so it can be recreated by hand if it turns out to have been the wrong one.",
	}, s.deleteTransaction)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ynab_assign_budget",
		Annotations: writeTool(true),
		Description: "Assign money to categories for a month, or move money between them. Give each category " +
			"either amount (set what is assigned to exactly this) or change (add this to what is already " +
			"assigned, negative to take money away). Moving $50 from Dining Out to Groceries is one call with " +
			"change:-50 on one and change:50 on the other. An amount overwrites whatever was assigned, so prefer " +
			"change unless you mean to replace it.",
	}, s.assignBudget)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ynab_manage_scheduled_transaction",
		Annotations: writeTool(true),
		Description: "Create, change or delete a scheduled (recurring) transaction. Set action to 'create', " +
			"'update' or 'delete'. Deleting cannot be undone and needs confirm:true. Splits cannot be created " +
			"through the API.",
	}, s.manageScheduledTransaction)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ynab_manage_category",
		Annotations: writeTool(false),
		Description: "Create or rename a category or a category group, and set or clear a category's target. " +
			"Nothing here deletes anything; YNAB has no API for deleting a category. Use ynab_assign_budget to put " +
			"money in a category — this tool only changes what the category is.",
	}, s.manageCategory)
}

// --- create_transactions ---

type newTransaction struct {
	Account   string  `json:"account" jsonschema:"account name or id"`
	Amount    float64 `json:"amount" jsonschema:"amount in the budget's currency; NEGATIVE for spending, positive for income"`
	Date      string  `json:"date,omitempty" jsonschema:"YYYY-MM-DD, 'today' (the default) or 'yesterday'"`
	Payee     string  `json:"payee,omitempty" jsonschema:"payee name or id; a name that does not exist yet is created"`
	Category  string  `json:"category,omitempty" jsonschema:"category name or id"`
	Memo      string  `json:"memo,omitempty"`
	Cleared   string  `json:"cleared,omitempty" jsonschema:"'cleared', 'uncleared' (the default) or 'reconciled'"`
	FlagColor string  `json:"flag_color,omitempty" jsonschema:"red, orange, yellow, green, blue or purple"`
	Splits    []split `json:"splits,omitempty" jsonschema:"split the transaction across categories; the split amounts must add up to amount"`
}

type split struct {
	Amount   float64 `json:"amount" jsonschema:"amount for this part, in the budget's currency"`
	Category string  `json:"category,omitempty" jsonschema:"category name or id"`
	Memo     string  `json:"memo,omitempty"`
}

type createTransactionsInput struct {
	BudgetID     string           `json:"budget_id,omitempty" jsonschema:"budget to use; defaults to the most recently used one"`
	DryRun       bool             `json:"dry_run,omitempty" jsonschema:"show what would be recorded without recording it"`
	Transactions []newTransaction `json:"transactions" jsonschema:"the transactions to record, at most 50"`
}

func (s *Server) createTransactions(ctx context.Context, _ *mcp.CallToolRequest, in createTransactionsInput) (*mcp.CallToolResult, any, error) {
	if len(in.Transactions) == 0 {
		return fail(fmt.Errorf("no transactions given"))
	}
	if len(in.Transactions) > maxBatch {
		return fail(fmt.Errorf("%d transactions is more than the %d a single call takes; split it up", len(in.Transactions), maxBatch))
	}
	p := plan(in.BudgetID)
	now := s.now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	var payload []ynab.NewTransaction
	var preview strings.Builder
	cf := s.currency(ctx, p)
	for i, t := range in.Transactions {
		account, err := s.api.ResolveAccount(ctx, p, t.Account)
		if err != nil {
			return fail(fmt.Errorf("transaction %d: %w", i+1, err))
		}
		date, err := parseDate(t.Date, now)
		if err != nil {
			return fail(fmt.Errorf("transaction %d: %w", i+1, err))
		}
		if date.After(today) {
			return fail(fmt.Errorf("transaction %d is dated %s, in the future. YNAB refuses those; use ynab_manage_scheduled_transaction instead",
				i+1, date.Format("2006-01-02")))
		}
		nt := ynab.NewTransaction{
			AccountId: ptr(uuidOf(account.ID)),
			Amount:    ptr(toMilli(t.Amount)),
			Date:      ptr(apiDate(date)),
			Approved:  ptr(true),
		}
		if t.Memo != "" {
			nt.Memo = ptr(t.Memo)
		}
		if t.Cleared != "" {
			nt.Cleared = ptr(ynab.TransactionClearedStatus(t.Cleared))
		}
		if t.FlagColor != "" {
			nt.FlagColor = ptr(ynab.TransactionFlagColor(t.FlagColor))
		}
		payeeLabel := "—"
		if t.Payee != "" {
			// An unknown name is not an error here: YNAB creates a payee from
			// payee_name, which is the whole point of naming one.
			if ref, err := s.api.ResolvePayee(ctx, p, t.Payee); err == nil {
				nt.PayeeId = ptr(uuidOf(ref.ID))
				payeeLabel = ref.Name
			} else {
				nt.PayeeName = ptr(t.Payee)
				payeeLabel = t.Payee + " (new)"
			}
		}
		categoryLabel := "—"
		if len(t.Splits) > 0 {
			subs, labels, err := s.resolveSplits(ctx, p, t)
			if err != nil {
				return fail(fmt.Errorf("transaction %d: %w", i+1, err))
			}
			nt.Subtransactions = &subs
			categoryLabel = "split: " + strings.Join(labels, ", ")
		} else if t.Category != "" {
			ref, err := s.api.ResolveCategory(ctx, p, t.Category)
			if err != nil {
				return fail(fmt.Errorf("transaction %d: %w", i+1, err))
			}
			nt.CategoryId = ptr(uuidOf(ref.ID))
			categoryLabel = ref.Name
		}
		payload = append(payload, nt)
		direction := "outflow"
		if t.Amount > 0 {
			direction = "INFLOW"
		}
		fmt.Fprintf(&preview, "%s | %s (%s) | %s | %s | %s\n",
			date.Format("2006-01-02"), money(nil, toMilli(t.Amount), cf), direction,
			payeeLabel, categoryLabel, account.Name)
	}

	if in.DryRun {
		return text("Dry run — nothing was recorded. This is what would be:\n" + preview.String()), nil, nil
	}
	res, err := s.api.CreateTransactions(ctx, p, payload)
	if err != nil {
		return fail(err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Recorded %d transaction(s):\n%s", len(res.Data.TransactionIds), preview.String())
	if res.Data.DuplicateImportIds != nil && len(*res.Data.DuplicateImportIds) > 0 {
		fmt.Fprintf(&b, "\n%d were skipped as duplicates of transactions already imported.\n", len(*res.Data.DuplicateImportIds))
	}
	return text(b.String()), nil, nil
}

// resolveSplits turns the split legs into YNAB's subtransactions, and checks
// that they add up. YNAB rejects a mismatch with a bare validation error; the
// arithmetic is worth doing here so the message says which way it is off.
func (s *Server) resolveSplits(ctx context.Context, p string, t newTransaction) ([]ynab.SaveSubTransaction, []string, error) {
	var subs []ynab.SaveSubTransaction
	var labels []string
	var sum int64
	for _, sp := range t.Splits {
		sub := ynab.SaveSubTransaction{Amount: toMilli(sp.Amount)}
		label := "—"
		if sp.Category != "" {
			ref, err := s.api.ResolveCategory(ctx, p, sp.Category)
			if err != nil {
				return nil, nil, err
			}
			sub.CategoryId = ptr(uuidOf(ref.ID))
			label = ref.Name
		}
		if sp.Memo != "" {
			sub.Memo = ptr(sp.Memo)
		}
		sum += sub.Amount
		subs = append(subs, sub)
		labels = append(labels, label)
	}
	if want := toMilli(t.Amount); sum != want {
		return nil, nil, fmt.Errorf("the split parts add up to %.2f but the transaction is %.2f",
			float64(sum)/1000, float64(want)/1000)
	}
	return subs, labels, nil
}

// --- update_transactions ---

type transactionUpdate struct {
	TransactionID string   `json:"transaction_id" jsonschema:"the transaction's id, as shown at the end of a ynab_search_transactions line"`
	Amount        *float64 `json:"amount,omitempty" jsonschema:"new amount in the budget's currency; NEGATIVE for spending"`
	Date          string   `json:"date,omitempty" jsonschema:"new date, YYYY-MM-DD"`
	Payee         string   `json:"payee,omitempty" jsonschema:"payee name or id"`
	Category      string   `json:"category,omitempty" jsonschema:"category name or id"`
	Memo          string   `json:"memo,omitempty"`
	Cleared       string   `json:"cleared,omitempty" jsonschema:"'cleared', 'uncleared' or 'reconciled'"`
	Approved      *bool    `json:"approved,omitempty"`
	FlagColor     string   `json:"flag_color,omitempty" jsonschema:"red, orange, yellow, green, blue or purple"`
}

type updateTransactionsInput struct {
	BudgetID string              `json:"budget_id,omitempty" jsonschema:"budget to use; defaults to the most recently used one"`
	DryRun   bool                `json:"dry_run,omitempty" jsonschema:"show what would change without changing it"`
	Updates  []transactionUpdate `json:"updates" jsonschema:"the changes to make, at most 50"`
}

func (s *Server) updateTransactions(ctx context.Context, _ *mcp.CallToolRequest, in updateTransactionsInput) (*mcp.CallToolResult, any, error) {
	if len(in.Updates) == 0 {
		return fail(fmt.Errorf("no updates given"))
	}
	if len(in.Updates) > maxBatch {
		return fail(fmt.Errorf("%d updates is more than the %d a single call takes; split it up", len(in.Updates), maxBatch))
	}
	p := plan(in.BudgetID)
	now := s.now()

	var payload []ynab.SaveTransactionWithIdOrImportId
	var preview strings.Builder
	for i, u := range in.Updates {
		if u.TransactionID == "" {
			return fail(fmt.Errorf("update %d has no transaction_id", i+1))
		}
		save := ynab.SaveTransactionWithIdOrImportId{Id: ptr(u.TransactionID)}
		var changes []string
		if u.Amount != nil {
			save.Amount = ptr(toMilli(*u.Amount))
			changes = append(changes, fmt.Sprintf("amount → %.2f", *u.Amount))
		}
		if u.Date != "" {
			d, err := parseDate(u.Date, now)
			if err != nil {
				return fail(fmt.Errorf("update %d: %w", i+1, err))
			}
			save.Date = ptr(apiDate(d))
			changes = append(changes, "date → "+d.Format("2006-01-02"))
		}
		if u.Category != "" {
			ref, err := s.api.ResolveCategory(ctx, p, u.Category)
			if err != nil {
				return fail(fmt.Errorf("update %d: %w", i+1, err))
			}
			save.CategoryId = ptr(uuidOf(ref.ID))
			changes = append(changes, "category → "+ref.Name)
		}
		if u.Payee != "" {
			if ref, err := s.api.ResolvePayee(ctx, p, u.Payee); err == nil {
				save.PayeeId = ptr(uuidOf(ref.ID))
				changes = append(changes, "payee → "+ref.Name)
			} else {
				save.PayeeName = ptr(u.Payee)
				changes = append(changes, "payee → "+u.Payee+" (new)")
			}
		}
		if u.Memo != "" {
			save.Memo = ptr(u.Memo)
			changes = append(changes, "memo → "+truncate(u.Memo, 40))
		}
		if u.Cleared != "" {
			save.Cleared = ptr(ynab.TransactionClearedStatus(u.Cleared))
			changes = append(changes, "cleared → "+u.Cleared)
		}
		if u.Approved != nil {
			save.Approved = u.Approved
			changes = append(changes, fmt.Sprintf("approved → %t", *u.Approved))
		}
		if u.FlagColor != "" {
			save.FlagColor = ptr(ynab.TransactionFlagColor(u.FlagColor))
			changes = append(changes, "flag → "+u.FlagColor)
		}
		if len(changes) == 0 {
			return fail(fmt.Errorf("update %d changes nothing", i+1))
		}
		payload = append(payload, save)
		fmt.Fprintf(&preview, "%s: %s\n", ynab.ShortID(u.TransactionID), strings.Join(changes, ", "))
	}

	if in.DryRun {
		return text("Dry run — nothing was changed. This is what would change:\n" + preview.String()), nil, nil
	}
	res, err := s.api.UpdateTransactions(ctx, p, payload)
	if err != nil {
		return fail(err)
	}
	return text(fmt.Sprintf("Changed %d transaction(s):\n%s", len(res.Data.TransactionIds), preview.String())), nil, nil
}

// --- delete_transaction ---

type deleteTransactionInput struct {
	BudgetID      string `json:"budget_id,omitempty" jsonschema:"budget to use; defaults to the most recently used one"`
	TransactionID string `json:"transaction_id" jsonschema:"the transaction's id, as shown at the end of a ynab_search_transactions line"`
	Confirm       bool   `json:"confirm" jsonschema:"must be true; deleting cannot be undone"`
}

func (s *Server) deleteTransaction(ctx context.Context, _ *mcp.CallToolRequest, in deleteTransactionInput) (*mcp.CallToolResult, any, error) {
	if in.TransactionID == "" {
		return fail(fmt.Errorf("transaction_id is required"))
	}
	if !in.Confirm {
		return fail(fmt.Errorf("deleting a transaction cannot be undone. Check with the person whose budget this is, then call again with confirm:true"))
	}
	p := plan(in.BudgetID)
	t, err := s.api.DeleteTransaction(ctx, p, in.TransactionID)
	if err != nil {
		return fail(err)
	}
	cf := s.currency(ctx, p)
	return text(fmt.Sprintf("Deleted, and it cannot be restored through the API:\n%s | %s | %s | %s | %s",
		isoDate(t.Date), money(t.AmountFormatted, t.Amount, cf),
		orDash(str(t.PayeeName)), orDash(str(t.CategoryName)), t.AccountName)), nil, nil
}

// --- assign_budget ---

type assignment struct {
	Category string   `json:"category" jsonschema:"category name or id"`
	Amount   *float64 `json:"amount,omitempty" jsonschema:"set the assigned amount to exactly this, replacing what is there"`
	Change   *float64 `json:"change,omitempty" jsonschema:"add this to the assigned amount; negative takes money away"`
}

type assignBudgetInput struct {
	BudgetID    string       `json:"budget_id,omitempty" jsonschema:"budget to use; defaults to the most recently used one"`
	Month       string       `json:"month,omitempty" jsonschema:"'current' (the default), 'last-month' or a month like 2026-03"`
	DryRun      bool         `json:"dry_run,omitempty" jsonschema:"show what would change without changing it"`
	Assignments []assignment `json:"assignments" jsonschema:"the categories to assign to, at most 20"`
}

func (s *Server) assignBudget(ctx context.Context, _ *mcp.CallToolRequest, in assignBudgetInput) (*mcp.CallToolResult, any, error) {
	if len(in.Assignments) == 0 {
		return fail(fmt.Errorf("no assignments given"))
	}
	if len(in.Assignments) > maxAssignments {
		return fail(fmt.Errorf("%d assignments is more than the %d a single call takes. Each one is a separate request against YNAB's hourly limit, so do them in smaller batches", len(in.Assignments), maxAssignments))
	}
	p := plan(in.BudgetID)
	month, err := parseMonth(in.Month, s.now())
	if err != nil {
		return fail(err)
	}
	// One read of the month covers every relative change and gives the before
	// values the result reports.
	m, err := s.api.Month(ctx, p, apiDate(month))
	if err != nil {
		return fail(err)
	}
	current := map[string]int64{}
	for _, c := range m.Categories {
		current[c.Id.String()] = c.Budgeted
	}
	cf := s.currency(ctx, p)

	type change struct {
		name       string
		id         string
		before     int64
		after      int64
		unresolved bool
	}
	var planned []change
	for i, a := range in.Assignments {
		if (a.Amount == nil) == (a.Change == nil) {
			return fail(fmt.Errorf("assignment %d must give exactly one of amount or change", i+1))
		}
		ref, err := s.api.ResolveCategory(ctx, p, a.Category)
		if err != nil {
			return fail(fmt.Errorf("assignment %d: %w", i+1, err))
		}
		before, ok := current[ref.ID]
		if !ok {
			return fail(fmt.Errorf("assignment %d: %q is not a category in %s", i+1, ref.Name, month.Format("2006-01")))
		}
		after := toMilli(*a.Amount)
		if a.Change != nil {
			after = before + toMilli(*a.Change)
		}
		planned = append(planned, change{name: ref.Name, id: ref.ID, before: before, after: after})
	}

	var b strings.Builder
	if in.DryRun {
		fmt.Fprintf(&b, "Dry run — nothing was assigned. For %s this would be:\n", month.Format("2006-01"))
	} else {
		fmt.Fprintf(&b, "Assigned for %s:\n", month.Format("2006-01"))
	}
	for _, c := range planned {
		if !in.DryRun {
			if _, err := s.api.SetBudgeted(ctx, p, apiDate(month), c.id, c.after); err != nil {
				fmt.Fprintf(&b, "%-28s FAILED: %v\n", truncate(c.name, 28), err)
				continue
			}
		}
		fmt.Fprintf(&b, "%-28s %s → %s\n", truncate(c.name, 28), money(nil, c.before, cf), money(nil, c.after, cf))
	}
	if !in.DryRun {
		// Ready to Assign moves with every one of these, and it is the number
		// the next decision depends on, so it is re-read rather than computed.
		if after, err := s.api.Month(ctx, p, apiDate(month)); err == nil {
			fmt.Fprintf(&b, "\nReady to Assign is now %s.", money(after.ToBeBudgetedFormatted, after.ToBeBudgeted, cf))
		}
	}
	return text(b.String()), nil, nil
}

// uuidOf parses an id that came back from YNAB. A resolved reference always
// holds a well-formed uuid, so a parse failure here would be this server
// corrupting its own cache rather than bad input.
func uuidOf(id string) openapi_types.UUID {
	u, err := uuid.Parse(id)
	if err != nil {
		return openapi_types.UUID{}
	}
	return u
}
