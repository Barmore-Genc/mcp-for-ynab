package mcpserver

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Barmore-Genc/mcp-for-ynab/internal/ynab"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// A budget's transaction history is the one thing here big enough to fill a
// context window on its own: a year is thousands of rows, and each one as JSON
// is around ten times what the rendered line costs. So the list is capped and
// says it is capped, and group_by exists to answer the aggregate questions —
// which are most of them — without listing anything.
const (
	defaultTxnLimit = 50
	maxTxnLimit     = 200
	// maxTxnScan is where a request stops being a question and starts being a
	// dump. Past it the tool refuses and points at group_by, because paginating
	// through it would cost more requests than the hour allows anyway.
	maxTxnScan = 5000
)

type searchTransactionsInput struct {
	BudgetID  string  `json:"budget_id,omitempty" jsonschema:"budget to use; defaults to the most recently used one"`
	SinceDate string  `json:"since_date,omitempty" jsonschema:"earliest date; YYYY-MM-DD or an offset like -90d. Defaults to 30 days ago"`
	UntilDate string  `json:"until_date,omitempty" jsonschema:"latest date; YYYY-MM-DD or 'today'"`
	Account   string  `json:"account,omitempty" jsonschema:"account name or id"`
	Category  string  `json:"category,omitempty" jsonschema:"category name or id; pass 'uncategorized' for transactions with no category"`
	Payee     string  `json:"payee,omitempty" jsonschema:"payee name or id"`
	Text      string  `json:"text,omitempty" jsonschema:"match this text against the memo, payee and category names"`
	Status    string  `json:"status,omitempty" jsonschema:"'uncategorized' or 'unapproved' to see only transactions needing attention"`
	Cleared   string  `json:"cleared,omitempty" jsonschema:"'cleared', 'uncleared' or 'reconciled'"`
	FlagColor string  `json:"flag_color,omitempty" jsonschema:"red, orange, yellow, green, blue or purple"`
	MinAmount float64 `json:"min_amount,omitempty" jsonschema:"smallest amount to include, in currency units; spending is negative"`
	MaxAmount float64 `json:"max_amount,omitempty" jsonschema:"largest amount to include, in currency units"`
	GroupBy   string  `json:"group_by,omitempty" jsonschema:"total the results instead of listing them: 'category', 'payee', 'account' or 'month'"`
	Sort      string  `json:"sort,omitempty" jsonschema:"date_desc (default), date_asc, amount_asc or amount_desc"`
	Limit     int     `json:"limit,omitempty" jsonschema:"how many transactions to list, default 50, maximum 200"`
	Offset    int     `json:"offset,omitempty" jsonschema:"skip this many, to page through a long result"`
}

func (s *Server) searchTransactions(ctx context.Context, _ *mcp.CallToolRequest, in searchTransactionsInput) (*mcp.CallToolResult, any, error) {
	p := plan(in.BudgetID)
	now := s.now()

	since, err := parseDate(nonEmpty(in.SinceDate, "-30d"), now)
	if err != nil {
		return fail(err)
	}
	var until *time.Time
	if in.UntilDate != "" {
		t, err := parseDate(in.UntilDate, now)
		if err != nil {
			return fail(err)
		}
		until = &t
	}

	scope := ynab.TransactionScope{SinceDate: ptr(apiDate(since)), Type: in.Status}
	if until != nil {
		scope.UntilDate = ptr(apiDate(*until))
	}
	// Only one scope is sent to YNAB, even when several filters are given; the
	// rest are applied here. Account is preferred because it is the endpoint
	// that returns whole transactions rather than split legs.
	uncategorized := strings.EqualFold(in.Category, "uncategorized")
	switch {
	case in.Account != "":
		ref, err := s.api.ResolveAccount(ctx, p, in.Account)
		if err != nil {
			return fail(err)
		}
		scope.AccountID = ref.ID
	case in.Category != "" && !uncategorized:
		ref, err := s.api.ResolveCategory(ctx, p, in.Category)
		if err != nil {
			return fail(err)
		}
		scope.CategoryID = ref.ID
	case in.Payee != "":
		ref, err := s.api.ResolvePayee(ctx, p, in.Payee)
		if err != nil {
			return fail(err)
		}
		scope.PayeeID = ref.ID
	}
	if uncategorized && scope.Type == "" {
		scope.Type = "uncategorized"
	}

	rows, err := s.api.Transactions(ctx, p, scope)
	if err != nil {
		return fail(err)
	}
	rows, err = s.filter(ctx, p, rows, in, uncategorized, scope)
	if err != nil {
		return fail(err)
	}

	cf := s.currency(ctx, p)
	window := fmt.Sprintf("%s → %s", since.Format("2006-01-02"), untilText(until, now))
	if in.GroupBy != "" && in.GroupBy != "none" {
		return text(renderGroups(rows, in.GroupBy, window, cf)), nil, nil
	}
	if len(rows) > maxTxnScan {
		return fail(fmt.Errorf("that matches %d transactions, too many to list. Narrow the dates or filters, or pass group_by to total them instead", len(rows)))
	}
	return text(renderTransactions(rows, in, window, cf)), nil, nil
}

// filter applies everything YNAB's own query parameters cannot express. The
// scope filters are re-applied here for the case where more than one was given
// and only the first went to the API.
func (s *Server) filter(ctx context.Context, p string, rows []ynab.Txn, in searchTransactionsInput, uncategorized bool, scope ynab.TransactionScope) ([]ynab.Txn, error) {
	var categoryID, payeeID, accountID string
	if in.Category != "" && !uncategorized && scope.CategoryID == "" {
		ref, err := s.api.ResolveCategory(ctx, p, in.Category)
		if err != nil {
			return nil, err
		}
		categoryID = ref.ID
	}
	if in.Payee != "" && scope.PayeeID == "" {
		ref, err := s.api.ResolvePayee(ctx, p, in.Payee)
		if err != nil {
			return nil, err
		}
		payeeID = ref.ID
	}
	if in.Account != "" && scope.AccountID == "" {
		ref, err := s.api.ResolveAccount(ctx, p, in.Account)
		if err != nil {
			return nil, err
		}
		accountID = ref.ID
	}

	needle := strings.ToLower(in.Text)
	out := rows[:0]
	for _, t := range rows {
		switch {
		case categoryID != "" && t.CategoryID != categoryID,
			accountID != "" && t.AccountID != accountID,
			uncategorized && t.CategoryName != "",
			in.Cleared != "" && !strings.EqualFold(t.Cleared, in.Cleared),
			in.FlagColor != "" && !strings.EqualFold(t.FlagColor, in.FlagColor),
			in.MinAmount != 0 && t.Amount < toMilli(in.MinAmount),
			in.MaxAmount != 0 && t.Amount > toMilli(in.MaxAmount):
			continue
		}
		if needle != "" && !strings.Contains(strings.ToLower(t.Memo+" "+t.PayeeName+" "+t.CategoryName), needle) {
			continue
		}
		out = append(out, t)
	}
	// payeeID is resolved but only usable as a scope: the row carries the payee
	// name rather than its id, so a second payee filter falls back to the name.
	if payeeID != "" {
		name := strings.ToLower(in.Payee)
		kept := out[:0]
		for _, t := range out {
			if strings.Contains(strings.ToLower(t.PayeeName), name) {
				kept = append(kept, t)
			}
		}
		out = kept
	}
	return out, nil
}

func renderTransactions(rows []ynab.Txn, in searchTransactionsInput, window string, cf *ynab.CurrencyFormat) string {
	sortTransactions(rows, in.Sort)
	var total int64
	for _, t := range rows {
		total += t.Amount
	}
	limit := clamp(in.Limit, defaultTxnLimit, maxTxnLimit)
	start := min(max(in.Offset, 0), len(rows))
	end := min(start+limit, len(rows))

	var b strings.Builder
	fmt.Fprintf(&b, "%d transactions, %s, totalling %s\n", len(rows), window, money(nil, total, cf))
	for _, t := range rows[start:end] {
		flags := ""
		if !t.Approved {
			flags += " | unapproved"
		}
		if t.FlagColor != "" {
			flags += " | flag " + t.FlagColor
		}
		if t.IsSplitPart {
			flags += " | part of a split"
		}
		memo := ""
		if t.Memo != "" {
			memo = " | " + truncate(t.Memo, 60)
		}
		fmt.Fprintf(&b, "%s | %10s | %s | %s | %s | %s%s%s | %s\n",
			isoDate(t.Date), money(t.AmountText, t.Amount, cf),
			orDash(t.PayeeName), orDash(t.CategoryName), t.AccountName,
			t.Cleared, flags, memo, ynab.ShortID(t.ID))
	}
	if len(rows) == 0 {
		b.WriteString("Nothing matched. Widen since_date if you were looking further back.\n")
	}
	if end < len(rows) {
		fmt.Fprintf(&b, "\nShowing %d-%d of %d. Pass offset:%d for the next page, or group_by to total them instead of listing them.\n",
			start+1, end, len(rows), end)
	}
	return b.String()
}

func renderGroups(rows []ynab.Txn, by, window string, cf *ynab.CurrencyFormat) string {
	type bucket struct {
		count int
		total int64
	}
	buckets := map[string]*bucket{}
	var grand int64
	for _, t := range rows {
		var key string
		switch by {
		case "category":
			key = orDash(t.CategoryName)
		case "payee":
			key = orDash(t.PayeeName)
		case "account":
			key = t.AccountName
		case "month":
			key = t.Date.Format("2006-01")
		default:
			key = "all"
		}
		bk := buckets[key]
		if bk == nil {
			bk = &bucket{}
			buckets[key] = bk
		}
		bk.count++
		bk.total += t.Amount
		grand += t.Amount
	}
	keys := make([]string, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	// Biggest outflow first, which is the order the question is usually asked
	// in; months sort chronologically instead, where order is the point.
	if by == "month" {
		sort.Strings(keys)
	} else {
		sort.Slice(keys, func(i, j int) bool { return buckets[keys[i]].total < buckets[keys[j]].total })
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d transactions, %s, totalling %s, by %s:\n", len(rows), window, money(nil, grand, cf), by)
	for _, k := range keys {
		fmt.Fprintf(&b, "%-34s %12s  (%d)\n", truncate(k, 34), money(nil, buckets[k].total, cf), buckets[k].count)
	}
	return b.String()
}

func sortTransactions(rows []ynab.Txn, by string) {
	switch by {
	case "date_asc":
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].Date.Before(rows[j].Date.Time) })
	case "amount_asc":
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].Amount < rows[j].Amount })
	case "amount_desc":
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].Amount > rows[j].Amount })
	default:
		sort.SliceStable(rows, func(i, j int) bool { return rows[j].Date.Before(rows[i].Date.Time) })
	}
}

// --- get_transaction ---

type getTransactionInput struct {
	BudgetID      string `json:"budget_id,omitempty" jsonschema:"budget to use; defaults to the most recently used one"`
	TransactionID string `json:"transaction_id" jsonschema:"the transaction's id, as shown at the end of a ynab_search_transactions line"`
}

func (s *Server) getTransaction(ctx context.Context, _ *mcp.CallToolRequest, in getTransactionInput) (*mcp.CallToolResult, any, error) {
	if in.TransactionID == "" {
		return fail(fmt.Errorf("transaction_id is required"))
	}
	p := plan(in.BudgetID)
	t, err := s.api.Transaction(ctx, p, in.TransactionID)
	if err != nil {
		return fail(err)
	}
	cf := s.currency(ctx, p)
	var b strings.Builder
	fmt.Fprintf(&b, "Date        %s\n", isoDate(t.Date))
	fmt.Fprintf(&b, "Amount      %s\n", money(t.AmountFormatted, t.Amount, cf))
	fmt.Fprintf(&b, "Payee       %s\n", orDash(str(t.PayeeName)))
	fmt.Fprintf(&b, "Category    %s\n", orDash(str(t.CategoryName)))
	fmt.Fprintf(&b, "Account     %s\n", t.AccountName)
	fmt.Fprintf(&b, "Status      %s, %s\n", t.Cleared, approvedText(t.Approved))
	if t.Memo != nil && *t.Memo != "" {
		fmt.Fprintf(&b, "Memo        %s\n", *t.Memo)
	}
	if t.FlagColor != nil {
		fmt.Fprintf(&b, "Flag        %s\n", string(*t.FlagColor))
	}
	if t.TransferAccountId != nil {
		fmt.Fprintf(&b, "Transfer    to or from another account in this budget\n")
	}
	if t.ImportPayeeNameOriginal != nil && *t.ImportPayeeNameOriginal != "" {
		fmt.Fprintf(&b, "Imported as %s\n", *t.ImportPayeeNameOriginal)
	}
	fmt.Fprintf(&b, "Id          %s\n", t.Id)
	if len(t.Subtransactions) > 0 {
		fmt.Fprintf(&b, "\nSplit into %d parts:\n", len(t.Subtransactions))
		for _, sub := range t.Subtransactions {
			if sub.Deleted {
				continue
			}
			fmt.Fprintf(&b, "  %10s | %s | %s | %s\n",
				money(sub.AmountFormatted, sub.Amount, cf),
				orDash(str(sub.CategoryName)), orDash(str(sub.PayeeName)), truncate(str(sub.Memo), 60))
		}
	}
	return text(b.String()), nil, nil
}

func approvedText(approved bool) string {
	if approved {
		return "approved"
	}
	return "not yet approved"
}

// --- list_scheduled_transactions ---

type listScheduledInput struct {
	BudgetID   string `json:"budget_id,omitempty" jsonschema:"budget to use; defaults to the most recently used one"`
	WithinDays int    `json:"within_days,omitempty" jsonschema:"only those due within this many days, default 30; pass 0 for all"`
	Account    string `json:"account,omitempty" jsonschema:"account name or id"`
}

func (s *Server) listScheduledTransactions(ctx context.Context, _ *mcp.CallToolRequest, in listScheduledInput) (*mcp.CallToolResult, any, error) {
	p := plan(in.BudgetID)
	all, err := s.api.ScheduledTransactions(ctx, p)
	if err != nil {
		return fail(err)
	}
	var accountID string
	if in.Account != "" {
		ref, err := s.api.ResolveAccount(ctx, p, in.Account)
		if err != nil {
			return fail(err)
		}
		accountID = ref.ID
	}
	// YNAB has no date filter on this endpoint, so the window is applied here.
	// It defaults to a month because "what is coming up" is the question; a
	// caller that wants the whole standing set passes -1.
	within := in.WithinDays
	if within == 0 {
		within = 30
	}
	cutoff := s.now().AddDate(0, 0, within)

	cf := s.currency(ctx, p)
	var b strings.Builder
	var total int64
	shown := 0
	sort.Slice(all, func(i, j int) bool { return all[i].DateNext.Before(all[j].DateNext.Time) })
	for _, t := range all {
		if accountID != "" && t.AccountId.String() != accountID {
			continue
		}
		if within > 0 && t.DateNext.After(cutoff) {
			continue
		}
		fmt.Fprintf(&b, "%s | %10s | %s | %s | %s | %s [%s]\n",
			isoDate(t.DateNext), money(t.AmountFormatted, t.Amount, cf),
			orDash(str(t.PayeeName)), orDash(str(t.CategoryName)), t.AccountName,
			string(t.Frequency), ynab.ShortID(t.Id.String()))
		total += t.Amount
		shown++
	}
	if shown == 0 {
		return text(fmt.Sprintf("Nothing scheduled in the next %d days.", within)), nil, nil
	}
	fmt.Fprintf(&b, "\n%d scheduled, totalling %s.", shown, money(nil, total, cf))
	return text(b.String()), nil, nil
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func nonEmpty(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func untilText(until *time.Time, now time.Time) string {
	if until != nil {
		return until.Format("2006-01-02")
	}
	return now.Format("2006-01-02")
}
