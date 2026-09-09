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

func (s *Server) addReadTools(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ynab_list_budgets",
		Annotations: readOnlyTool(),
		Description: "List the YNAB budgets on this account, with each one's currency and the months it covers. " +
			"Every other tool works on the most recently used budget unless you pass a budget_id, so you only " +
			"need this when the person has more than one budget or names one explicitly.",
	}, s.listBudgets)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ynab_get_budget_month",
		Annotations: readOnlyTool(),
		Description: "The budget for one month: Ready to Assign, total income, assigned and activity, and every " +
			"category's assigned, spent and available amounts. This is the tool for 'how is my budget doing', " +
			"'what is left in X' and 'what am I overspent on'. Use only='overspent' or only='underfunded' to get " +
			"just the categories that need attention, and filter to narrow to one group or name. Goal details are " +
			"left out unless you ask for them, because they are eighteen fields per category.",
	}, s.getBudgetMonth)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ynab_list_accounts",
		Annotations: readOnlyTool(),
		Description: "List the accounts in a budget with their balances, and flag any whose bank connection is " +
			"broken. Closed accounts are left out unless you ask for them.",
	}, s.listAccounts)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ynab_list_payees",
		Annotations: readOnlyTool(),
		Description: "Find payees by name. A budget commonly has hundreds, so pass query to search rather than " +
			"listing them all. Transfer payees (the ones that stand for another account) are left out unless you " +
			"ask for them.",
	}, s.listPayees)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ynab_search_transactions",
		Annotations: readOnlyTool(),
		Description: "Find transactions, or total them up. All filters are optional and combine with AND. " +
			"For a question about totals — what was spent on something, where the money went, how much a payee " +
			"was paid — set group_by and read the totals instead of listing hundreds of rows. The default window " +
			"is the last 30 days, so widen since_date for anything older. Amounts are negative for spending.",
	}, s.searchTransactions)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ynab_get_transaction",
		Annotations: readOnlyTool(),
		Description: "Everything about one transaction, including the parts of a split and where an imported " +
			"transaction came from. search_transactions deliberately leaves those out, so this is how to get them.",
	}, s.getTransaction)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ynab_list_scheduled_transactions",
		Annotations: readOnlyTool(),
		Description: "List scheduled and recurring transactions with when each is next due. Use it for 'what is " +
			"coming up' and 'what are my recurring bills'.",
	}, s.listScheduledTransactions)
}

// --- list_budgets ---

type listBudgetsInput struct{}

func (s *Server) listBudgets(ctx context.Context, _ *mcp.CallToolRequest, _ listBudgetsInput) (*mcp.CallToolResult, any, error) {
	plans, _, err := s.api.Plans(ctx)
	if err != nil {
		return fail(err)
	}
	if len(plans) == 0 {
		return text("This YNAB account has no budgets."), nil, nil
	}
	lastUsed := lastUsedPlan(plans)
	var b strings.Builder
	fmt.Fprintf(&b, "%d budget(s):\n", len(plans))
	for _, p := range plans {
		marker := ""
		if p.Id.String() == lastUsed {
			marker = "  ← used most recently, the default for every tool"
		}
		iso := ""
		if p.CurrencyFormat != nil {
			iso = " | " + p.CurrencyFormat.IsoCode
		}
		months := ""
		if p.FirstMonth != nil && p.LastMonth != nil {
			months = fmt.Sprintf(" | %s → %s", p.FirstMonth.Format("2006-01"), p.LastMonth.Format("2006-01"))
		}
		fmt.Fprintf(&b, "%s%s%s | budget_id %s%s\n", p.Name, iso, months, p.Id.String(), marker)
	}
	return text(b.String()), nil, nil
}

// lastUsedPlan is the local stand-in for YNAB's "last-used" alias, which the
// API resolves server-side and never names in a response. It is only used to
// label the list and to pick a currency format, never to address a request.
func lastUsedPlan(plans []ynab.PlanSummary) string {
	var id string
	var newest time.Time
	for _, p := range plans {
		if p.LastModifiedOn != nil && p.LastModifiedOn.After(newest) {
			newest, id = *p.LastModifiedOn, p.Id.String()
		}
	}
	return id
}

// currency finds the budget's currency format, which is only needed to render
// the one response shape YNAB does not pre-format.
func (s *Server) currency(ctx context.Context, planID string) *ynab.CurrencyFormat {
	plans, _, err := s.api.Plans(ctx)
	if err != nil {
		return nil
	}
	want := planID
	if want == ynab.PlanLastUsed {
		want = lastUsedPlan(plans)
	}
	for _, p := range plans {
		if p.Id.String() == want {
			return p.CurrencyFormat
		}
	}
	return nil
}

// --- get_budget_month ---

type getBudgetMonthInput struct {
	BudgetID      string `json:"budget_id,omitempty" jsonschema:"budget to use; defaults to the most recently used one"`
	Month         string `json:"month,omitempty" jsonschema:"'current' (the default), 'last-month', or a month like 2026-03"`
	Only          string `json:"only,omitempty" jsonschema:"narrow to categories needing attention: 'overspent', 'underfunded', or 'has_goal'"`
	Filter        string `json:"filter,omitempty" jsonschema:"only categories or groups whose name contains this text"`
	IncludeHidden bool   `json:"include_hidden,omitempty" jsonschema:"include hidden categories"`
	IncludeGoals  bool   `json:"include_goals,omitempty" jsonschema:"include each category's goal target and progress"`
}

func (s *Server) getBudgetMonth(ctx context.Context, _ *mcp.CallToolRequest, in getBudgetMonthInput) (*mcp.CallToolResult, any, error) {
	p := plan(in.BudgetID)
	month, err := parseMonth(in.Month, s.now())
	if err != nil {
		return fail(err)
	}
	m, err := s.api.Month(ctx, p, apiDate(month))
	if err != nil {
		return fail(err)
	}
	cf := s.currency(ctx, p)

	var b strings.Builder
	fmt.Fprintf(&b, "Budget for %s\n", m.Month.Format("2006-01"))
	fmt.Fprintf(&b, "Ready to Assign %s | income %s | assigned %s | activity %s",
		money(m.ToBeBudgetedFormatted, m.ToBeBudgeted, cf),
		money(m.IncomeFormatted, m.Income, cf),
		money(m.BudgetedFormatted, m.Budgeted, cf),
		money(m.ActivityFormatted, m.Activity, cf))
	if m.AgeOfMoney != nil {
		fmt.Fprintf(&b, " | age of money %dd", *m.AgeOfMoney)
	}
	b.WriteString("\n\n")

	filter := strings.ToLower(in.Filter)
	shown, skipped := 0, 0
	group := ""
	for _, c := range m.Categories {
		if c.Deleted || c.Internal {
			continue
		}
		if c.Hidden && !in.IncludeHidden {
			continue
		}
		if !matchesOnly(c, in.Only) {
			skipped++
			continue
		}
		name := str(c.CategoryGroupName)
		if filter != "" && !strings.Contains(strings.ToLower(c.Name), filter) && !strings.Contains(strings.ToLower(name), filter) {
			skipped++
			continue
		}
		if name != group {
			group = name
			fmt.Fprintf(&b, "%s\n", group)
		}
		fmt.Fprintf(&b, "  %-28s assigned %10s  spent %10s  available %10s  [%s]",
			truncate(c.Name, 28),
			money(c.BudgetedFormatted, c.Budgeted, cf),
			money(c.ActivityFormatted, c.Activity, cf),
			money(c.BalanceFormatted, c.Balance, cf),
			ynab.ShortID(c.Id.String()))
		if in.IncludeGoals && c.GoalType != nil {
			fmt.Fprintf(&b, "\n      goal %s target %s", string(*c.GoalType), money(c.GoalTargetFormatted, deref(c.GoalTarget), cf))
			if c.GoalTargetMonth != nil {
				fmt.Fprintf(&b, " by %s", c.GoalTargetMonth.Format("2006-01"))
			}
			if c.GoalUnderFunded != nil && *c.GoalUnderFunded > 0 {
				fmt.Fprintf(&b, ", short %s this month", money(c.GoalUnderFundedFormatted, *c.GoalUnderFunded, cf))
			}
		}
		b.WriteString("\n")
		shown++
	}
	if shown == 0 {
		fmt.Fprintf(&b, "No categories matched.\n")
	}
	if skipped > 0 {
		fmt.Fprintf(&b, "\n%d more categories not shown by the filters.\n", skipped)
	}
	if !in.IncludeGoals {
		b.WriteString("Goal targets are omitted; pass include_goals to see them.\n")
	}
	return text(b.String()), nil, nil
}

func matchesOnly(c ynab.Category, only string) bool {
	switch only {
	case "", "all":
		return true
	case "overspent":
		return c.Balance < 0
	case "underfunded":
		return c.GoalUnderFunded != nil && *c.GoalUnderFunded > 0
	case "has_goal":
		return c.GoalType != nil
	default:
		return true
	}
}

// --- list_accounts ---

type listAccountsInput struct {
	BudgetID      string `json:"budget_id,omitempty" jsonschema:"budget to use; defaults to the most recently used one"`
	IncludeClosed bool   `json:"include_closed,omitempty" jsonschema:"include closed accounts"`
}

func (s *Server) listAccounts(ctx context.Context, _ *mcp.CallToolRequest, in listAccountsInput) (*mcp.CallToolResult, any, error) {
	p := plan(in.BudgetID)
	accounts, err := s.api.Accounts(ctx, p)
	if err != nil {
		return fail(err)
	}
	cf := s.currency(ctx, p)
	var b strings.Builder
	var onBudget, tracking int64
	shown, closed := 0, 0
	for _, a := range accounts {
		if a.Closed && !in.IncludeClosed {
			closed++
			continue
		}
		flags := ""
		if a.Closed {
			flags += " | closed"
		}
		if a.DirectImportInError != nil && *a.DirectImportInError {
			flags += " | bank connection is broken"
		}
		fmt.Fprintf(&b, "%-24s %-12s %-10s %12s (cleared %s, uncleared %s)%s [%s]\n",
			truncate(a.Name, 24), string(a.Type), budgetSide(a.OnBudget),
			money(a.BalanceFormatted, a.Balance, cf),
			money(a.ClearedBalanceFormatted, a.ClearedBalance, cf),
			money(a.UnclearedBalanceFormatted, a.UnclearedBalance, cf),
			flags, ynab.ShortID(a.Id.String()))
		shown++
		if a.Closed {
			continue
		}
		if a.OnBudget {
			onBudget += a.Balance
		} else {
			tracking += a.Balance
		}
	}
	if shown == 0 {
		return text("No accounts in this budget."), nil, nil
	}
	fmt.Fprintf(&b, "\nOn-budget total %s | tracking total %s",
		money(nil, onBudget, cf), money(nil, tracking, cf))
	if closed > 0 {
		fmt.Fprintf(&b, "\n%d closed account(s) not shown; pass include_closed to see them.", closed)
	}
	return text(b.String()), nil, nil
}

func budgetSide(onBudget bool) string {
	if onBudget {
		return "on-budget"
	}
	return "tracking"
}

// --- list_payees ---

type listPayeesInput struct {
	BudgetID         string `json:"budget_id,omitempty" jsonschema:"budget to use; defaults to the most recently used one"`
	Query            string `json:"query,omitempty" jsonschema:"only payees whose name contains this text"`
	IncludeTransfers bool   `json:"include_transfer_payees,omitempty" jsonschema:"include the payees that stand for transfers to another account"`
	Limit            int    `json:"limit,omitempty" jsonschema:"how many to return, default 50, maximum 200"`
}

func (s *Server) listPayees(ctx context.Context, _ *mcp.CallToolRequest, in listPayeesInput) (*mcp.CallToolResult, any, error) {
	p := plan(in.BudgetID)
	payees, err := s.api.Payees(ctx, p)
	if err != nil {
		return fail(err)
	}
	limit := clamp(in.Limit, 50, 200)
	q := strings.ToLower(in.Query)
	var matched []ynab.Payee
	for _, v := range payees {
		if v.TransferAccountId != nil && !in.IncludeTransfers {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(v.Name), q) {
			continue
		}
		matched = append(matched, v)
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].Name < matched[j].Name })
	var b strings.Builder
	for i, v := range matched {
		if i >= limit {
			break
		}
		fmt.Fprintf(&b, "%s [%s]\n", v.Name, ynab.ShortID(v.Id.String()))
	}
	if len(matched) == 0 {
		return text(fmt.Sprintf("No payees match %q.", in.Query)), nil, nil
	}
	if len(matched) > limit {
		fmt.Fprintf(&b, "\nShowing %d of %d. Narrow it with query.", limit, len(matched))
	}
	return text(b.String()), nil, nil
}

func clamp(v, def, max int) int {
	if v <= 0 {
		return def
	}
	if v > max {
		return max
	}
	return v
}

func deref(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}
