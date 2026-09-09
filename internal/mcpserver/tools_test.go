package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Barmore-Genc/mcp-for-ynab/internal/oauth"
	"github.com/Barmore-Genc/mcp-for-ynab/internal/ynab"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// fakeYNAB serves canned versions of the endpoints the tools call, so the
// rendering and the filtering can be tested without a real budget behind them.
func fakeYNAB(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, data any) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"data": data})
	}
	mux.HandleFunc("/plans", func(w http.ResponseWriter, r *http.Request) {
		write(w, map[string]any{"plans": []any{map[string]any{
			"id":               planID,
			"name":             "Household",
			"last_modified_on": "2026-03-09T12:00:00Z",
			"first_month":      "2025-01-01",
			"last_month":       "2026-04-01",
			"currency_format": map[string]any{
				"iso_code": "USD", "currency_symbol": "$", "decimal_digits": 2,
				"decimal_separator": ".", "group_separator": ",",
				"display_symbol": true, "symbol_first": true, "example_format": "123,456.78",
			},
		}}})
	})
	mux.HandleFunc("/plans/last-used/accounts", func(w http.ResponseWriter, r *http.Request) {
		write(w, map[string]any{"server_knowledge": 1, "accounts": []any{
			map[string]any{
				"id": accountID, "name": "Checking", "type": "checking", "on_budget": true,
				"closed": false, "deleted": false, "balance": 243109, "cleared_balance": 238009,
				"uncleared_balance": 5100, "balance_formatted": "$243.11",
				"cleared_balance_formatted": "$238.01", "uncleared_balance_formatted": "$51.00",
				"transfer_payee_id": nil,
			},
			map[string]any{
				"id": "cccccccc-3333-4333-8333-333333333333", "name": "Old Card", "type": "creditCard",
				"on_budget": true, "closed": true, "deleted": false, "balance": 0,
				"cleared_balance": 0, "uncleared_balance": 0, "transfer_payee_id": nil,
			},
		}})
	})
	mux.HandleFunc("/plans/last-used/transactions", func(w http.ResponseWriter, r *http.Request) {
		write(w, map[string]any{"server_knowledge": 1, "transactions": []any{
			txnJSON("t1", "2026-03-04", -42500, "Whole Foods", "Groceries", "cleared", true),
			txnJSON("t2", "2026-03-05", -12000, "Whole Foods", "Groceries", "uncleared", false),
			txnJSON("t3", "2026-03-06", -80000, "Landlord", "Rent", "cleared", true),
		}})
	})
	mux.HandleFunc("/plans/last-used/payees", func(w http.ResponseWriter, r *http.Request) {
		write(w, map[string]any{"server_knowledge": 1, "payees": []any{
			map[string]any{"id": "eeeeeeee-5555-4555-8555-555555555555", "name": "Whole Foods", "deleted": false},
			map[string]any{"id": "ffffffff-6666-4666-8666-666666666666", "name": "Landlord", "deleted": false},
		}})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request to %s", r.URL.Path)
		http.Error(w, "not found", http.StatusNotFound)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

const (
	planID    = "11111111-1111-4111-8111-111111111111"
	accountID = "aaaaaaaa-1111-4111-8111-111111111111"
)

func txnJSON(id, date string, amount int, payee, category, cleared string, approved bool) map[string]any {
	return map[string]any{
		"id": id, "date": date, "amount": amount, "cleared": cleared, "approved": approved,
		"deleted": false, "account_id": accountID, "account_name": "Checking",
		"payee_name": payee, "category_name": category,
		"category_id": "dddddddd-4444-4444-8444-444444444444",
		"memo":        nil, "subtransactions": []any{},
	}
}

// connect wires a client to the server over the in-memory transport, which
// exercises the real tool schemas and dispatch without HTTP or OAuth.
func connect(t *testing.T, readOnly bool) *mcp.ClientSession {
	t.Helper()
	fake := fakeYNAB(t)
	api, err := ynab.NewAPIAt("test-token", fake.URL)
	if err != nil {
		t.Fatalf("api: %v", err)
	}
	s := New(api, oauth.NewSigner("secret"), "https://ynab.example", "test", readOnly)
	s.now = func() time.Time { return testNow }

	ctx := context.Background()
	clientT, serverT := mcp.NewInMemoryTransports()
	if _, err := s.build().Connect(ctx, serverT, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func toolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	names := make([]string, 0, len(res.Tools))
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	return names
}

func TestToolSurface(t *testing.T) {
	names := toolNames(t, connect(t, false))
	if len(names) != 13 {
		t.Fatalf("expected 13 tools, got %d: %v", len(names), names)
	}
	// Every name carries the service prefix so it stays distinguishable from
	// the other servers an agent has connected at the same time.
	for _, n := range names {
		if !strings.HasPrefix(n, "ynab_") {
			t.Errorf("tool %q is not prefixed", n)
		}
	}
}

// Read-only mode has to remove the write tools rather than fail them when
// called, so a model never plans around a tool it cannot use.
func TestReadOnlyModeHidesWriteTools(t *testing.T) {
	names := toolNames(t, connect(t, true))
	if len(names) != 7 {
		t.Fatalf("expected 7 read tools, got %d: %v", len(names), names)
	}
	for _, n := range names {
		switch n {
		case "ynab_create_transactions", "ynab_update_transactions", "ynab_delete_transaction",
			"ynab_assign_budget", "ynab_manage_scheduled_transaction", "ynab_manage_category":
			t.Errorf("%s is offered in read-only mode", n)
		}
	}
}

func TestToolsHaveSubstantialDescriptions(t *testing.T) {
	res, err := connect(t, false).ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	for _, tool := range res.Tools {
		if len(tool.Description) < 120 {
			t.Errorf("%s has a %d-character description; a tool needs enough for a model to tell when to reach for it",
				tool.Name, len(tool.Description))
		}
	}
}

func callText(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) string {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	if res.IsError {
		t.Fatalf("%s returned an error: %s", name, b.String())
	}
	return b.String()
}

func TestListAccountsHidesClosedAndTotals(t *testing.T) {
	out := callText(t, connect(t, false), "ynab_list_accounts", map[string]any{})
	if !strings.Contains(out, "Checking") || !strings.Contains(out, "$243.11") {
		t.Fatalf("account line missing: %s", out)
	}
	if strings.Contains(out, "Old Card") {
		t.Fatalf("a closed account was listed by default: %s", out)
	}
	if !strings.Contains(out, "1 closed account(s) not shown") {
		t.Fatalf("the closed account was hidden without saying so: %s", out)
	}
}

func TestSearchTransactionsRendersLinesAndTotal(t *testing.T) {
	out := callText(t, connect(t, false), "ynab_search_transactions", map[string]any{})
	if !strings.Contains(out, "3 transactions") {
		t.Fatalf("count missing: %s", out)
	}
	// Newest first by default, and the window is echoed so an empty result can
	// be told apart from a badly aimed one.
	if !strings.Contains(out, "2026-02-07 → 2026-03-09") {
		t.Fatalf("resolved window not reported: %s", out)
	}
	if i, j := strings.Index(out, "2026-03-06"), strings.Index(out, "2026-03-04"); i > j {
		t.Fatalf("not sorted newest first: %s", out)
	}
	if !strings.Contains(out, "unapproved") {
		t.Fatalf("the unapproved transaction is not marked: %s", out)
	}
}

func TestSearchTransactionsGroupBy(t *testing.T) {
	out := callText(t, connect(t, false), "ynab_search_transactions", map[string]any{"group_by": "category"})
	if !strings.Contains(out, "by category") {
		t.Fatalf("not grouped: %s", out)
	}
	// Groceries is two transactions totalling -54.50, and the biggest outflow
	// leads.
	if !strings.Contains(out, "-$54.50") || !strings.Contains(out, "(2)") {
		t.Fatalf("groceries not totalled: %s", out)
	}
	if strings.Contains(out, "2026-03-04") {
		t.Fatalf("grouping still listed the rows: %s", out)
	}
}

func TestSearchTransactionsTextFilter(t *testing.T) {
	out := callText(t, connect(t, false), "ynab_search_transactions", map[string]any{"text": "landlord"})
	if !strings.Contains(out, "1 transactions") || !strings.Contains(out, "Landlord") {
		t.Fatalf("text filter did not narrow the result: %s", out)
	}
}

// A delete without confirm has to fail before anything reaches YNAB.
func TestDeleteRequiresConfirmation(t *testing.T) {
	cs := connect(t, false)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "ynab_delete_transaction",
		Arguments: map[string]any{"transaction_id": "t1"},
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !res.IsError {
		t.Fatal("an unconfirmed delete was accepted")
	}
}

func TestCreateTransactionRefusesFutureDate(t *testing.T) {
	cs := connect(t, false)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "ynab_create_transactions",
		Arguments: map[string]any{"transactions": []any{map[string]any{
			"account": "Checking", "amount": -10.0, "date": "2026-12-01",
		}}},
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !res.IsError {
		t.Fatal("a future-dated transaction was sent to YNAB, which rejects them")
	}
}

// A dry run must not write, and must show what it would have written.
func TestCreateTransactionsDryRun(t *testing.T) {
	out := callText(t, connect(t, false), "ynab_create_transactions", map[string]any{
		"dry_run": true,
		"transactions": []any{map[string]any{
			"account": "Checking", "amount": -42.50, "payee": "Whole Foods", "date": "today",
		}},
	})
	if !strings.Contains(out, "Dry run") || !strings.Contains(out, "-$42.50") {
		t.Fatalf("dry run did not preview the write: %s", out)
	}
	if !strings.Contains(out, "outflow") {
		t.Fatalf("the direction of the amount is not spelled out: %s", out)
	}
}

// A positive amount is income in YNAB, and mislabelling it is the commonest
// mistake against this API, so the preview has to name it.
func TestCreateTransactionsMarksInflow(t *testing.T) {
	out := callText(t, connect(t, false), "ynab_create_transactions", map[string]any{
		"dry_run": true,
		"transactions": []any{map[string]any{
			"account": "Checking", "amount": 42.50, "payee": "Whole Foods",
		}},
	})
	if !strings.Contains(out, "INFLOW") {
		t.Fatalf("a positive amount was not flagged as income: %s", out)
	}
}

func TestSplitsMustAddUp(t *testing.T) {
	cs := connect(t, false)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "ynab_create_transactions",
		Arguments: map[string]any{"transactions": []any{map[string]any{
			"account": "Checking", "amount": -50.0,
			"splits": []any{map[string]any{"amount": -20.0}, map[string]any{"amount": -20.0}},
		}}},
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !res.IsError {
		t.Fatal("split parts that do not add up were accepted")
	}
}

func TestUnknownAccountNameExplainsItself(t *testing.T) {
	cs := connect(t, false)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "ynab_search_transactions",
		Arguments: map[string]any{"account": "Brokerage"},
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !res.IsError {
		t.Fatal("an unknown account name was accepted")
	}
}

func TestListBudgets(t *testing.T) {
	out := callText(t, connect(t, false), "ynab_list_budgets", map[string]any{})
	if !strings.Contains(out, "Household") || !strings.Contains(out, "USD") {
		t.Fatalf("budget not described: %s", out)
	}
	if !strings.Contains(out, planID) {
		t.Fatalf("the full budget id has to be usable as budget_id: %s", out)
	}
}
