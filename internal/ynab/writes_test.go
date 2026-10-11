package ynab

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func fakeAPI(t *testing.T, mux *http.ServeMux) *API {
	t.Helper()
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	a, err := NewAPIAt("test-token", ts.URL)
	if err != nil {
		t.Fatalf("api: %v", err)
	}
	return a
}

// Changing only the amount must leave the payee, category, memo and flag out of
// the body: YNAB clears any field sent as null.
func TestUpdateTransactionsSendsOnlySetFields(t *testing.T) {
	var body map[string][]map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("PATCH /plans/p/transactions", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("decoding body %s: %v", raw, err)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"transaction_ids":["t1"],"server_knowledge":1}}`)
	})
	amount := int64(-102590)
	id := "t1"
	_, err := fakeAPI(t, mux).UpdateTransactions(context.Background(), "p", []SaveTransactionWithIdOrImportId{{Id: &id, Amount: &amount}})
	if err != nil {
		t.Fatal(err)
	}
	got := body["transactions"][0]
	if len(got) != 2 || got["id"] != "t1" || got["amount"] != float64(-102590) {
		t.Fatalf("expected only id and amount, got %v", got)
	}
}

func TestUpdateCategorySendsOnlySetFields(t *testing.T) {
	var body map[string]map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("PATCH /plans/p/categories/c1", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("decoding body %s: %v", raw, err)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"category":{"id":"dddddddd-4444-4444-8444-444444444444","category_group_id":"dddddddd-4444-4444-8444-444444444444","name":"Fun","hidden":false,"budgeted":0,"activity":0,"balance":0,"deleted":false},"server_knowledge":1}}`)
	})
	name := "Fun"
	if _, err := fakeAPI(t, mux).UpdateCategory(context.Background(), "p", "c1", ExistingCategory{Name: &name}); err != nil {
		t.Fatal(err)
	}
	if got := body["category"]; len(got) != 1 || got["name"] != "Fun" {
		t.Fatalf("expected only the name, got %v", got)
	}
}

func TestTransactionCategoryIncludesInflow(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /plans/p/categories", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"server_knowledge":1,"category_groups":[
			{"id":"aaaaaaaa-1111-4111-8111-111111111111","name":"Internal Master Category","hidden":false,"internal":true,"deleted":false,"categories":[
				{"id":"bbbbbbbb-2222-4222-8222-222222222222","category_group_id":"aaaaaaaa-1111-4111-8111-111111111111","name":"Inflow: Ready to Assign","hidden":false,"internal":true,"budgeted":0,"activity":0,"balance":0,"deleted":false}]},
			{"id":"cccccccc-3333-4333-8333-333333333333","name":"Wants","hidden":false,"deleted":false,"categories":[
				{"id":"dddddddd-4444-4444-8444-444444444444","category_group_id":"cccccccc-3333-4333-8333-333333333333","name":"Fun","hidden":false,"budgeted":0,"activity":0,"balance":0,"deleted":false}]}]}}`)
	})
	a := fakeAPI(t, mux)
	ctx := context.Background()
	if _, err := a.ResolveCategory(ctx, "p", "Inflow: Ready to Assign"); err == nil {
		t.Fatal("Ready to Assign must not be assignable")
	}
	got, err := a.ResolveTransactionCategory(ctx, "p", "Inflow: Ready to Assign")
	if err != nil || got.ID != "bbbbbbbb-2222-4222-8222-222222222222" {
		t.Fatalf("got %+v, %v", got, err)
	}
}
