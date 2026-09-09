package ynab

import (
	"errors"
	"testing"
)

var testAccounts = []Named{
	{ID: "aaaaaaaa-1111-4111-8111-111111111111", Name: "Checking"},
	{ID: "bbbbbbbb-2222-4222-8222-222222222222", Name: "Checking Savings"},
	{ID: "cccccccc-3333-4333-8333-333333333333", Name: "Visa"},
}

func TestResolveByFullID(t *testing.T) {
	got, err := resolve("account", testAccounts[2].ID, testAccounts)
	if err != nil || got.Name != "Visa" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestResolveByShortID(t *testing.T) {
	got, err := resolve("account", "cccccccc", testAccounts)
	if err != nil || got.Name != "Visa" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

// An exact name wins over a longer name it is a prefix of, which is the case
// that would otherwise be reported as ambiguous on every call.
func TestExactNameBeatsPrefix(t *testing.T) {
	got, err := resolve("account", "Checking", testAccounts)
	if err != nil || got.Name != "Checking" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestResolveIsCaseInsensitive(t *testing.T) {
	got, err := resolve("account", "vISa", testAccounts)
	if err != nil || got.Name != "Visa" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestAmbiguousListsCandidates(t *testing.T) {
	_, err := resolve("account", "check", testAccounts)
	var amb *AmbiguousError
	if !errors.As(err, &amb) {
		t.Fatalf("expected an ambiguity error, got %v", err)
	}
	if len(amb.Candidates) != 2 {
		t.Fatalf("expected both candidates, got %v", amb.Candidates)
	}
}

func TestNotFound(t *testing.T) {
	_, err := resolve("account", "brokerage", testAccounts)
	var nf *NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected a not-found error, got %v", err)
	}
}

// A category name is only unique within its group, so the group-qualified form
// has to resolve as an exact match.
func TestGroupQualifiedName(t *testing.T) {
	cats := []Named{
		{ID: "1", Name: "Fun", Group: "Wants"},
		{ID: "2", Name: "Fun", Group: "Kids"},
	}
	got, err := resolve("category", "Kids / Fun", cats)
	if err != nil || got.ID != "2" {
		t.Fatalf("got %+v, %v", got, err)
	}
	if _, err := resolve("category", "Fun", cats); err == nil {
		t.Fatal("a name shared by two groups resolved without complaint")
	}
}
