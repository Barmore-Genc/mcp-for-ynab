package mcpserver

import (
	"testing"
	"time"

	"github.com/Barmore-Genc/mcp-for-ynab/internal/ynab"
)

func TestToMilliRounds(t *testing.T) {
	// 42.50 * 1000 is 42499.999999999996 in float64; truncating loses a cent.
	for _, c := range []struct {
		in   float64
		want int64
	}{{42.50, 42500}, {-12.40, -12400}, {0.01, 10}, {1234.56, 1234560}, {0, 0}} {
		if got := toMilli(c.in); got != c.want {
			t.Errorf("toMilli(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestMoneyPrefersYNABsOwnFormatting(t *testing.T) {
	formatted := "£1.234,56"
	if got := money(&formatted, 999, nil); got != formatted {
		t.Fatalf("got %q, want the formatted string through unchanged", got)
	}
}

func TestMoneyFallbackHonoursCurrencyFormat(t *testing.T) {
	euro := &ynab.CurrencyFormat{
		CurrencySymbol: "€", DecimalDigits: 2, DecimalSeparator: ",",
		GroupSeparator: ".", DisplaySymbol: true, SymbolFirst: false,
	}
	if got := money(nil, 1234567, euro); got != "1.234,57€" {
		t.Fatalf("got %q, want 1.234,57€", got)
	}
	if got := money(nil, -50000, euro); got != "-50,00€" {
		t.Fatalf("got %q, want -50,00€", got)
	}
}

func TestMoneyFallbackWithNoCurrencyFormat(t *testing.T) {
	if got := money(nil, -294230, nil); got != "-294.23" {
		t.Fatalf("got %q, want -294.23", got)
	}
}

var testNow = time.Date(2026, 3, 9, 15, 4, 0, 0, time.UTC)

func TestParseDate(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"", "2026-03-09"},
		{"today", "2026-03-09"},
		{"yesterday", "2026-03-08"},
		{"2026-01-15", "2026-01-15"},
		{"-30d", "2026-02-07"},
		{"-3m", "2025-12-09"},
		{"-1y", "2025-03-09"},
		{"2026-01", "2026-01-01"},
	} {
		got, err := parseDate(c.in, testNow)
		if err != nil {
			t.Errorf("parseDate(%q): %v", c.in, err)
			continue
		}
		if got.Format("2006-01-02") != c.want {
			t.Errorf("parseDate(%q) = %s, want %s", c.in, got.Format("2006-01-02"), c.want)
		}
	}
	if _, err := parseDate("sometime last spring", testNow); err == nil {
		t.Error("an unparseable date was accepted")
	}
}

// YNAB wants the first of the month, and a bare YYYY-MM is what a model reaches
// for, so it has to be widened rather than passed through.
func TestParseMonth(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"", "2026-03-01"},
		{"current", "2026-03-01"},
		{"last-month", "2026-02-01"},
		{"2026-01", "2026-01-01"},
		{"2025-12-17", "2025-12-01"},
	} {
		got, err := parseMonth(c.in, testNow)
		if err != nil {
			t.Errorf("parseMonth(%q): %v", c.in, err)
			continue
		}
		if got.Format("2006-01-02") != c.want {
			t.Errorf("parseMonth(%q) = %s, want %s", c.in, got.Format("2006-01-02"), c.want)
		}
	}
}

func TestTruncateMarksWhatItCut(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Fatalf("got %q", got)
	}
	if got := truncate("a much longer memo than fits", 10); got != "a much lon…" {
		t.Fatalf("got %q", got)
	}
}
