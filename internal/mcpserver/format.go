package mcpserver

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/Barmore-Genc/mcp-for-ynab/internal/ynab"
	openapi_types "github.com/oapi-codegen/runtime/types"
)

// YNAB stores money as milliunits: 1000 of them to the currency unit, so
// -$294.23 is -294230. That representation never reaches the model. Outputs use
// the `*_formatted` strings YNAB returns, which already honour the budget's
// symbol, separators and decimal digits; inputs are plain currency numbers,
// converted here.

// toMilli converts a currency amount to milliunits. The rounding is load
// bearing: 42.50 * 1000 is 42499.999999999996 in float64, and truncating it
// would lose a cent on a great many amounts.
func toMilli(v float64) int64 { return int64(math.Round(v * 1000)) }

// money renders an amount, preferring YNAB's own formatted string. Only the
// full-plan response omits those, and formatting from the budget's currency
// format is the fallback for it.
func money(formatted *string, milli int64, cf *ynab.CurrencyFormat) string {
	if formatted != nil && *formatted != "" {
		return *formatted
	}
	if cf == nil {
		return strconv.FormatFloat(float64(milli)/1000, 'f', 2, 64)
	}
	digits := int(cf.DecimalDigits)
	neg := milli < 0
	if neg {
		milli = -milli
	}
	s := strconv.FormatFloat(float64(milli)/1000, 'f', digits, 64)
	whole, frac, _ := strings.Cut(s, ".")
	whole = group(whole, cf.GroupSeparator)
	out := whole
	if digits > 0 {
		out += cf.DecimalSeparator + frac
	}
	if cf.DisplaySymbol {
		if cf.SymbolFirst {
			out = cf.CurrencySymbol + out
		} else {
			out += cf.CurrencySymbol
		}
	}
	if neg {
		out = "-" + out
	}
	return out
}

func group(whole, sep string) string {
	if sep == "" || len(whole) <= 3 {
		return whole
	}
	var parts []string
	for len(whole) > 3 {
		parts = append([]string{whole[len(whole)-3:]}, parts...)
		whole = whole[:len(whole)-3]
	}
	return strings.Join(append([]string{whole}, parts...), sep)
}

// parseDate accepts an ISO date or one of the relative forms an agent is likely
// to reach for. Relative forms resolve in the server's local timezone, which is
// whatever TZ the container runs with, because "today" in UTC is the wrong day
// for part of every day for most of the world.
func parseDate(s string, now time.Time) (time.Time, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	switch s {
	case "", "today":
		return today, nil
	case "yesterday":
		return today.AddDate(0, 0, -1), nil
	case "tomorrow":
		return today.AddDate(0, 0, 1), nil
	}
	// "-30d", "-6m", "-1y": a window measured back from today, which is how a
	// question like "the last three months" arrives.
	if len(s) > 2 && s[0] == '-' {
		if n, err := strconv.Atoi(s[1 : len(s)-1]); err == nil {
			switch s[len(s)-1] {
			case 'd':
				return today.AddDate(0, 0, -n), nil
			case 'w':
				return today.AddDate(0, 0, -7*n), nil
			case 'm':
				return today.AddDate(0, -n, 0), nil
			case 'y':
				return today.AddDate(-n, 0, 0), nil
			}
		}
	}
	if t, err := time.ParseInLocation("2006-01-02", s, now.Location()); err == nil {
		return t, nil
	}
	if t, err := time.ParseInLocation("2006-01", s, now.Location()); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("could not read %q as a date; use YYYY-MM-DD, 'today', 'yesterday' or an offset like '-30d'", s)
}

// parseMonth normalizes a month to the first day of that month, which is what
// YNAB's {month} path parameter wants. A bare "2026-03" is the form a model
// reaches for most often and YNAB rejects it, so it is widened here.
//
// YNAB also accepts the literal "current", but resolves it in UTC, which names
// the wrong month for part of every month-end. The current month is resolved
// here instead, in the server's own timezone.
func parseMonth(s string, now time.Time) (time.Time, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "", "current", "this-month", "this month":
		s = now.Format("2006-01")
	case "last-month", "last month":
		s = now.AddDate(0, -1, 0).Format("2006-01")
	case "next-month", "next month":
		s = now.AddDate(0, 1, 0).Format("2006-01")
	}
	t, err := parseDate(s, now)
	if err != nil {
		return time.Time{}, fmt.Errorf("could not read %q as a month; use YYYY-MM, 'current' or 'last-month'", s)
	}
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, t.Location()), nil
}

func apiDate(t time.Time) openapi_types.Date { return openapi_types.Date{Time: t} }

func isoDate(d openapi_types.Date) string { return d.Format("2006-01-02") }

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// truncate keeps free-text fields from dominating a list line. The ellipsis is
// there so the model can tell the difference between a short memo and a cut one.
func truncate(s string, n int) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
	if len(s) <= n {
		return s
	}
	return strings.TrimSpace(s[:n]) + "…"
}

// openapiDate is the generated client's date type, aliased so signatures in
// this package do not have to carry the generator's import name.
type openapiDate = openapi_types.Date
