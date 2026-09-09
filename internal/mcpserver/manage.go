package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/Barmore-Genc/mcp-for-ynab/internal/ynab"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Scheduled transactions and categories each spread three or four endpoints
// over one field set, and an agent touches either of them once in a session if
// at all. They are one tool apiece with an action, where transactions are not:
// there, folding create and delete together would put the irreversible write
// behind the same approval as the cheap one.

// --- manage_scheduled_transaction ---

type manageScheduledInput struct {
	BudgetID  string   `json:"budget_id,omitempty" jsonschema:"budget to use; defaults to the most recently used one"`
	Action    string   `json:"action" jsonschema:"'create', 'update' or 'delete'"`
	ID        string   `json:"scheduled_transaction_id,omitempty" jsonschema:"which one to change; required for update and delete"`
	Account   string   `json:"account,omitempty" jsonschema:"account name or id; required when creating"`
	Amount    *float64 `json:"amount,omitempty" jsonschema:"amount in the budget's currency; NEGATIVE for spending"`
	Date      string   `json:"date,omitempty" jsonschema:"the next date it is due, YYYY-MM-DD; required when creating"`
	Frequency string   `json:"frequency,omitempty" jsonschema:"never, daily, weekly, everyOtherWeek, twiceAMonth, every4Weeks, monthly, everyOtherMonth, every3Months, every4Months, twiceAYear, yearly or everyOtherYear"`
	Payee     string   `json:"payee,omitempty" jsonschema:"payee name or id"`
	Category  string   `json:"category,omitempty" jsonschema:"category name or id"`
	Memo      string   `json:"memo,omitempty"`
	FlagColor string   `json:"flag_color,omitempty" jsonschema:"red, orange, yellow, green, blue or purple"`
	Confirm   bool     `json:"confirm,omitempty" jsonschema:"required for delete; deleting cannot be undone"`
}

func (s *Server) manageScheduledTransaction(ctx context.Context, _ *mcp.CallToolRequest, in manageScheduledInput) (*mcp.CallToolResult, any, error) {
	p := plan(in.BudgetID)
	cf := s.currency(ctx, p)

	if in.Action == "delete" {
		switch {
		case in.ID == "":
			return fail(fmt.Errorf("scheduled_transaction_id is required to delete"))
		case !in.Confirm:
			return fail(fmt.Errorf("deleting a scheduled transaction cannot be undone. Check with the person whose budget this is, then call again with confirm:true"))
		}
		t, err := s.api.DeleteScheduledTransaction(ctx, p, in.ID)
		if err != nil {
			return fail(err)
		}
		return text("Deleted the schedule for " + describeScheduled(t, cf)), nil, nil
	}

	save, err := s.buildScheduled(ctx, p, in)
	if err != nil {
		return fail(err)
	}
	switch in.Action {
	case "create":
		t, err := s.api.CreateScheduledTransaction(ctx, p, save)
		if err != nil {
			return fail(err)
		}
		return text("Scheduled " + describeScheduled(t, cf)), nil, nil
	case "update":
		if in.ID == "" {
			return fail(fmt.Errorf("scheduled_transaction_id is required to update"))
		}
		t, err := s.api.UpdateScheduledTransaction(ctx, p, in.ID, save)
		if err != nil {
			return fail(err)
		}
		return text("Updated, now " + describeScheduled(t, cf)), nil, nil
	default:
		return fail(fmt.Errorf("action must be 'create', 'update' or 'delete', got %q", in.Action))
	}
}

// buildScheduled fills the body YNAB wants. Account and date are required by
// the schema even on an update, so an update that means to leave them alone
// still has to restate them; the error says so rather than letting YNAB return
// a bare validation failure.
func (s *Server) buildScheduled(ctx context.Context, p string, in manageScheduledInput) (ynab.SaveScheduledTransaction, error) {
	var save ynab.SaveScheduledTransaction
	if in.Account == "" || in.Date == "" {
		return save, fmt.Errorf("account and date are both required, on an update as well as a create: YNAB replaces the whole schedule rather than patching it")
	}
	account, err := s.api.ResolveAccount(ctx, p, in.Account)
	if err != nil {
		return save, err
	}
	date, err := parseDate(in.Date, s.now())
	if err != nil {
		return save, err
	}
	save.AccountId = uuidOf(account.ID)
	save.Date = apiDate(date)
	if in.Amount != nil {
		save.Amount = ptr(toMilli(*in.Amount))
	}
	if in.Frequency != "" {
		save.Frequency = ptr(ynab.ScheduledTransactionFrequency(in.Frequency))
	}
	if in.Memo != "" {
		save.Memo = ptr(in.Memo)
	}
	if in.FlagColor != "" {
		save.FlagColor = ptr(ynab.TransactionFlagColor(in.FlagColor))
	}
	if in.Category != "" {
		ref, err := s.api.ResolveCategory(ctx, p, in.Category)
		if err != nil {
			return save, err
		}
		save.CategoryId = ptr(uuidOf(ref.ID))
	}
	if in.Payee != "" {
		if ref, err := s.api.ResolvePayee(ctx, p, in.Payee); err == nil {
			save.PayeeId = ptr(uuidOf(ref.ID))
		} else {
			save.PayeeName = ptr(in.Payee)
		}
	}
	return save, nil
}

func describeScheduled(t *ynab.ScheduledTransactionDetail, cf *ynab.CurrencyFormat) string {
	return fmt.Sprintf("%s %s from %s, %s, next on %s [%s]",
		money(t.AmountFormatted, t.Amount, cf), orDash(str(t.PayeeName)), t.AccountName,
		string(t.Frequency), isoDate(t.DateNext), ynab.ShortID(t.Id.String()))
}

// --- manage_category ---

type manageCategoryInput struct {
	BudgetID       string   `json:"budget_id,omitempty" jsonschema:"budget to use; defaults to the most recently used one"`
	Action         string   `json:"action" jsonschema:"'create_category', 'update_category', 'create_group' or 'update_group'"`
	Category       string   `json:"category,omitempty" jsonschema:"the category to change, by name or id; required for update_category"`
	Group          string   `json:"group,omitempty" jsonschema:"the category group, by name or id; required for create_category and for group actions"`
	Name           string   `json:"name,omitempty" jsonschema:"the new name"`
	Note           string   `json:"note,omitempty"`
	Target         *float64 `json:"target,omitempty" jsonschema:"the target amount for this category, in the budget's currency; pass 0 to clear it"`
	TargetDate     string   `json:"target_date,omitempty" jsonschema:"the date to reach the target by, YYYY-MM-DD"`
	TargetCadence  string   `json:"target_cadence,omitempty" jsonschema:"'monthly', 'weekly' or 'yearly'"`
	WholeAmountDue bool     `json:"needs_whole_amount,omitempty" jsonschema:"the full target is needed each period rather than the shortfall"`
}

func (s *Server) manageCategory(ctx context.Context, _ *mcp.CallToolRequest, in manageCategoryInput) (*mcp.CallToolResult, any, error) {
	p := plan(in.BudgetID)
	switch in.Action {
	case "create_group":
		if in.Name == "" {
			return fail(fmt.Errorf("name is required to create a group"))
		}
		g, err := s.api.CreateCategoryGroup(ctx, p, in.Name)
		if err != nil {
			return fail(err)
		}
		return text(fmt.Sprintf("Created the category group %q [%s].", g.Name, ynab.ShortID(g.Id.String()))), nil, nil

	case "update_group":
		if in.Group == "" || in.Name == "" {
			return fail(fmt.Errorf("group and name are both required to rename a group"))
		}
		ref, err := s.api.ResolveCategoryGroup(ctx, p, in.Group)
		if err != nil {
			return fail(err)
		}
		g, err := s.api.UpdateCategoryGroup(ctx, p, ref.ID, in.Name)
		if err != nil {
			return fail(err)
		}
		return text(fmt.Sprintf("Renamed the group %q to %q.", ref.Name, g.Name)), nil, nil

	case "create_category":
		if in.Group == "" || in.Name == "" {
			return fail(fmt.Errorf("group and name are both required to create a category"))
		}
		group, err := s.api.ResolveCategoryGroup(ctx, p, in.Group)
		if err != nil {
			return fail(err)
		}
		nc := ynab.NewCategory{CategoryGroupId: uuidOf(group.ID), Name: ptr(in.Name)}
		if in.Note != "" {
			nc.Note = ptr(in.Note)
		}
		if err := s.applyGoal(&nc.GoalTarget, &nc.GoalTargetDate, &nc.GoalNeedsWholeAmount, in); err != nil {
			return fail(err)
		}
		if in.TargetCadence != "" {
			nc.GoalFrequency = ptr(ynab.NewCategoryGoalFrequency(in.TargetCadence))
		}
		c, err := s.api.CreateCategory(ctx, p, nc)
		if err != nil {
			return fail(err)
		}
		return text(fmt.Sprintf("Created %q in %q [%s].", c.Name, group.Name, ynab.ShortID(c.Id.String()))), nil, nil

	case "update_category":
		if in.Category == "" {
			return fail(fmt.Errorf("category is required to update a category"))
		}
		ref, err := s.api.ResolveCategory(ctx, p, in.Category)
		if err != nil {
			return fail(err)
		}
		var ec ynab.ExistingCategory
		var changed []string
		if in.Name != "" {
			ec.Name = ptr(in.Name)
			changed = append(changed, "name → "+in.Name)
		}
		if in.Note != "" {
			ec.Note = ptr(in.Note)
			changed = append(changed, "note")
		}
		if in.Group != "" {
			group, err := s.api.ResolveCategoryGroup(ctx, p, in.Group)
			if err != nil {
				return fail(err)
			}
			ec.CategoryGroupId = ptr(uuidOf(group.ID))
			changed = append(changed, "moved to "+group.Name)
		}
		if err := s.applyGoal(&ec.GoalTarget, &ec.GoalTargetDate, &ec.GoalNeedsWholeAmount, in); err != nil {
			return fail(err)
		}
		if in.Target != nil {
			changed = append(changed, fmt.Sprintf("target → %.2f", *in.Target))
		}
		if in.TargetCadence != "" {
			ec.GoalFrequency = ptr(ynab.ExistingCategoryGoalFrequency(in.TargetCadence))
			changed = append(changed, "cadence → "+in.TargetCadence)
		}
		if len(changed) == 0 {
			return fail(fmt.Errorf("nothing to change; pass a name, note, group or target"))
		}
		c, err := s.api.UpdateCategory(ctx, p, ref.ID, ec)
		if err != nil {
			return fail(err)
		}
		return text(fmt.Sprintf("Updated %q: %s.", c.Name, strings.Join(changed, ", "))), nil, nil

	default:
		return fail(fmt.Errorf("action must be one of create_category, update_category, create_group, update_group; got %q", in.Action))
	}
}

// applyGoal fills the three goal fields the create and update bodies share.
// They are separate types with identical shapes, so the pointers are passed in
// rather than the struct.
func (s *Server) applyGoal(target **int64, date **openapiDate, whole **bool, in manageCategoryInput) error {
	if in.Target != nil {
		*target = ptr(toMilli(*in.Target))
	}
	if in.TargetDate != "" {
		d, err := parseDate(in.TargetDate, s.now())
		if err != nil {
			return err
		}
		*date = ptr(apiDate(d))
	}
	if in.WholeAmountDue {
		*whole = ptr(true)
	}
	return nil
}
