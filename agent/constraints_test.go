package agent

import (
	"strings"
	"testing"
)

func TestRuleConstraintRoundTripAndPromptGroup(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	expID, err := d.CreateExploration("constraint rule fixture", "rule roundtrip")
	if err != nil {
		t.Fatal(err)
	}
	ts := d.Exploration(expID)
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)

	if _, err := ts.AddConstraint("allow", "仅测 example.invalid", "human"); err != nil {
		t.Fatal(err)
	}
	if _, err := ts.AddConstraint("deny", "禁止爆破", "human"); err != nil {
		t.Fatal(err)
	}
	ruleID, err := ts.AddConstraint("rule", "每次请求至少间隔 2 秒", "human")
	if err != nil {
		t.Fatalf("persist rule: %v", err)
	}
	rows, err := ts.ListConstraints()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || rows[2].ID != ruleID || rows[2].Kind != "rule" || rows[2].Text != "每次请求至少间隔 2 秒" {
		t.Fatalf("constraint roundtrip/order mismatch: %#v", rows)
	}

	block := constraintBlock(ts)
	for _, expected := range []string{"允许的操作：", "禁止的操作：", "规则：", "- 每次请求至少间隔 2 秒"} {
		if !strings.Contains(block, expected) {
			t.Errorf("prompt block missing %q: %s", expected, block)
		}
	}

	if err := ts.UpdateConstraint(ruleID, "rule", "每次请求至少间隔 3 秒"); err != nil {
		t.Fatal(err)
	}
	rows, err = ts.ListConstraints()
	if err != nil {
		t.Fatal(err)
	}
	if rows[2].Kind != "rule" || rows[2].Text != "每次请求至少间隔 3 秒" {
		t.Fatalf("updated rule not preserved: %#v", rows[2])
	}
}
