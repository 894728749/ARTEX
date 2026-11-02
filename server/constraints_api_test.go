package server

import "testing"

func TestNormalizeConstraintKindSupportsRuleAndLegacyKinds(t *testing.T) {
	for _, kind := range []string{"allow", "deny", "rule"} {
		if got := normalizeConstraintKind("  " + kind + " "); got != kind {
			t.Errorf("normalizeConstraintKind(%q) = %q, want %q", kind, got, kind)
		}
	}
	if got := normalizeConstraintKind("other"); got != "" {
		t.Errorf("normalizeConstraintKind(other) = %q, want empty", got)
	}
}
