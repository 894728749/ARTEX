package db

import (
	"encoding/json"
	"testing"
)

func intPointer(v int) *int { return &v }

func TestNativeReplayPlanValidation(t *testing.T) {
	tests := []struct {
		name    string
		plan    NativeReplayPlan
		wantErr bool
	}{
		{"valid exit", NativeReplayPlan{Version: 1, InputMode: "stdin", Assertion: &NativeReplayAssertion{Type: "exit_code", Value: intPointer(0)}}, false},
		{"valid signal upper bound", NativeReplayPlan{Version: 1, InputMode: "stdin", Assertion: &NativeReplayAssertion{Type: "signal", Value: intPointer(64)}}, false},
		{"omitted input mode normalizes", NativeReplayPlan{Version: 1, Assertion: &NativeReplayAssertion{Type: "exit_code", Value: intPointer(125)}}, false},
		{"missing version", NativeReplayPlan{Assertion: &NativeReplayAssertion{Type: "exit_code", Value: intPointer(0)}}, true},
		{"unsupported version", NativeReplayPlan{Version: 2, Assertion: &NativeReplayAssertion{Type: "exit_code", Value: intPointer(0)}}, true},
		{"unknown input mode", NativeReplayPlan{Version: 1, InputMode: "file", Assertion: &NativeReplayAssertion{Type: "exit_code", Value: intPointer(0)}}, true},
		{"unknown assertion type", NativeReplayPlan{Version: 1, Assertion: &NativeReplayAssertion{Type: "stdout", Value: intPointer(0)}}, true},
		{"exit below range", NativeReplayPlan{Version: 1, Assertion: &NativeReplayAssertion{Type: "exit_code", Value: intPointer(-1)}}, true},
		{"exit above range", NativeReplayPlan{Version: 1, Assertion: &NativeReplayAssertion{Type: "exit_code", Value: intPointer(126)}}, true},
		{"signal below range", NativeReplayPlan{Version: 1, Assertion: &NativeReplayAssertion{Type: "signal", Value: intPointer(0)}}, true},
		{"signal above range", NativeReplayPlan{Version: 1, Assertion: &NativeReplayAssertion{Type: "signal", Value: intPointer(65)}}, true},
		{"missing value", NativeReplayPlan{Version: 1, Assertion: &NativeReplayAssertion{Type: "exit_code"}}, true},
		{"no assertion allowed only as secondary expectation", NativeReplayPlan{Version: 1}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.plan.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.name == "omitted input mode normalizes" && tt.plan.InputMode != "stdin" {
				t.Fatalf("omitted input mode normalized to %q", tt.plan.InputMode)
			}
		})
	}
}

func TestNativeReplayPlanStrictJSON(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{"unknown plan field", `{"version":1,"input_mode":"stdin","assertion":{"type":"exit_code","value":0},"stdout_contains":"ok"}`},
		{"unknown assertion field", `{"version":1,"input_mode":"stdin","assertion":{"type":"exit_code","value":0,"stderr":"bad"}}`},
		{"version wrong type", `{"version":"1","input_mode":"stdin"}`},
		{"input mode wrong type", `{"version":1,"input_mode":false}`},
		{"assertion wrong type", `{"version":1,"assertion":"exit_code"}`},
		{"assertion value wrong type", `{"version":1,"assertion":{"type":"exit_code","value":"0"}}`},
		{"malformed JSON", `{"version":1`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var plan NativeReplayPlan
			if err := json.Unmarshal([]byte(tt.json), &plan); err == nil {
				t.Fatalf("json.Unmarshal(%s) unexpectedly succeeded", tt.json)
			}
		})
	}
}

func TestValidateNativeCaseReplayPlanAssertions(t *testing.T) {
	zero := 0
	plan := &NativeReplayPlan{Version: 1, InputMode: "stdin", Assertion: &NativeReplayAssertion{Type: "exit_code", Value: &zero}}
	tests := []struct {
		name    string
		c       NativeCase
		wantErr bool
	}{
		{"plan assertion only", NativeCase{ArtifactID: 7, ProfileID: "lab", Title: "plan", ReplayPlan: plan}, false},
		{"top-level plus plan assertion", NativeCase{ArtifactID: 7, ProfileID: "lab", Title: "two", ExpectedExit: &zero, ReplayPlan: plan}, true},
		{"no expectation", NativeCase{ArtifactID: 7, ProfileID: "lab", Title: "none", ReplayPlan: &NativeReplayPlan{Version: 1, InputMode: "stdin"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNativeCase(&tt.c)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateNativeCase() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNativeCaseHashLegacyCompatibilityAndPlanStability(t *testing.T) {
	legacy := NativeCase{ArtifactID: 7, ProfileID: "lab", Title: "legacy", InputBase64: "", ExpectedExit: intPointer(0)}
	if err := ValidateNativeCase(&legacy); err != nil {
		t.Fatal(err)
	}
	const oldHash = "0cab0b0746ee791c77f4bc551f83b63fd70f75c951dd2e043db2d16760ec65a1"
	if legacy.SHA256 != oldHash {
		t.Fatalf("legacy hash changed: got %s, want %s", legacy.SHA256, oldHash)
	}

	planCase := NativeCase{ArtifactID: 7, ProfileID: "lab", Title: "planned", InputBase64: "", ReplayPlan: &NativeReplayPlan{Version: 1, Assertion: &NativeReplayAssertion{Type: "exit_code", Value: intPointer(0)}}}
	if err := ValidateNativeCase(&planCase); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(planCase)
	if err != nil {
		t.Fatal(err)
	}
	var roundTripped NativeCase
	if err := json.Unmarshal(encoded, &roundTripped); err != nil {
		t.Fatal(err)
	}
	if err := ValidateNativeCase(&roundTripped); err != nil {
		t.Fatal(err)
	}
	if roundTripped.ReplayPlan.InputMode != "stdin" {
		t.Fatalf("round-tripped input_mode = %q, want stdin", roundTripped.ReplayPlan.InputMode)
	}
	if roundTripped.SHA256 != planCase.SHA256 {
		t.Fatalf("hash changed across JSON roundtrip: %s != %s", roundTripped.SHA256, planCase.SHA256)
	}

	changed := roundTripped
	changed.ReplayPlan = &NativeReplayPlan{Version: 1, InputMode: "stdin", Assertion: &NativeReplayAssertion{Type: "exit_code", Value: intPointer(1)}}
	if err := ValidateNativeCase(&changed); err != nil {
		t.Fatal(err)
	}
	if changed.SHA256 == roundTripped.SHA256 {
		t.Fatal("changing replay assertion did not change case hash")
	}
}

func TestNativeCaseReplayExpectations(t *testing.T) {
	legacyExit, legacySignal := 7, 11
	planExit, planSignal := 3, 9
	tests := []struct {
		name                 string
		c                    NativeCase
		wantExit, wantSignal *int
	}{
		{"legacy expectations", NativeCase{ExpectedExit: &legacyExit}, &legacyExit, nil},
		{"legacy signal", NativeCase{ExpectedSignal: &legacySignal}, nil, &legacySignal},
		{"plan exit", NativeCase{ReplayPlan: &NativeReplayPlan{Version: 1, Assertion: &NativeReplayAssertion{Type: "exit_code", Value: &planExit}}}, &planExit, nil},
		{"plan signal", NativeCase{ReplayPlan: &NativeReplayPlan{Version: 1, Assertion: &NativeReplayAssertion{Type: "signal", Value: &planSignal}}}, nil, &planSignal},
		{"plan without assertion uses legacy", NativeCase{ExpectedSignal: &legacySignal, ReplayPlan: &NativeReplayPlan{Version: 1}}, nil, &legacySignal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.c.ArtifactID, tt.c.ProfileID, tt.c.Title = 7, "lab", "expectation"
			if err := ValidateNativeCase(&tt.c); err != nil {
				t.Fatal(err)
			}
			exit, signal := tt.c.ReplayExpectations()
			if !sameIntPointer(exit, tt.wantExit) || !sameIntPointer(signal, tt.wantSignal) {
				t.Fatalf("ReplayExpectations() = (%v,%v), want (%v,%v)", exit, signal, tt.wantExit, tt.wantSignal)
			}
		})
	}
}

func sameIntPointer(a, b *int) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
