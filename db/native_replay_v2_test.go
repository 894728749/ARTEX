package db

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestNativeCaseV1HashRemainsStable(t *testing.T) {
	exit := 0
	c := NativeCase{ArtifactID: 7, ProfileID: "lab", Title: "legacy", Argv: []string{"--check"}, InputBase64: "AQID", ExpectedExit: &exit}
	legacyIdentity := []any{c.ArtifactID, c.ProfileID, c.Argv, c.InputBase64, c.ExpectedExit, c.ExpectedSignal}
	raw, err := json.Marshal(legacyIdentity)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(raw)
	if err := ValidateNativeCase(&c); err != nil {
		t.Fatal(err)
	}
	if got := c.SHA256; got != hex.EncodeToString(want[:]) {
		t.Fatalf("legacy case hash changed: got %s want %s", got, hex.EncodeToString(want[:]))
	}
}

func TestNativeReplayPlanV2Validation(t *testing.T) {
	value := 0
	valid := func() NativeCase {
		return NativeCase{ArtifactID: 7, ProfileID: "lab", Title: "v2", InputBase64: "AQ==", ReplayPlan: &NativeReplayPlan{
			Version: 2, ArtifactSHA256: stringOf('a', 64), Image: "registry.example/native@sha256:" + stringOf('b', 64), PolicyRevision: 3,
			Assertion: &NativeReplayAssertion{Type: "exit_code", Value: &value},
		}}
	}
	tests := []struct {
		name   string
		change func(*NativeCase)
	}{
		{"missing specimen", func(c *NativeCase) { c.ReplayPlan.ArtifactSHA256 = "" }},
		{"invalid specimen", func(c *NativeCase) { c.ReplayPlan.ArtifactSHA256 = "not-a-hash" }},
		{"mutable image", func(c *NativeCase) { c.ReplayPlan.Image = "registry.example/native:latest" }},
		{"missing policy revision", func(c *NativeCase) { c.ReplayPlan.PolicyRevision = 0 }},
		{"duplicate target id", func(c *NativeCase) {
			c.ReplayPlan.Target = &NativeTarget{Dependencies: []NativeArtifactBinding{{ArtifactID: 8, SHA256: stringOf('c', 64), Name: "libx.so"}}, Loader: &NativeArtifactBinding{ArtifactID: 8, SHA256: stringOf('d', 64), Name: "ld.so"}}
		}},
		{"duplicate target name", func(c *NativeCase) {
			c.ReplayPlan.Target = &NativeTarget{Dependencies: []NativeArtifactBinding{{ArtifactID: 8, SHA256: stringOf('c', 64), Name: "same.so"}, {ArtifactID: 9, SHA256: stringOf('d', 64), Name: "same.so"}}}
		}},
		{"unsafe target path", func(c *NativeCase) {
			c.ReplayPlan.Target = &NativeTarget{Dependencies: []NativeArtifactBinding{{ArtifactID: 8, SHA256: stringOf('c', 64), Name: "../escape.so"}}}
		}},
		{"harness with file input", func(c *NativeCase) {
			c.ReplayPlan.InputMode = "file"
			c.Argv = []string{"{input}"}
			c.ReplayPlan.Target = &NativeTarget{Harness: &NativeArtifactBinding{ArtifactID: 8, SHA256: stringOf('c', 64), Name: "harness.py"}}
		}},
		{"harness stdout assertion", func(c *NativeCase) {
			c.ReplayPlan.Assertion = &NativeReplayAssertion{Type: "stdout_contains_base64", DataBase64: "QQ=="}
			c.ReplayPlan.Target = &NativeTarget{Harness: &NativeArtifactBinding{ArtifactID: 8, SHA256: stringOf('c', 64), Name: "harness.py"}}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := valid()
			tc.change(&c)
			if err := ValidateNativeCase(&c); err == nil {
				t.Fatal("invalid replay plan accepted")
			}
		})
	}
	c := valid()
	if err := ValidateNativeCase(&c); err != nil {
		t.Fatalf("valid v2 plan rejected: %v", err)
	}
}

func stringOf(ch byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = ch
	}
	return string(b)
}
