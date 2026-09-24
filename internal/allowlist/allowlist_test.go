package allowlist

import "testing"

func TestFingerprintIsStableAndDependsOnAllThreeInputs(t *testing.T) {
	a := Fingerprint("aws-access-key-id", "config.env", "AKIAIOSFODNN7EXAMPLE")
	b := Fingerprint("aws-access-key-id", "config.env", "AKIAIOSFODNN7EXAMPLE")
	if a != b {
		t.Fatalf("same inputs produced different fingerprints: %q vs %q", a, b)
	}
	if len(a) != 64 {
		t.Fatalf("fingerprint length = %d, want 64 (hex sha256)", len(a))
	}

	differentRule := Fingerprint("other-rule", "config.env", "AKIAIOSFODNN7EXAMPLE")
	differentPath := Fingerprint("aws-access-key-id", "other.env", "AKIAIOSFODNN7EXAMPLE")
	differentValue := Fingerprint("aws-access-key-id", "config.env", "AKIAIOSFODNN7DIFFERENT")
	for name, other := range map[string]string{
		"rule":  differentRule,
		"path":  differentPath,
		"value": differentValue,
	} {
		if other == a {
			t.Errorf("changing the %s did not change the fingerprint", name)
		}
	}
}

func TestParseRequiresAFingerprintAndAReason(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"missing reason", `allow:
  - fingerprint: "` + fakeFingerprint + `"
`},
		{"missing fingerprint", `allow:
  - reason: "test fixture, not a real key"
`},
		{"fingerprint too short", `allow:
  - fingerprint: "abc123"
    reason: "test fixture"
`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Parse([]byte(c.yaml)); err == nil {
				t.Fatalf("Parse(%q) succeeded, want an error", c.yaml)
			}
		})
	}
}

func TestParseAcceptsAWellFormedEntry(t *testing.T) {
	src := `allow:
  - fingerprint: "` + fakeFingerprint + `"
    reason: "test fixtures in testdata/, not real credentials"
`
	f, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Allow) != 1 {
		t.Fatalf("got %d entries, want 1", len(f.Allow))
	}
}

func TestAllowsMatchesOnlyAnExactFingerprint(t *testing.T) {
	f := &File{Allow: []Entry{{Fingerprint: fakeFingerprint, Reason: "test fixture"}}}

	ok, entry := f.Allows(fakeFingerprint)
	if !ok || entry == nil || entry.Reason != "test fixture" {
		t.Fatalf("Allows(matching) = %v, %v, want true with the entry", ok, entry)
	}

	ok, _ = f.Allows("0000000000000000000000000000000000000000000000000000000000000000"[:64])
	if ok {
		t.Fatalf("Allows(non-matching) = true, want false")
	}
}

func TestAllowsOnANilFileIsFalse(t *testing.T) {
	var f *File
	if ok, _ := f.Allows(fakeFingerprint); ok {
		t.Fatalf("Allows on a nil *File = true, want false")
	}
}

const fakeFingerprint = "a3f5c9d1e2b4a6f8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6"
