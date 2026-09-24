// Package allowlist lets a known false positive stop being reported,
// without ever asking the allowlist file itself to hold a secret value.
package allowlist

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"gopkg.in/yaml.v3"
)

// Entry accepts every future finding that fingerprints the same way: the
// same rule, on the same path, matching the same value. The value itself
// is never stored -- only its fingerprint, which credsweep prints
// alongside every finding for exactly this purpose.
type Entry struct {
	Fingerprint string `yaml:"fingerprint"`
	Reason      string `yaml:"reason"`
}

// File is the parsed contents of an allowlist YAML file.
type File struct {
	Allow []Entry `yaml:"allow"`
}

// Fingerprint identifies a specific secret value found by a specific
// rule in a specific file -- not a specific commit, so a false positive
// that was committed many times over a file's history is allowlisted
// once rather than once per commit.
func Fingerprint(ruleID, path, value string) string {
	h := sha256.Sum256([]byte(ruleID + "\x00" + path + "\x00" + value))
	return hex.EncodeToString(h[:])
}

// Parse reads an allowlist file. Every entry must carry a fingerprint
// (as printed by a credsweep finding) and a reason: an allowlist entry
// nobody can explain is indistinguishable from one nobody checked.
func Parse(data []byte) (*File, error) {
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing allowlist: %w", err)
	}
	for i, e := range f.Allow {
		if len(e.Fingerprint) != 64 {
			return nil, fmt.Errorf("allowlist entry %d: fingerprint must be the 64-character hex value credsweep prints with a finding, got %q", i, e.Fingerprint)
		}
		if e.Reason == "" {
			return nil, fmt.Errorf("allowlist entry %d: reason is required", i)
		}
	}
	return &f, nil
}

// Allows reports whether fingerprint is on the list, and the entry that
// matched.
func (f *File) Allows(fingerprint string) (bool, *Entry) {
	if f == nil {
		return false, nil
	}
	for i := range f.Allow {
		if f.Allow[i].Fingerprint == fingerprint {
			return true, &f.Allow[i]
		}
	}
	return false, nil
}
