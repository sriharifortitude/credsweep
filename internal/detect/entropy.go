package detect

import (
	"math"
	"regexp"
	"strings"
)

const genericSecretID = "generic-high-entropy-secret"

// genericSecretPattern looks for an assignment whose key name suggests a
// secret. The value is checked for entropy and against a placeholder
// list before being reported -- name alone is far too noisy on its own
// (every config file has a variable called "token").
// No leading \b: "_" is a word character, so "db_password" would
// otherwise never match right before "password".
var genericSecretPattern = regexp.MustCompile(
	`(?i)(?:secret|password|passwd|token|api[_-]?key|access[_-]?key|credential)\w*\s*[:=]\s*['"]?([^\s'"]{12,})['"]?`,
)

var placeholderValue = regexp.MustCompile(
	`(?i)^(changeme|change_me|placeholder|xxx+|todo|fixme|example|dummy|redacted|fake|sample|test|your[_-]?(api[_-]?)?key([_-]?here)?|\*+|<[^>]*>|\$\{[^}]*\}|\$\([^)]*\))$`,
)

// minEntropyBits is the Shannon entropy floor, in bits per character, a
// candidate value must clear to be reported. Base64/hex secrets of
// realistic length comfortably clear 4; English words and repeated
// characters do not.
const minEntropyBits = 3.5

// genericSecretRule is the fallback for secrets that don't match a known
// service's format: high-entropy values assigned to a suspiciously named
// variable.
type genericSecretRule struct{}

func (genericSecretRule) ID() string         { return genericSecretID }
func (genericSecretRule) Severity() Severity { return Medium }
func (genericSecretRule) Description() string {
	return "a high-entropy value assigned to a variable named like a secret"
}

func (genericSecretRule) Find(line string) []Match {
	var out []Match
	for _, sm := range genericSecretPattern.FindAllStringSubmatch(line, -1) {
		val := sm[1]
		if placeholderValue.MatchString(strings.TrimSpace(val)) {
			continue
		}
		if shannonEntropy(val) < minEntropyBits {
			continue
		}
		out = append(out, Match{RuleID: genericSecretID, Severity: Medium, Value: val})
	}
	return out
}

// shannonEntropy returns the Shannon entropy of s, in bits per
// character, treating each byte as a symbol.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var entropy float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}
