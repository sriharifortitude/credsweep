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

// callExpression matches an unquoted value that is code, not data: an
// identifier or dotted path followed by a parenthesised argument list,
// optionally trailed by the ?, ; or ! that end a statement. A real
// credential in source is a string literal or a bare base64/hex blob,
// never `tokenize(expr);`.
var callExpression = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*\(.*\)[?;!,]*$`)

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
	for _, loc := range genericSecretPattern.FindAllStringSubmatchIndex(line, -1) {
		start, end := loc[2], loc[3]
		val := line[start:end]
		if placeholderValue.MatchString(strings.TrimSpace(val)) {
			continue
		}
		quoted := start > 0 && (line[start-1] == '"' || line[start-1] == '\'')
		if !quoted && callExpression.MatchString(val) {
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
