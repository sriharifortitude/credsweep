// Package detect holds the patterns credsweep matches against a single
// added line, and the machinery that runs them. It knows nothing about
// git, commits or files -- that separation is what makes every rule
// testable with a bare string.
package detect

import (
	"fmt"
	"regexp"
)

type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
)

var severityOrder = map[Severity]int{Medium: 0, High: 1, Critical: 2}

// AtLeast reports whether s is at or above threshold.
func (s Severity) AtLeast(threshold Severity) bool {
	return severityOrder[s] >= severityOrder[threshold]
}

// Match is one hit within a line. Value is the raw secret text -- it is
// kept in memory only for the caller to redact and fingerprint; nothing
// in this package writes it anywhere.
type Match struct {
	RuleID   string
	Severity Severity
	Value    string
}

// Rule recognises one kind of secret in one line of text.
type Rule interface {
	ID() string
	Severity() Severity
	Description() string
	Find(line string) []Match
}

var registry []Rule

func register(r Rule) {
	for _, existing := range registry {
		if existing.ID() == r.ID() {
			panic(fmt.Sprintf("rule ID %q registered twice", r.ID()))
		}
	}
	registry = append(registry, r)
}

// All returns every built-in rule, in registration order.
func All() []Rule {
	out := make([]Rule, len(registry))
	copy(out, registry)
	return out
}

// Scan runs every rule against one line and returns every match, in
// rule order. When a specific rule (an AWS key, a Slack token, ...) and
// the generic high-entropy fallback both match the exact same value, only
// the specific rule's finding is kept -- the generic rule exists to
// catch what nothing else recognises, not to duplicate a finding a more
// precise rule already made.
func Scan(line string) []Match {
	var specific, generic []Match
	for _, r := range All() {
		if r.ID() == genericSecretID {
			generic = append(generic, r.Find(line)...)
			continue
		}
		specific = append(specific, r.Find(line)...)
	}

	covered := make(map[string]bool, len(specific))
	for _, m := range specific {
		covered[m.Value] = true
	}

	out := specific
	for _, m := range generic {
		if !covered[m.Value] {
			out = append(out, m)
		}
	}
	return out
}

// regexRule matches a compiled pattern against a line. When the pattern
// has a capture group, the group's text is the secret value (used when a
// key name or surrounding quotes need to be matched but excluded from
// what gets reported and fingerprinted); otherwise the whole match is.
type regexRule struct {
	id       string
	severity Severity
	desc     string
	re       *regexp.Regexp
}

func (r regexRule) ID() string          { return r.id }
func (r regexRule) Severity() Severity  { return r.severity }
func (r regexRule) Description() string { return r.desc }

func (r regexRule) Find(line string) []Match {
	var out []Match
	if r.re.NumSubexp() > 0 {
		for _, sm := range r.re.FindAllStringSubmatch(line, -1) {
			if len(sm) > 1 && sm[1] != "" {
				out = append(out, Match{RuleID: r.id, Severity: r.severity, Value: sm[1]})
			}
		}
		return out
	}
	for _, m := range r.re.FindAllString(line, -1) {
		out = append(out, Match{RuleID: r.id, Severity: r.severity, Value: m})
	}
	return out
}
