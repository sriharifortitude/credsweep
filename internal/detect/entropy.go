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
//
// The closing parenthesis is not required: the value is cut at the first
// space, so `Split(piece.Trim()).Where(t => t.Length > 0)` reaches this rule
// as `Split(piece.Trim()).Where(t`. An unquoted value that opens with
// `identifier(` is code either way.
//
// A list or tuple that opens with a call is code too:
// `tokens=[base64.b64encode(...)]` in Python, found in rulefire.
var callExpression = regexp.MustCompile(`^[\[(]?[A-Za-z_][A-Za-z0-9_.]*\(`)

// referenceExpression matches an unquoted value that names where a value
// comes from rather than being one: an identifier followed by at least one
// .field or [index] (`var.db_password`, `ephemeral.random_password.db.result`,
// `local.secrets[0]`), optionally wrapped in a list's brackets. It needs a
// dot or bracket after the first identifier, which base64 and hex secrets
// never have; JWTs, which do have dots, are caught by their own rule first.
// An index holds a number or a key, never base64's `+`, `/` or `=`. Up to
// v0.1.4 any index was accepted, so base64 written as an identifier followed
// by a bracketed blob went unreported; rules_test.go has the case.
var referenceExpression = regexp.MustCompile(`^\[?[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*|\[[A-Za-z0-9_"'-]*\])+\]?[;,]*$`)

// typeExpression matches an unquoted value that is a type annotation: a
// capitalised generic such as `Option<String>,` or `Vec<Option<Token>>;`
// (a struct field, a TypeScript interface member, a Java field). It needs a
// capital first letter and only type-ish characters inside the angle
// brackets, so a literal secret that happens to contain `<` and `>` (and
// would normally be quoted) is not caught by it.
var typeExpression = regexp.MustCompile(`^[&*]?[A-Z][A-Za-z0-9_:]*<[A-Za-z0-9_:,&*<>\[\]']+>[?,;]*$`)

// subscriptedType matches a Python type annotation, `list[Token])` or
// `dict[str,` (the value is cut at the first space), found in rulefire. Only
// identifiers may sit inside the brackets, so base64 with `+`, `/` or `=` in
// it is still reported. A secret made only of letters and digits and written
// unquoted as `name[secret]` would be skipped; nothing seen so far looks so.
var subscriptedType = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*\[[A-Za-z_][A-Za-z0-9_.]*([,|\[\]]+[A-Za-z_][A-Za-z0-9_.]*)*[,\]]*[)\],:;=]*$`)

// filePath matches an unquoted absolute path: two or more segments of
// word characters, dots and dashes. A path is reported only if most of its
// segments contain a capital letter, which random base64 that happens to
// contain slashes almost always does and file paths almost never do. Found
// by scanning sudoers files, where `NOPASSWD: /home/monitor/bin/check_disk`
// reached this rule as a "password" with a path for its value.
var filePath = regexp.MustCompile(`^(/[A-Za-z0-9._-]+){2,}/?[,;]*$`)

func looksLikeFilePath(val string) bool {
	if !filePath.MatchString(val) {
		return false
	}
	segments := strings.Split(strings.Trim(val, "/,;"), "/")
	capitalised := 0
	for _, s := range segments {
		if strings.ToLower(s) != s {
			capitalised++
		}
	}
	return capitalised*2 < len(segments)
}

// sudoersTag reports the NOPASSWD: and PASSWD: tags of a sudoers rule, which
// contain "passwd" and a colon but assign nothing.
func sudoersTag(line string, keyStart int) bool {
	for _, tag := range []string{"NOPASSWD:", "PASSWD:"} {
		for _, at := range []int{keyStart, keyStart - 2} {
			if at >= 0 && strings.HasPrefix(line[at:], tag) {
				return true
			}
		}
	}
	return false
}

// interpolation is a ${...} template expression (Terraform, shell, JS).
var interpolation = regexp.MustCompile(`\$\{[^}]*\}`)

// codeNotData reports an unquoted value that is an expression, not a literal.
func codeNotData(val string) bool {
	return callExpression.MatchString(val) || referenceExpression.MatchString(val) || typeExpression.MatchString(val) ||
		subscriptedType.MatchString(val)
}

// secretComesFromInterpolation reports a templated value whose literal text,
// with every ${...} removed, holds no secret: either it's too short or
// plain to be one, or it's a URL whose password is entirely interpolated
// ("postgresql://${user}:${password}@${host}/db"). A URL with a literal
// password next to an interpolated host is still reported.
func secretComesFromInterpolation(val string) bool {
	if !interpolation.MatchString(val) {
		return false
	}
	literal := interpolation.ReplaceAllString(val, "")
	if scheme := strings.Index(literal, "://"); scheme >= 0 {
		rest := literal[scheme+3:]
		if at := strings.Index(rest, "@"); at >= 0 {
			if _, password, hasPassword := strings.Cut(rest[:at], ":"); !hasPassword || password == "" {
				return true
			}
		}
	}
	return len(literal) < 12 || shannonEntropy(literal) < minEntropyBits
}

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
		if !quoted && (codeNotData(val) || looksLikeFilePath(val)) {
			continue
		}
		if sudoersTag(line, loc[0]) {
			continue
		}
		if secretComesFromInterpolation(val) {
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
