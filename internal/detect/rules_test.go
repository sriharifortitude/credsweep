package detect

import (
	"strings"
	"testing"
)

func TestRegistryHasNoDuplicateIDs(t *testing.T) {
	seen := map[string]bool{}
	all := All()
	if len(all) != 10 {
		t.Fatalf("got %d rules, want 10", len(all))
	}
	for _, r := range all {
		if seen[r.ID()] {
			t.Fatalf("duplicate rule ID %q", r.ID())
		}
		seen[r.ID()] = true
	}
}

func ids(matches []Match) []string {
	out := make([]string, len(matches))
	for i, m := range matches {
		out[i] = m.RuleID
	}
	return out
}

func hasID(matches []Match, id string) bool {
	for _, i := range ids(matches) {
		if i == id {
			return true
		}
	}
	return false
}

func TestScanCleanLinesFindNothing(t *testing.T) {
	clean := []string{
		"",
		"import os",
		"func main() {",
		"# this is a comment",
		`API_KEY = os.environ["API_KEY"]`,
		"password: changeme",
		"token: <your-token-here>",
		"secret: ${SECRET_FROM_VAULT}",
	}
	for _, line := range clean {
		if got := Scan(line); len(got) != 0 {
			t.Errorf("line %q: got %+v, want no matches", line, got)
		}
	}
}

func TestAWSAccessKeyID(t *testing.T) {
	got := Scan(`aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"`)
	if !hasID(got, "aws-access-key-id") {
		t.Fatalf("got %+v, want aws-access-key-id", got)
	}
}

func TestAWSSecretAccessKeyRequiresTheConventionalVariableName(t *testing.T) {
	found := Scan(`aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`)
	if !hasID(found, "aws-secret-access-key") {
		t.Fatalf("got %+v, want aws-secret-access-key", found)
	}
	notFound := Scan(`some_other_var = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`)
	if hasID(notFound, "aws-secret-access-key") {
		t.Fatalf("got %+v, want no aws-secret-access-key match without the variable name", notFound)
	}
}

func TestGitHubTokens(t *testing.T) {
	classic := Scan("GITHUB_TOKEN=ghp_" + strings.Repeat("a1B2c3D4", 5)[:36])
	if !hasID(classic, "github-pat") {
		t.Fatalf("got %+v, want github-pat", classic)
	}
	fineGrained := Scan("token: github_pat_" + strings.Repeat("Z9y8X7w6", 4))
	if !hasID(fineGrained, "github-fine-grained-pat") {
		t.Fatalf("got %+v, want github-fine-grained-pat", fineGrained)
	}
}

func TestSlackToken(t *testing.T) {
	got := Scan("SLACK_WEBHOOK_TOKEN=xoxb-notarealsegment-abcdefghijklmnop")
	if !hasID(got, "slack-token") {
		t.Fatalf("got %+v, want slack-token", got)
	}
}

func TestStripeLiveSecretKey(t *testing.T) {
	got := Scan(`stripe_key = "sk_live_` + strings.Repeat("a1B2c3D4", 4) + `"`)
	if !hasID(got, "stripe-live-secret-key") {
		t.Fatalf("got %+v, want stripe-live-secret-key", got)
	}
}

func TestGoogleAPIKey(t *testing.T) {
	got := Scan("MAPS_KEY=AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY")
	if !hasID(got, "google-api-key") {
		t.Fatalf("got %+v, want google-api-key", got)
	}
}

func TestPrivateKeyBlock(t *testing.T) {
	got := Scan("-----BEGIN RSA PRIVATE KEY-----")
	if !hasID(got, "private-key-block") {
		t.Fatalf("got %+v, want private-key-block", got)
	}
}

func TestJWT(t *testing.T) {
	got := Scan("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ_typical_signature_bytes")
	if !hasID(got, "jwt") {
		t.Fatalf("got %+v, want jwt", got)
	}
}

func TestGenericRuleDoesNotDuplicateASpecificRulesFinding(t *testing.T) {
	// aws_access_key_id also matches the generic rule's key-name pattern
	// ("access_key"); the specific aws-access-key-id rule should be the
	// only finding on this line, not two findings for one value.
	got := Scan(`aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"`)
	if len(got) != 1 {
		t.Fatalf("got %d matches, want 1 (no duplicate from the generic rule): %+v", len(got), got)
	}
	if got[0].RuleID != "aws-access-key-id" {
		t.Fatalf("got %+v, want the specific rule to win", got)
	}
}

func TestGenericHighEntropySecretRequiresBothANamedKeyAndEnoughEntropy(t *testing.T) {
	found := Scan(`db_password = "Tr0ub4dor&3zQmP9xVk2LwR"`)
	if !hasID(found, genericSecretID) {
		t.Fatalf("got %+v, want %s", found, genericSecretID)
	}
	// named like a secret, but the value is a placeholder
	placeholder := Scan(`db_password = "changeme"`)
	if hasID(placeholder, genericSecretID) {
		t.Fatalf("got %+v, want no match for a placeholder value", placeholder)
	}
	// named like a secret, but low-entropy (a real word)
	lowEntropy := Scan(`api_token_name = "aaaaaaaaaaaaaaaaaaaa"`)
	if hasID(lowEntropy, genericSecretID) {
		t.Fatalf("got %+v, want no match for a low-entropy value", lowEntropy)
	}
	// high-entropy value, but not assigned to anything secret-sounding
	unnamed := Scan(`greeting = "Tr0ub4dor&3zQmP9xVk2LwR"`)
	if hasID(unnamed, genericSecretID) {
		t.Fatalf("got %+v, want no match without a secret-sounding key", unnamed)
	}
}
