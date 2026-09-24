package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sriharifortitude/credsweep/internal/allowlist"
	"github.com/sriharifortitude/credsweep/internal/detect"
	"github.com/sriharifortitude/credsweep/internal/scan"
)

func sample() Result {
	rows := []Row{
		{Finding: scan.Finding{
			RuleID: "aws-access-key-id", Severity: detect.Critical, Path: "config.env", Line: 3,
			Commit: "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab1", Author: "Jane Doe", Date: "2026-01-01T00:00:00Z",
			Redacted: "AKI...MPL (20 chars)", Fingerprint: "f1",
		}},
		{Finding: scan.Finding{
			RuleID: "generic-high-entropy-secret", Severity: detect.Medium, Path: "app.py", Line: 12,
			Commit: "0000000000000000000000000000000000000f", Author: "Jane Doe", Date: "2026-01-02T00:00:00Z",
			Redacted: "[redacted, 10 chars]", Fingerprint: "f2",
		}, Allowed: true, AllowReason: "test fixture, JIRA-9"},
	}
	return NewResult(rows)
}

func TestNewResultSortsMostSevereFirst(t *testing.T) {
	r := sample()
	if r.Rows[0].RuleID != "aws-access-key-id" {
		t.Fatalf("first row = %q, want the CRITICAL finding first", r.Rows[0].RuleID)
	}
}

func TestCountsSeparatesFindingsFromAllowed(t *testing.T) {
	c := sample().Counts()
	if c.Findings != 1 || c.Allowed != 1 {
		t.Fatalf("got %+v, want Findings=1 Allowed=1", c)
	}
}

func TestFailingExcludesAllowedRows(t *testing.T) {
	failing := sample().Failing(detect.Medium)
	if len(failing) != 1 || failing[0].RuleID != "aws-access-key-id" {
		t.Fatalf("got %+v, want only the unallowed finding", failing)
	}
}

func TestFailingRespectsTheSeverityThreshold(t *testing.T) {
	// the one unallowed row is CRITICAL; asking for CRITICAL-only should
	// still return it, but nothing exists above CRITICAL to hide it behind
	failing := sample().Failing(detect.Critical)
	if len(failing) != 1 {
		t.Fatalf("got %d, want 1", len(failing))
	}
}

func TestTerminalShowsBothFoundAndAllowedRowsWithTheirReasonOrFingerprint(t *testing.T) {
	out := Terminal(sample())
	if !strings.Contains(out, "FOUND") {
		t.Errorf("missing FOUND label:\n%s", out)
	}
	if !strings.Contains(out, "allowed") {
		t.Errorf("missing allowed label:\n%s", out)
	}
	if !strings.Contains(out, "fingerprint: f1") {
		t.Errorf("missing fingerprint for the unallowed row:\n%s", out)
	}
	if !strings.Contains(out, "test fixture, JIRA-9") {
		t.Errorf("missing allow reason:\n%s", out)
	}
	if !strings.Contains(out, "2 findings: 1 flagged, 1 allowed") {
		t.Errorf("missing or wrong summary line:\n%s", out)
	}
}

func TestJSONRoundTripsTheSummaryAndEveryField(t *testing.T) {
	data, err := JSON(sample())
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Summary  Counts    `json:"summary"`
		Findings []jsonRow `json:"findings"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Summary.Findings != 1 || parsed.Summary.Allowed != 1 {
		t.Fatalf("summary = %+v, want Findings=1 Allowed=1", parsed.Summary)
	}
	if len(parsed.Findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(parsed.Findings))
	}
	if parsed.Findings[0].Fingerprint != "f1" || parsed.Findings[0].Allowed {
		t.Errorf("first finding = %+v, want fingerprint f1 and allowed=false", parsed.Findings[0])
	}
	if parsed.Findings[1].AllowReason != "test fixture, JIRA-9" {
		t.Errorf("second finding = %+v, want the allow reason", parsed.Findings[1])
	}
}

func TestSARIFDeclaresEveryRuleAndOmitsAllowedFindings(t *testing.T) {
	data, err := SARIF(sample())
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Runs) != 1 {
		t.Fatalf("got %d runs, want 1", len(parsed.Runs))
	}
	if len(parsed.Runs[0].Tool.Driver.Rules) != len(detect.All()) {
		t.Fatalf("declared %d rules, want all %d built-in rules", len(parsed.Runs[0].Tool.Driver.Rules), len(detect.All()))
	}
	if len(parsed.Runs[0].Results) != 1 {
		t.Fatalf("got %d results, want 1 (the allowed row must be omitted)", len(parsed.Runs[0].Results))
	}
	if parsed.Runs[0].Results[0].RuleID != "aws-access-key-id" || parsed.Runs[0].Results[0].Level != "error" {
		t.Errorf("got %+v, want aws-access-key-id at error level", parsed.Runs[0].Results[0])
	}
}

func TestApplyMatchesOnFingerprint(t *testing.T) {
	al := &allowlist.File{Allow: []allowlist.Entry{{
		Fingerprint: allowlist.Fingerprint("aws-access-key-id", "config.env", "AKIAIOSFODNN7EXAMPLE"),
		Reason:      "test fixture",
	}}}
	f := scan.Finding{RuleID: "aws-access-key-id", Path: "config.env",
		Fingerprint: allowlist.Fingerprint("aws-access-key-id", "config.env", "AKIAIOSFODNN7EXAMPLE")}
	row := Apply(al, f)
	if !row.Allowed || row.AllowReason != "test fixture" {
		t.Fatalf("got %+v, want Allowed=true with the reason", row)
	}

	other := scan.Finding{RuleID: "aws-access-key-id", Path: "config.env", Fingerprint: "does-not-match"}
	row = Apply(al, other)
	if row.Allowed {
		t.Fatalf("got %+v, want Allowed=false for a non-matching fingerprint", row)
	}
}

func TestApplyWithANilAllowlistAllowsNothing(t *testing.T) {
	f := scan.Finding{RuleID: "aws-access-key-id", Fingerprint: "anything"}
	row := Apply(nil, f)
	if row.Allowed {
		t.Fatalf("got %+v, want Allowed=false with no allowlist", row)
	}
}
