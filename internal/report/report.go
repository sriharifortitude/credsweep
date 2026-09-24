// Package report renders a scan's results as terminal text, JSON, or
// SARIF 2.1.0 (for GitHub code scanning and similar). Nothing in this
// package ever sees the raw secret value -- scan.Finding already carries
// only a redacted form and a fingerprint.
package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/sriharifortitude/credsweep/internal/allowlist"
	"github.com/sriharifortitude/credsweep/internal/detect"
	"github.com/sriharifortitude/credsweep/internal/scan"
)

// Row is one finding plus whatever the allowlist did to it.
type Row struct {
	scan.Finding
	Allowed     bool
	AllowReason string
}

// Result is a whole scan: every row, most severe first, in a stable
// order (by path and line within a severity) so a re-run over the same
// history produces a byte-identical report.
type Result struct {
	Rows []Row
}

func NewResult(rows []Row) Result {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Severity != b.Severity {
			return severityRank(a.Severity) > severityRank(b.Severity)
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Line < b.Line
	})
	return Result{Rows: rows}
}

func severityRank(s detect.Severity) int {
	switch s {
	case detect.Critical:
		return 2
	case detect.High:
		return 1
	default:
		return 0
	}
}

// Counts summarises what happened: an allowed row is not a failure and
// is not silently dropped either -- it stays visible, marked as such.
type Counts struct {
	Findings int `json:"findings"`
	Allowed  int `json:"allowed"`
}

func (r Result) Counts() Counts {
	var c Counts
	for _, row := range r.Rows {
		if row.Allowed {
			c.Allowed++
		} else {
			c.Findings++
		}
	}
	return c
}

// Failing returns the rows that count against --fail-on: everything not
// allowed, at or above the threshold severity.
func (r Result) Failing(threshold detect.Severity) []Row {
	var out []Row
	for _, row := range r.Rows {
		if row.Allowed {
			continue
		}
		if !row.Severity.AtLeast(threshold) {
			continue
		}
		out = append(out, row)
	}
	return out
}

func Terminal(r Result) string {
	var b strings.Builder
	for _, row := range r.Rows {
		label := "FOUND"
		if row.Allowed {
			label = "allowed"
		}
		fmt.Fprintf(&b, "%-9s %-8s %-28s %s:%d\n", label, row.Severity, row.RuleID, row.Path, row.Line)
		fmt.Fprintf(&b, "          commit %s  %s  %s\n", shortSHA(row.Commit), row.Date, row.Author)
		fmt.Fprintf(&b, "          %s\n", row.Redacted)
		if row.Allowed {
			fmt.Fprintf(&b, "          allowed: %s\n", row.AllowReason)
		} else {
			fmt.Fprintf(&b, "          fingerprint: %s (allowlist this exact value with it)\n", row.Fingerprint)
		}
	}
	c := r.Counts()
	fmt.Fprintf(&b, "\n%d findings: %d flagged, %d allowed\n", len(r.Rows), c.Findings, c.Allowed)
	return b.String()
}

func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

type jsonRow struct {
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
	Path        string `json:"path"`
	Line        int    `json:"line"`
	Commit      string `json:"commit"`
	Author      string `json:"author"`
	Date        string `json:"date"`
	Redacted    string `json:"redacted"`
	Fingerprint string `json:"fingerprint"`
	Allowed     bool   `json:"allowed"`
	AllowReason string `json:"allow_reason,omitempty"`
}

func JSON(r Result) ([]byte, error) {
	rows := make([]jsonRow, 0, len(r.Rows))
	for _, row := range r.Rows {
		rows = append(rows, jsonRow{
			Rule: row.RuleID, Severity: string(row.Severity), Path: row.Path, Line: row.Line,
			Commit: row.Commit, Author: row.Author, Date: row.Date,
			Redacted: row.Redacted, Fingerprint: row.Fingerprint,
			Allowed: row.Allowed, AllowReason: row.AllowReason,
		})
	}
	out := struct {
		Summary Counts    `json:"summary"`
		Rows    []jsonRow `json:"findings"`
	}{r.Counts(), rows}
	return json.MarshalIndent(out, "", "  ")
}

// Apply checks a finding against the allowlist and builds its Row. A nil
// *allowlist.File (no --allowlist flag given) allows nothing.
func Apply(f *allowlist.File, finding scan.Finding) Row {
	ok, entry := f.Allows(finding.Fingerprint)
	row := Row{Finding: finding, Allowed: ok}
	if entry != nil {
		row.AllowReason = entry.Reason
	}
	return row
}
