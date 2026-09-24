// Package scan wires gitlog, gitdiff and detect together: walk every
// commit reachable from any ref, look at only the lines it added, and
// run every detect rule over them.
package scan

import (
	"fmt"
	"sort"

	"github.com/sriharifortitude/credsweep/internal/allowlist"
	"github.com/sriharifortitude/credsweep/internal/detect"
	"github.com/sriharifortitude/credsweep/internal/gitdiff"
	"github.com/sriharifortitude/credsweep/internal/gitlog"
)

// Finding is one match, with enough about where and when it was
// introduced to act on, and never the raw secret value -- Redacted and
// Fingerprint are derived from it once here and the value itself is
// discarded.
type Finding struct {
	RuleID      string
	Severity    detect.Severity
	Path        string
	Line        int
	Commit      string
	Author      string
	Date        string
	Redacted    string
	Fingerprint string
}

// Run scans every commit reachable from any ref in the repository at
// dir and returns every match, sorted by file, then line, then commit,
// so output is stable across runs of the same history.
func Run(dir string) ([]Finding, error) {
	if !gitlog.IsRepo(dir) {
		return nil, fmt.Errorf("%s is not a git repository", dir)
	}
	commits, err := gitlog.History(dir)
	if err != nil {
		return nil, err
	}

	var findings []Finding
	for _, c := range commits {
		for _, fd := range gitdiff.Parse(c.Patch) {
			for _, line := range fd.Added {
				for _, m := range detect.Scan(line.Text) {
					findings = append(findings, Finding{
						RuleID:      m.RuleID,
						Severity:    m.Severity,
						Path:        fd.Path,
						Line:        line.Line,
						Commit:      c.SHA,
						Author:      c.Author,
						Date:        c.Date,
						Redacted:    redact(m.Value),
						Fingerprint: allowlist.Fingerprint(m.RuleID, fd.Path, m.Value),
					})
				}
			}
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Commit != b.Commit {
			return a.Commit < b.Commit
		}
		return a.RuleID < b.RuleID
	})
	return findings, nil
}

// redact keeps a finding identifiable without ever letting the output
// reconstruct the secret: short values are fully masked, and longer ones
// show at most three characters at each end -- always a minority of the
// value, regardless of length.
func redact(value string) string {
	n := len(value)
	if n <= 12 {
		return fmt.Sprintf("[redacted, %d chars]", n)
	}
	return fmt.Sprintf("%s...%s (%d chars)", value[:3], value[n-3:], n)
}
