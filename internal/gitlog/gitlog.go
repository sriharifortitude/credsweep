// Package gitlog shells out to git to read a repository's full commit
// history as patches. It is a thin, deliberately dumb wrapper: all the
// parsing that can be done without git lives in gitdiff instead, so it
// can be tested with plain strings.
package gitlog

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// Commit is one commit's metadata plus the unified diff of everything it
// changed, relative to its first parent (or the empty tree, for a root
// commit).
type Commit struct {
	SHA    string
	Author string
	Date   string // RFC 3339, the commit's authored date
	Patch  string
}

// recordSep is a control character that cannot appear in a commit's
// author name or date, and is vanishingly unlikely to appear literally in
// diff content -- git log emits it as a plain byte in --format, not
// interpreted, so it is safe to split on.
const recordSep = "\x01"

// IsRepo reports whether dir is inside a git working tree.
func IsRepo(dir string) bool {
	cmd := exec.Command("git", "-C", dir, "rev-parse", "--is-inside-work-tree")
	out, err := cmd.Output()
	return err == nil && strings.TrimSpace(string(out)) == "true"
}

// History returns every commit reachable from any ref, each with the
// full-history diff it introduced. One git process reads the whole
// repository, rather than one process per commit, so scanning a large
// history stays a single fork.
func History(dir string) ([]Commit, error) {
	// %x01/%x00 are git's own pretty-format escapes for those bytes: the
	// argument itself must stay plain text (a literal NUL or SOH byte in
	// an argv entry breaks process creation on Windows), and git inserts
	// the real byte into its output for us to split on below.
	cmd := exec.Command("git", "-C", dir, "log", "--all", "--no-color", "--unified=0", "-p",
		"--format=%x01%H%x00%an%x00%aI")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git log: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	var commits []Commit
	for _, record := range strings.Split(string(out), recordSep) {
		if record == "" {
			continue
		}
		header, patch, _ := strings.Cut(record, "\n")
		parts := strings.SplitN(header, "\x00", 3)
		if len(parts) != 3 {
			continue
		}
		commits = append(commits, Commit{SHA: parts[0], Author: parts[1], Date: parts[2], Patch: patch})
	}
	return commits, nil
}
