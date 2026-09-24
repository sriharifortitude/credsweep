// Package gitdiff parses unified diff text produced by `git show
// --unified=0 --no-color --format=`, extracting only the lines a commit
// added and the line number they landed on in the new file. It is a pure
// string-to-struct parser with no dependency on git itself, so it is
// exercised directly with fixture text rather than a real repository.
package gitdiff

import "strings"

// AddedLine is one line introduced by a commit, at its position in the
// file as it existed after the commit.
type AddedLine struct {
	Line int
	Text string
}

// FileDiff is every line one file gained in a single commit.
type FileDiff struct {
	Path  string
	Added []AddedLine
}

// Parse reads the concatenated per-file diffs of a single commit and
// returns one FileDiff per file that gained at least one line. Files that
// were only deleted, renamed without change, or are binary contribute no
// FileDiff.
func Parse(patch string) []FileDiff {
	var files []FileDiff
	var cur *FileDiff
	newLine := 0

	flush := func() {
		if cur != nil && len(cur.Added) > 0 {
			files = append(files, *cur)
		}
		cur = nil
	}

	for _, line := range strings.Split(patch, "\n") {
		switch {
		case strings.HasPrefix(line, "diff --git "):
			flush()
		case strings.HasPrefix(line, "Binary files "):
			cur = nil
		case strings.HasPrefix(line, "+++ "):
			path := strings.TrimPrefix(line, "+++ ")
			if path == "/dev/null" {
				cur = nil
				continue
			}
			path = strings.TrimPrefix(path, "b/")
			cur = &FileDiff{Path: path}
		case strings.HasPrefix(line, "@@ "):
			newLine = hunkNewStart(line)
		case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
			if cur != nil {
				cur.Added = append(cur.Added, AddedLine{Line: newLine, Text: line[1:]})
			}
			newLine++
		case strings.HasPrefix(line, " "):
			newLine++
		}
	}
	flush()
	return files
}

// hunkNewStart reads the "+newStart" field out of a hunk header such as
// "@@ -12,3 +14,5 @@ func foo() {". It defaults to 0 if the header cannot
// be parsed, which only happens on malformed input.
func hunkNewStart(header string) int {
	plus := strings.IndexByte(header, '+')
	if plus < 0 {
		return 0
	}
	rest := header[plus+1:]
	end := strings.IndexAny(rest, ", @")
	if end < 0 {
		end = len(rest)
	}
	n := 0
	for _, c := range rest[:end] {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
