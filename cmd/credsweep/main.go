// Command credsweep scans a git repository's full commit history for
// leaked credentials -- not just the files on disk today, but every line
// any commit ever added, so a secret that was committed and later
// removed still gets caught.
//
//	credsweep scan .
package main

import (
	"fmt"
	"os"

	"github.com/sriharifortitude/credsweep/internal/allowlist"
	"github.com/sriharifortitude/credsweep/internal/detect"
	"github.com/sriharifortitude/credsweep/internal/report"
	"github.com/sriharifortitude/credsweep/internal/scan"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 || args[0] != "scan" {
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	fs := newFlagSet()
	if err := fs.Parse(args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if fs.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "scan: expected at most one repository path")
		return 2
	}
	repoDir := "."
	if fs.NArg() == 1 {
		repoDir = fs.Arg(0)
	}

	var al *allowlist.File
	if fs.allowlist != "" {
		data, err := os.ReadFile(fs.allowlist)
		if err != nil {
			fmt.Fprintf(os.Stderr, "reading %s: %s\n", fs.allowlist, err)
			return 2
		}
		al, err = allowlist.Parse(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s\n", fs.allowlist, err)
			return 2
		}
	}

	threshold, err := parseSeverity(fs.failOn)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	findings, err := scan.Run(repoDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scanning %s: %s\n", repoDir, err)
		return 2
	}

	rows := make([]report.Row, 0, len(findings))
	for _, f := range findings {
		rows = append(rows, report.Apply(al, f))
	}
	result := report.NewResult(rows)

	out, err := render(result, fs.format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rendering %s report: %s\n", fs.format, err)
		return 2
	}
	if err := write(out, fs.output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if fs.output != "" && fs.format != "terminal" {
		fmt.Print(report.Terminal(result))
	}

	if len(result.Failing(threshold)) > 0 {
		return 1
	}
	return 0
}

func render(r report.Result, format string) (string, error) {
	switch format {
	case "terminal", "":
		return report.Terminal(r), nil
	case "json":
		b, err := report.JSON(r)
		return string(b) + "\n", err
	case "sarif":
		b, err := report.SARIF(r)
		return string(b) + "\n", err
	default:
		return "", fmt.Errorf("unknown format %q: expected terminal, json or sarif", format)
	}
}

func write(text, path string) error {
	if path == "" {
		fmt.Print(text)
		return nil
	}
	return os.WriteFile(path, []byte(text), 0o644)
}

func parseSeverity(s string) (detect.Severity, error) {
	switch s {
	case "medium", "":
		return detect.Medium, nil
	case "high":
		return detect.High, nil
	case "critical":
		return detect.Critical, nil
	default:
		return "", fmt.Errorf("--fail-on: expected medium, high or critical, got %q", s)
	}
}

const usage = `usage: credsweep scan [--format terminal|json|sarif] [--output FILE] [--fail-on medium|high|critical] [--allowlist FILE] [REPO_DIR]`
