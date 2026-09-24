package scan

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sriharifortitude/credsweep/internal/allowlist"
)

func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run(t, dir, "init", "-q", "-b", "main")
	run(t, dir, "config", "user.name", "credsweep tests")
	run(t, dir, "config", "user.email", "tests@example.invalid")
	run(t, dir, "config", "commit.gpgsign", "false")
	return dir
}

func run(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func commitAll(t *testing.T, dir, msg string) {
	t.Helper()
	run(t, dir, "add", "-A")
	run(t, dir, "commit", "-q", "-m", msg)
}

func TestRunFindsASecretEvenAfterItWasRemovedInALaterCommit(t *testing.T) {
	repo := initRepo(t)
	writeFile(t, repo, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
	commitAll(t, repo, "add config (oops)")

	writeFile(t, repo, "config.env", "AWS_KEY=REMOVED\n")
	commitAll(t, repo, "remove the key")

	findings, err := Run(repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (the secret is gone from HEAD but still lives in history)", len(findings))
	}
	f := findings[0]
	if f.RuleID != "aws-access-key-id" {
		t.Errorf("RuleID = %q, want aws-access-key-id", f.RuleID)
	}
	if f.Path != "config.env" || f.Line != 1 {
		t.Errorf("Path:Line = %s:%d, want config.env:1", f.Path, f.Line)
	}
}

func TestRunOnCleanHistoryFindsNothing(t *testing.T) {
	repo := initRepo(t)
	writeFile(t, repo, "README.md", "# a clean project\n\nnothing to see here.\n")
	commitAll(t, repo, "initial commit")

	findings, err := Run(repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %+v, want no findings", findings)
	}
}

func TestRunOnANonGitDirectoryReturnsAnError(t *testing.T) {
	if _, err := Run(t.TempDir()); err == nil {
		t.Fatal("Run on a non-git directory succeeded, want an error")
	}
}

func TestRunFingerprintMatchesTheAllowlistPackagesComputation(t *testing.T) {
	repo := initRepo(t)
	writeFile(t, repo, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
	commitAll(t, repo, "add config")

	findings, err := Run(repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	want := allowlist.Fingerprint("aws-access-key-id", "config.env", "AKIAIOSFODNN7EXAMPLE")
	if findings[0].Fingerprint != want {
		t.Errorf("Fingerprint = %q, want %q", findings[0].Fingerprint, want)
	}
}

func TestRunResultsAreSortedByPathThenLine(t *testing.T) {
	repo := initRepo(t)
	writeFile(t, repo, "z.env", "A=AKIAIOSFODNN7EXAMPLE\nB=AKIAIOSFODNN7SECONDX\n")
	writeFile(t, repo, "a.env", "C=AKIAIOSFODNN7THIRDXX\n")
	commitAll(t, repo, "add two files")

	findings, err := Run(repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3", len(findings))
	}
	if findings[0].Path != "a.env" {
		t.Errorf("first result Path = %q, want a.env (sorted first)", findings[0].Path)
	}
	if findings[1].Path != "z.env" || findings[1].Line != 1 {
		t.Errorf("second result = %s:%d, want z.env:1", findings[1].Path, findings[1].Line)
	}
	if findings[2].Path != "z.env" || findings[2].Line != 2 {
		t.Errorf("third result = %s:%d, want z.env:2", findings[2].Path, findings[2].Line)
	}
}

func TestRedactMasksShortValuesCompletelyAndLongValuesMostly(t *testing.T) {
	short := redact("AKIAEXAMPLE") // 11 chars
	if strings.Contains(short, "AKIA") {
		t.Errorf("redact(short) = %q, leaks the value", short)
	}
	long := redact("AKIAIOSFODNN7EXAMPLE") // 20 chars
	if !strings.HasPrefix(long, "AKI") || !strings.HasSuffix(strings.SplitN(long, " ", 2)[0], "PLE") {
		t.Errorf("redact(long) = %q, want a 3-char prefix and suffix", long)
	}
	if strings.Contains(long, "IOSFODNN7EXAM") {
		t.Errorf("redact(long) = %q, leaks the middle of the value", long)
	}
}
