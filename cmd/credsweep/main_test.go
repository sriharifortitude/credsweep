package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// demoRepo builds the same fixture testdata/build-demo-repo.sh produces
// the README's example output from, fresh in a temp dir for this test.
func demoRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script, err := filepath.Abs("../../testdata/build-demo-repo.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", script, dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the demo repo: %v\n%s", err, out)
	}
	return dir
}

// out runs the CLI in-process and returns the exit code plus whatever
// was written to --output. --output is inserted right after the
// subcommand: flag parsing stops at the first non-flag token, so it must
// come before the positional repo path.
func out(t *testing.T, args ...string) (code int, report string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "report.out")
	withOutput := append([]string{args[0], "--output", path}, args[1:]...)
	code = run(withOutput)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return code, ""
		}
		t.Fatalf("reading report: %s", err)
	}
	return code, string(data)
}

func TestScanTheDemoRepoWithoutAnAllowlist(t *testing.T) {
	repo := demoRepo(t)
	code, report := out(t, "scan", "--format", "json", repo)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (real secrets in history)", code)
	}
	for _, want := range []string{
		`"rule": "aws-access-key-id"`,
		`"rule": "slack-token"`,
		`"rule": "generic-high-entropy-secret"`,
		`"path": "config.env"`,
		`"path": "notifications/slack.py"`,
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report missing %s\n%s", want, report)
		}
	}
	if strings.Contains(report, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("the raw secret value leaked into the report; only the redacted form should appear")
	}
	if !strings.Contains(report, `"findings": 4`) {
		t.Errorf("report:\n%s", report)
	}
}

func TestScanTheDemoRepoWithTheAllowlist(t *testing.T) {
	repo := demoRepo(t)
	code, report := out(t, "scan", "--format", "json", "--allowlist", "../../testdata/demo-allowlist.yaml", repo)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (three real findings remain even with the allowlist)", code)
	}
	if !strings.Contains(report, `"findings": 3`) || !strings.Contains(report, `"allowed": 1`) {
		t.Errorf("report:\n%s", report)
	}
	if !strings.Contains(report, "the generic entropy rule can't tell the two apart") {
		t.Error("the allowlist's reason should appear in the report")
	}
}

func TestScanWithACriticalOnlyThresholdStillFailsOnTheAWSKey(t *testing.T) {
	repo := demoRepo(t)
	code, _ := out(t, "scan", "--fail-on", "critical", repo)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (the AWS key is CRITICAL)", code)
	}
}

func TestScanWithACriticalOnlyThresholdAndTheAWSKeyAllowedPasses(t *testing.T) {
	repo := demoRepo(t)
	allowlistPath := filepath.Join(t.TempDir(), "allow.yaml")
	// Fingerprint of aws-access-key-id / config.env / AKIAIOSFODNN7EXAMPLE,
	// as printed by a real scan of the demo repo -- see the README.
	data := "allow:\n  - fingerprint: ae19d1f68d1ef291c447d9c10b1dc4df45e309c7ebf85c60c92de97487ba5654\n    reason: test\n"
	if err := os.WriteFile(allowlistPath, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _ := out(t, "scan", "--fail-on", "critical", "--allowlist", allowlistPath, repo)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (the only CRITICAL finding is allowed, nothing else reaches critical)", code)
	}
}

func TestScanOnCleanHistoryExitsZero(t *testing.T) {
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q", "-b", "main")
	run("config", "user.name", "clean")
	run("config", "user.email", "clean@example.invalid")
	run("config", "commit.gpgsign", "false")
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# nothing to see here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "-A")
	run("commit", "-q", "-m", "initial commit")

	code, report := out(t, "scan", "--format", "json", dir)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0: %s", code, report)
	}
	if !strings.Contains(report, `"findings": []`) && !strings.Contains(report, `"findings": null`) {
		t.Errorf("expected no findings at all:\n%s", report)
	}
}

func TestSARIFOutputIsWellFormedAndOmitsAllowedFindings(t *testing.T) {
	repo := demoRepo(t)
	code, report := out(t, "scan", "--format", "sarif", "--allowlist", "../../testdata/demo-allowlist.yaml", repo)
	if code != 1 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(report, `"version": "2.1.0"`) {
		t.Error("not a SARIF 2.1.0 document")
	}
	if strings.Contains(report, "generic entropy rule can't tell") {
		t.Error("an allowed finding's reason should not leak into SARIF (SARIF has no allowlist concept)")
	}
	if !strings.Contains(report, `"ruleId": "aws-access-key-id"`) {
		t.Error("the AWS key finding should still be a real SARIF result")
	}
}

func TestNonGitDirectoryExitsTwo(t *testing.T) {
	code, _ := out(t, "scan", t.TempDir())
	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (not a git repository)", code)
	}
}

func TestUnknownFailOnValueIsRejected(t *testing.T) {
	code, _ := out(t, "scan", "--fail-on", "severe", t.TempDir())
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestBadAllowlistFileIsRejected(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "allow.yaml")
	if err := os.WriteFile(bad, []byte("allow:\n  - reason: missing the fingerprint\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _ := out(t, "scan", "--allowlist", bad, t.TempDir())
	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (missing fingerprint)", code)
	}
}

func TestTooManyPositionalArgsIsRejected(t *testing.T) {
	code, _ := out(t, "scan", ".", ".")
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestNoSubcommandPrintsUsage(t *testing.T) {
	if code := run(nil); code != 2 {
		t.Fatalf("run(nil) = %d, want 2", code)
	}
	if code := run([]string{"bogus"}); code != 2 {
		t.Fatalf("run([bogus]) = %d, want 2", code)
	}
}
