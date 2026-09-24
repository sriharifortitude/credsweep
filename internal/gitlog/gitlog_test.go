package gitlog

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// initRepo creates a throwaway git repository in a temp dir, configured
// so commits work unattended on any machine (no reliance on a global
// user.name/email, no GPG signing prompt).
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

func TestIsRepo(t *testing.T) {
	repo := initRepo(t)
	if !IsRepo(repo) {
		t.Fatalf("IsRepo(%q) = false, want true", repo)
	}
	notRepo := t.TempDir()
	if IsRepo(notRepo) {
		t.Fatalf("IsRepo(%q) = true, want false", notRepo)
	}
}

func TestHistoryOnAnEmptyRepoIsEmpty(t *testing.T) {
	repo := initRepo(t)
	commits, err := History(repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(commits) != 0 {
		t.Fatalf("got %d commits, want 0", len(commits))
	}
}

func TestHistoryReturnsOneCommitWithItsPatch(t *testing.T) {
	repo := initRepo(t)
	writeFile(t, repo, "config.env", "TOKEN=ghp_notrealbutshapedlikeoneabcdefghijklmno\n")
	run(t, repo, "add", "config.env")
	run(t, repo, "commit", "-q", "-m", "add config")

	commits, err := History(repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(commits) != 1 {
		t.Fatalf("got %d commits, want 1", len(commits))
	}
	c := commits[0]

	wantSHA := strings.TrimSpace(runOut(t, repo, "rev-parse", "HEAD"))
	if c.SHA != wantSHA {
		t.Errorf("SHA = %q, want %q", c.SHA, wantSHA)
	}
	if c.Author != "credsweep tests" {
		t.Errorf("Author = %q, want %q", c.Author, "credsweep tests")
	}
	if !strings.HasPrefix(c.Date, "20") {
		t.Errorf("Date = %q, want an RFC 3339-ish timestamp", c.Date)
	}
	if !strings.Contains(c.Patch, "+++ b/config.env") {
		t.Errorf("Patch missing the expected file header:\n%s", c.Patch)
	}
	if !strings.Contains(c.Patch, "+TOKEN=ghp_notrealbutshapedlikeoneabcdefghijklmno") {
		t.Errorf("Patch missing the added line:\n%s", c.Patch)
	}
}

func TestHistoryIncludesCommitsOnEveryBranchNotJustHEAD(t *testing.T) {
	repo := initRepo(t)
	writeFile(t, repo, "a.txt", "on main\n")
	run(t, repo, "add", "a.txt")
	run(t, repo, "commit", "-q", "-m", "main commit")

	run(t, repo, "checkout", "-q", "-b", "side")
	writeFile(t, repo, "b.txt", "on side\n")
	run(t, repo, "add", "b.txt")
	run(t, repo, "commit", "-q", "-m", "side commit")

	commits, err := History(repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(commits) != 2 {
		t.Fatalf("got %d commits, want 2 (one per branch)", len(commits))
	}
}

func runOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}
