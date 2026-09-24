# 1. Scan every commit's diff, not the files on disk today

Status: accepted — 2026-09-24

## Context

The simplest possible secrets scanner greps the working tree: walk every
file currently checked out, run the patterns over it. That catches a key
still sitting in `config.env` right now. It does not catch the far more
common real incident -- a key was committed, `git rm`'d or overwritten
two commits later, and everyone breathes out because `git status` and
`grep` on `HEAD` both come up clean. The key is still there. Anyone with
clone access can run `git log -p` and find it, forever, unless history is
rewritten (which most teams never do, correctly regarding it as more
disruptive than rotating the credential).

A scanner that only reads the working tree cannot tell the difference
between "never committed" and "committed, then removed" -- and the
second case is the one that actually burns people.

## Decision

`internal/scan.Run` walks every commit reachable from any ref
(`git log --all`) and, for each one, looks at only the lines that commit
*added* -- not the full file content at that revision. This is a
deliberate choice against two simpler alternatives:

- **Full-file content at every revision** (`git show <sha>:<path>` for
  every file at every commit) would re-scan an unchanged file's
  unchanged lines at every commit that merely touched a sibling file,
  and would re-report the same finding once per descendant commit
  instead of once at the commit that introduced it.
- **Working tree plus a separate "scan staged changes" pre-commit mode**
  (what most competing tools lead with) never looks backward at all; it
  only prevents new leaks, and says nothing about a history that
  predates the tool's adoption -- which, for a portfolio-scale
  scanner meant to demonstrate finding *existing* problems, is the more
  interesting question.

Diffing is done by `internal/gitdiff.Parse`, a pure string parser with no
git dependency of its own, fed by `internal/gitlog.History`, which reads
the whole repository in one `git log --all -p` process rather than one
`git show` per commit -- a history of a few thousand commits stays a
single fork.

## Consequences

- A finding names the exact commit, author and date a secret was
  introduced -- the information someone needs to know what else that
  commit's author had access to and when to start the incident clock
  from, not just "somewhere in this repo".
- The same literal secret committed once and never touched again is
  reported exactly once, at the commit that added it -- not once per
  commit thereafter.
- **What this deliberately does not do:** it does not scan the working
  tree's uncommitted or staged changes, so it is not a pre-commit hook by
  itself. It is meant to run in CI against the full history (on a clone
  that actually has that history -- a shallow `git clone --depth 1`
  would silently make this a no-op, which is why the README says so).
- Binary files and merge commits' diffs are not specially handled beyond
  what `git log -p` itself does (binary files show as "Binary files ...
  differ" with no content to scan, which is correct -- a binary blob is
  not going to match a text-oriented pattern).
