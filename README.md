# credsweep

[![CI](https://github.com/sriharifortitude/credsweep/actions/workflows/ci.yml/badge.svg)](https://github.com/sriharifortitude/credsweep/actions/workflows/ci.yml)

A secrets scanner for a git repository's whole history, not just the
files checked out today. A key that was committed and removed two
commits later is still in the repository forever, readable to anyone
with clone access -- `git status` and a plain `grep` both come up clean,
which is exactly the problem. credsweep reads every commit's diff
(`git log --all -p`) and checks only the lines each commit *added*, so a
secret that predates the tool's adoption is found at the commit that
introduced it, not silently missed because it's gone from `HEAD`. See
[ADR 1](docs/adr/0001-scan-full-history-not-working-tree.md).

```
$ ./testdata/build-demo-repo.sh /tmp/demo && credsweep scan --allowlist testdata/demo-allowlist.yaml /tmp/demo

FOUND     CRITICAL aws-access-key-id            config.env:2
          commit 630329fe6174  2024-01-01T09:00:00Z  demo
          AKI...PLE (20 chars)
          fingerprint: ae19d1f68d1ef291c447d9c10b1dc4df45e309c7ebf85c60c92de97487ba5654 (allowlist this exact value with it)
FOUND     HIGH     slack-token                  notifications/slack.py:3
          commit 4f97ec6d6c95  2024-01-03T09:00:00Z  demo
          xox...vwx (63 chars)
          fingerprint: c1d7e3c23296ddc178c22ad0823eec9d027bf0d91b79ac8c344ad09ea1abe6e4 (allowlist this exact value with it)
allowed   MEDIUM   generic-high-entropy-secret  config.env:2
          commit d3a241c24ce3  2024-01-02T09:00:00Z  demo
          fro...ime (21 chars)
          allowed: "from-vault-at-runtime" is a placeholder saying the real value comes from Vault at deploy time, not a leaked credential -- the generic entropy rule can't tell the two apart, a human has to.
FOUND     MEDIUM   generic-high-entropy-secret  tests/fixtures.py:2
          commit d2487f2ee429  2024-01-04T09:00:00Z  demo
          Zx9...0Ga (32 chars)
          fingerprint: 412f6b1090843f77b3b334c05f1414df8723054c6ddc32d9a3c46e520821e7eb (allowlist this exact value with it)

4 findings: 3 flagged, 1 allowed
$ echo $?
1
```

(Real output. `testdata/build-demo-repo.sh` builds the exact repository
this was captured from -- fixed commit dates, so the SHAs and this
output are reproducible byte for byte; `.github/workflows/ci.yml` runs
this on every push and checks the output against these same strings.
Notice the AWS key is still found two commits after it was replaced with
`from-vault-at-runtime` -- and notice `from-vault-at-runtime` itself
trips the generic entropy rule too, which is exactly the false positive
the allowlist entry exists to accept.)

## The rules

| rule | severity | what it catches |
| --- | --- | --- |
| `aws-access-key-id` | Critical | an AWS access key ID (`AKIA...`) |
| `aws-secret-access-key` | Critical | a 40-character AWS secret key, matched alongside its conventional variable name |
| `github-pat` | Critical | a classic GitHub personal access token (`ghp_...`) |
| `github-fine-grained-pat` | Critical | a fine-grained GitHub personal access token |
| `slack-token` | High | a Slack API token (`xoxb-`, `xoxp-`, ...) |
| `stripe-live-secret-key` | Critical | a Stripe live-mode secret key (`sk_live_...`) |
| `google-api-key` | High | a Google API key (`AIza...`) |
| `private-key-block` | Critical | a PEM private key block |
| `jwt` | High | a JSON Web Token |
| `generic-high-entropy-secret` | Medium | a high-entropy value assigned to a variable named like a secret, when no more specific rule already caught it. An unquoted function call (`let tokens = tokenize(expr);`) is code, not a value, and is skipped; a quoted string is always checked |

v0.1.0's generic rule reported function calls assigned to variables
named like `token`. That surfaced the first time credsweep ran over
another repo's real source
([bomdelta](https://github.com/sriharifortitude/bomdelta)'s Rust parser),
and was fixed in v0.1.1 with a regression test built from those lines.

Every finding names the exact commit, author, date, file and line a
secret was added on -- and never the secret itself. See
[ADR 2](docs/adr/0002-never-store-or-print-the-secret.md) for why: the
report shows a redaction (`AKI...PLE (20 chars)`, or `[redacted, N
chars]` for anything 12 characters or shorter) and a fingerprint, never
the value.

## Allowlisting a false positive

A finding's fingerprint -- printed with the finding itself -- is a
`sha256` of the rule, the file path and the matched value. Copy it
straight into an allowlist; nothing about the real secret value needs to
be typed or stored:

```yaml
allow:
  - fingerprint: d3ebb4ad3038b0626a7c4fc81c741f330b4da2ebaee01709fd7f232e402ef7fc
    reason: >-
      "from-vault-at-runtime" is a placeholder, not a leaked credential.
```

`reason` is required -- an allowlist entry nobody can explain is
indistinguishable from one nobody checked. An allowed finding still
appears in the terminal and JSON report (marked `allowed`, with its
reason), so nothing silently disappears; it is just excluded from the
pass/fail decision and from SARIF, which has no concept of "accepted
risk" to put it in.

## Output formats and exit codes

`--format terminal|json|sarif`, `--output FILE`, `--fail-on
medium|high|critical` (default `medium`: the lowest severity any rule
here produces, so by default any unallowed finding fails the run).

| exit code | meaning |
| --- | --- |
| 0 | nothing unallowed at or above `--fail-on` |
| 1 | at least one finding does |
| 2 | the path isn't a git repository, or the allowlist file is malformed |

## Running it

    go install github.com/sriharifortitude/credsweep/cmd/credsweep@v0.1.0
    credsweep scan .

Or the image (needs a real `git` binary at runtime, so unlike most of
this portfolio's Go tools it is not `FROM scratch`/distroless -- see the
Dockerfile):

    docker run --rm -v "$PWD:/repo" ghcr.io/sriharifortitude/credsweep:0.1 scan /repo

`credsweep scan` with no path scans the current directory.

## Checks

    go build ./... && go vet ./... && staticcheck ./...
    go test ./... -race -cover

Every package below `internal/` is tested in isolation with plain Go
values -- no git process involved -- except `gitlog`, `scan` and the CLI
itself, which build a real throwaway repository with `git init` in a
temp directory and assert against its actual history. That split is
deliberate: `internal/gitdiff` (patch text to added lines) and
`internal/detect` (a line of text to zero or more matches) are pure
functions tested with fixture strings; only the handful of tests that
exist specifically to prove "this really works against real git" pay
the cost of shelling out to it.

## What it deliberately does not do

- **No pre-commit / staged-changes mode.** This scans committed history,
  not what's about to be committed -- see
  [ADR 1](docs/adr/0001-scan-full-history-not-working-tree.md). Pair it
  with a pre-commit hook tool if you also want to stop a leak before it
  is committed at all; this one is for what already happened.
- **A shallow clone silently scans less than you think.** `git clone
  --depth 1` truncates history before credsweep ever sees it. Run it
  against a full clone (`fetch-depth: 0` in GitHub Actions' checkout
  action) or it will report a false all-clear.
- **Regex and entropy, not an ML model.** Ten specific patterns plus one
  entropy-based fallback. This misses secret formats nobody has written
  a pattern for yet and, on the generic rule, flags some things that
  aren't secrets at all (the demo output above shows both a real find
  and a heuristic false positive, on purpose).
- **No automatic remediation, rotation, or history rewriting.** It
  tells you what was found and exactly where; it changes nothing.
- **AWS, GitHub, Slack, Stripe, Google and generic PEM/JWT only.** Not
  every provider's key format. Extending `internal/detect/patterns.go`
  with another `regexRule` is the intended way to add one.

## Licence

MIT.
