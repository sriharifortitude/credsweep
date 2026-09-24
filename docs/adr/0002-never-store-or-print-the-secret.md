# 2. The tool never writes a raw secret value anywhere -- not the report, not the allowlist

Status: accepted — 2026-09-24

## Context

A secrets scanner's whole job is finding sensitive values, which puts it
one careless `Printf` away from being the thing that leaks them: into a
CI log that is far more widely readable than the repository it scanned,
into a SARIF result that gets posted as a PR comment, into an allowlist
file that a team commits to skip a false positive and now holds the very
value it meant to stop worrying about. Every one of those is a real
place secret-scanner output has ended up in practice.

## Decision

The raw matched value (`detect.Match.Value`) lives only inside
`internal/scan.Run`'s loop, in memory, and never crosses a package
boundary as itself. Before a `scan.Finding` is built, the value is
reduced to two derived, one-way forms and then dropped:

- **A redaction** (`scan.redact`): a value of 12 characters or fewer
  becomes `[redacted, N chars]` with no content at all; a longer one
  shows at most 3 characters at each end (`AKI...PLE (20 chars)`) --
  always a minority of the string, enough for a human scanning the
  report to tell one finding from another without the report itself
  becoming a second place the secret is written down.
- **A fingerprint** (`allowlist.Fingerprint`): `sha256(ruleID + path +
  value)`, one-way and non-reversible. This is what an allowlist entry
  matches on, and it is what every finding prints specifically so a
  human never has to paste the real secret into a YAML file to suppress
  a false positive -- they copy the fingerprint credsweep already
  printed. An allowlist file committed to the repository it protects is
  consequently safe to commit: it can prove a value was seen and judged
  safe without the file itself being able to reproduce that value.

## Consequences

- SARIF results (`report.SARIF`) carry the redacted form in their
  message, not the value -- SARIF output is designed to be posted in
  exactly the semi-public places (PR checks, code-scanning dashboards)
  this decision is guarding against.
- An allowlist reviewer can audit *that* a fingerprint was accepted and
  *why* (the mandatory `reason` field), but cannot recover *what* the
  value was from the allowlist file alone -- which is the intended
  trade-off, not a limitation someone should route around by relaxing
  the fingerprint length check in `allowlist.Parse`.
- The redaction is asymmetric on purpose: `internal/scan/scan_test.go`'s
  `TestRedactMasksShortValuesCompletelyAndLongValuesMostly` pins both
  halves of that promise -- a short value is not just "kind of hidden",
  it is fully masked, because 3 characters at each end of a 10-character
  value would reveal most of it.
- What this does not protect against: a value the scanner's report is
  later copy-pasted alongside from some *other* unredacted source (the
  original file, a stack trace, a support ticket). credsweep can only
  answer for what it itself writes.
