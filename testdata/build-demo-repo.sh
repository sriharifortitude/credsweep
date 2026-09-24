#!/bin/sh
# Builds the small demo repository the README's example output and the
# CI verification step are both captured from. Every commit is
# deterministic (fixed author, fixed content) so the demo is reproducible
# byte for byte.
#
#   ./testdata/build-demo-repo.sh /path/to/dir
set -eu
dir="$1"
mkdir -p "$dir"
git -C "$dir" init -q -b main
git -C "$dir" config user.name "demo"
git -C "$dir" config user.email "demo@example.invalid"
git -C "$dir" config commit.gpgsign false

# Every commit gets a fixed author/committer date so the SHAs -- and the
# README output and CI check captured from this script -- are the same
# on every machine and every run, not just internally consistent.
export GIT_AUTHOR_NAME="demo" GIT_COMMITTER_NAME="demo"
export GIT_AUTHOR_EMAIL="demo@example.invalid" GIT_COMMITTER_EMAIL="demo@example.invalid"

cat >"$dir/config.env" <<'EOF'
DATABASE_URL=postgres://app:app@localhost/app
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
EOF
git -C "$dir" add config.env
GIT_AUTHOR_DATE="2024-01-01T09:00:00+00:00" GIT_COMMITTER_DATE="2024-01-01T09:00:00+00:00" \
  git -C "$dir" commit -q -m "add local dev config"

cat >"$dir/config.env" <<'EOF'
DATABASE_URL=postgres://app:app@localhost/app
AWS_ACCESS_KEY_ID=from-vault-at-runtime
EOF
git -C "$dir" add config.env
GIT_AUTHOR_DATE="2024-01-02T09:00:00+00:00" GIT_COMMITTER_DATE="2024-01-02T09:00:00+00:00" \
  git -C "$dir" commit -q -m "load the AWS key from vault instead of committing it"

mkdir -p "$dir/notifications"
cat >"$dir/notifications/slack.py" <<'EOF'
import requests

SLACK_TOKEN = "xoxb-notarealworkspace-notarealbotuser-abcdefghijklmnopqrstuvwx"


def notify(message):
    requests.post(
        "https://slack.com/api/chat.postMessage",
        json={"text": message},
        headers={"Authorization": f"Bearer {SLACK_TOKEN}"},
    )
EOF
git -C "$dir" add notifications/slack.py
GIT_AUTHOR_DATE="2024-01-03T09:00:00+00:00" GIT_COMMITTER_DATE="2024-01-03T09:00:00+00:00" \
  git -C "$dir" commit -q -m "add Slack notifications"

mkdir -p "$dir/tests"
cat >"$dir/tests/fixtures.py" <<'EOF'
# Used only by the test suite; never sent to a real API.
test_api_key = "Zx9Qm2Lp7Rk4Vn8Wt1Yc6Bh3Fj5Ds0Ga"
EOF
git -C "$dir" add tests/fixtures.py
GIT_AUTHOR_DATE="2024-01-04T09:00:00+00:00" GIT_COMMITTER_DATE="2024-01-04T09:00:00+00:00" \
  git -C "$dir" commit -q -m "add a fixture api key for the notifications tests"
