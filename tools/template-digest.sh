#!/bin/sh
# acse-gate-template-1: the digest of the gate template in a repository (the reusable workflow and the composite
# action), with find, sort, grep, sed, tail, sha256sum and jq only. ACSE's reference recipe, unchanged apart from this
# header; tests/vectors/template-digest.json holds its golden vectors.
#
# The one line of .github/workflows/acse-gate.yml that runs the composite action names the policy repository and a ref
# (`uses: <owner>/<repo>/.github/actions/acse-gate@<ref>`), so it differs between policy repositories. It is hashed in
# its placeholder form, `uses: __OWNER__/__REPOSITORY__/.github/actions/acse-gate@__REF__`, and every other byte as it
# is: every copy of one release has one digest. Exactly one such line must exist, and the file must end with a line
# feed; otherwise the template is invalid. (ACSE separately requires the real line to name the policy repository itself
# and the same ref the caller used.)
#
# Usage: template-digest.sh <repository-root>      (for this repository's source: template-digest.sh template)
# Prints sha256:<64 hex>. Exits 2 on a usage error, a missing template file, anything but regular files, or a workflow
# without exactly one action line.
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: template-digest.sh <repository-root>" >&2
  exit 2
fi
cd "$1"

workflow=.github/workflows/acse-gate.yml
action=.github/actions/acse-gate
if [ -h "$workflow" ] || [ ! -f "$workflow" ] || [ -h "$action" ] || [ ! -d "$action" ]; then
  echo "the gate template is missing or not regular files" >&2
  exit 2
fi
if [ -n "$(find "$action" ! -type f ! -type d -print)" ]; then
  echo "not a regular file under $action" >&2
  exit 2
fi

# The action line: optional indentation and list dash, `uses:`, then <owner>/<repo>/.github/actions/acse-gate@<ref>.
line='^([[:blank:]]*(-[[:blank:]]+)?uses:[[:blank:]]+)[A-Za-z0-9_-]+/[A-Za-z0-9._-]+(/\.github/actions/acse-gate@)[^[:space:]#]+'
if [ "$(grep -cE "$line" "$workflow" || true)" != 1 ] || [ -n "$(tail -c 1 "$workflow")" ]; then
  echo "$workflow must end with a line feed and have exactly one line uses: <owner>/<repo>/.github/actions/acse-gate@<ref>" >&2
  exit 2
fi

{ printf '%s\n' "$workflow"; find "$action" -type f -print; } | LC_ALL=C sort | while IFS= read -r path; do
  if [ "$path" = "$workflow" ]; then
    sum=$(sed -E "s|$line|\\1__OWNER__/__REPOSITORY__\\3__REF__|" "$path" | sha256sum | cut -d ' ' -f 1)
  else
    sum=$(sha256sum -- "$path" | cut -d ' ' -f 1)
  fi
  printf '%s\t%s\n' "$path" "$sum"
done | jq -R -n '{format: "acse-gate-template-1", files: [inputs | split("\t") | {path: .[0], sha256: .[1]}]}' \
  | jq -jcS . | sha256sum | cut -d ' ' -f 1 | sed 's/^/sha256:/'
