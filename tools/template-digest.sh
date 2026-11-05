#!/bin/sh
# acse-gate-template-1: the digest of the gate template in a repository (the reusable workflow and the composite
# action), with find, sort, sha256sum and jq only. ACSE's reference recipe, unchanged apart from this header;
# tests/vectors/template-digest.json holds its golden vectors.
#
# Usage: template-digest.sh <repository-root>      (for this repository's source: template-digest.sh template)
# Prints sha256:<64 hex>. Exits 2 on a usage error, a missing template file, or anything but regular files.
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

{ printf '%s\n' "$workflow"; find "$action" -type f -print; } | LC_ALL=C sort | while IFS= read -r path; do
  sum=$(sha256sum -- "$path" | cut -d ' ' -f 1)
  printf '%s\t%s\n' "$path" "$sum"
done | jq -R -n '{format: "acse-gate-template-1", files: [inputs | split("\t") | {path: .[0], sha256: .[1]}]}' \
  | jq -jcS . | sha256sum | cut -d ' ' -f 1 | sed 's/^/sha256:/'
