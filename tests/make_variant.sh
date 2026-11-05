#!/usr/bin/env bash
# Copies the fixture policy repository to <dir> and changes only its bundle.json, as ACSE's Studio change path would.
#   versioning-enforce  gcp-storage-versioning moves from observe (the default) to enforce   (AC-G4)
#   salted              the customer sets a salt for the optional address hashes             (gate-run-report-2.0)
set -euo pipefail
variant=$1 dir=$2
rm -rf "$dir"
cp -R fixtures/policy-repo "$dir"
control="$dir/bundles/main/bundle.json"
case "$variant" in
  versioning-enforce) jq '.classes += [{"check_id": "gcp-storage-versioning", "mode": "enforce"}]' "$control" >"$control.new" ;;
  salted) jq '.address_hashing = {"salt": "fixture-salt-not-a-secret-0001"}' "$control" >"$control.new" ;;
  *) echo "unknown variant: $variant" >&2; exit 2 ;;
esac
mv "$control.new" "$control"
