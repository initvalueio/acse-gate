#!/bin/sh
# acse-class-digest-1: the digest of one class directory of a gate bundle, with find, sort, sha256sum and jq only.
# ACSE's reference recipe, unchanged apart from this header; tests/vectors/class-digest.json holds its golden vectors.
#
# Usage: class-digest.sh <class-directory> <check_id>
# Prints sha256:<64 hex>. Exits 2 on a usage error or when the directory holds anything but regular files.
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: class-digest.sh <class-directory> <check_id>" >&2
  exit 2
fi
dir=$1
check_id=$2

case "$check_id" in
  [a-z]*) ;;
  *) echo "not a check id: $check_id" >&2; exit 2 ;;
esac

cd "$dir"

# Every entry is a regular file or a directory: a symbolic link (or anything else) makes the bundle invalid.
if [ -n "$(find . ! -type f ! -type d -print)" ]; then
  echo "not a regular file under $dir" >&2
  exit 2
fi

find . -type f -print | sed 's|^\./||' | LC_ALL=C sort | while IFS= read -r path; do
  sum=$(sha256sum -- "$path" | cut -d ' ' -f 1)
  printf '%s\t%s\n' "$path" "$sum"
done | jq -R -n --arg check_id "$check_id" \
  '{algorithm: "acse-class-digest-1", check_id: $check_id, files: [inputs | split("\t") | {path: .[0], sha256: .[1]}]}' \
  | jq -jcS . | sha256sum | cut -d ' ' -f 1 | sed 's/^/sha256:/'
