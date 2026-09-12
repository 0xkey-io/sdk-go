#!/usr/bin/env sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
source_file="$repo_root/api/services-public_api.swagger.json"
overlay_file="$repo_root/api/public_api.compat.patch"
target_file="$repo_root/api/public_api.swagger.json"

if [ "${1:-}" = "--check" ]; then
  candidate=$(mktemp)
  trap 'rm -f "$candidate"' EXIT
  cp "$source_file" "$candidate"
  patch --silent "$candidate" < "$overlay_file"
  if ! cmp -s "$candidate" "$target_file"; then
    echo "error: api/public_api.swagger.json is not the canonical compatibility projection" >&2
    exit 1
  fi
  exit 0
fi

cp "$source_file" "$target_file"
patch --silent "$target_file" < "$overlay_file"
