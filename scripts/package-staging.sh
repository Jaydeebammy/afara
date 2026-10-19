#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
output="${1:-/tmp/afara-staging.zip}"
mkdir -p "$(dirname "$output")"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/afara"
cp afara.php "$tmp/afara/"
cp -R src assets "$tmp/afara/"
cd "$tmp"
zip -q -r "$output" afara
unzip -t "$output" >/dev/null
unzip -Z1 "$output" | grep -Fx 'afara/afara.php' >/dev/null
if unzip -Z1 "$output" | grep -E '(^|/)(tests|\.github|vendor|node_modules)/|(^|/)\.env$'; then
  echo "Unexpected development or secret file in ZIP" >&2
  exit 1
fi
echo "Validated staging plugin ZIP: $output"
