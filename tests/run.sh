#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
find . -type f -name '*.php' -not -path './vendor/*' -not -path './node_modules/*' -print0 | xargs -0 -r -n1 php -l
for test in tests/*Test.php; do
    php "$test"
done
php tests/McpServerTest.php missing
php tests/McpServerTest.php old
