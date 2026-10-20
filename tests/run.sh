#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
find . -type f -name '*.php' -not -path './vendor/*' -not -path './node_modules/*' -print0 | xargs -0 -r -n1 php -l
for test in tests/*Test.php; do
    log="$(mktemp)"
    if php "$test" >"$log" 2>&1; then
        cat "$log"
    else
        status=$?
        cat "$log"
        while IFS= read -r line; do
            line="${line//'%'/'%25'}"
            echo "::error title=$test::$line"
        done < "$log"
        rm -f "$log"
        exit "$status"
    fi
    rm -f "$log"
done
php tests/McpServerTest.php missing
php tests/McpServerTest.php old
