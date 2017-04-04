#!/bin/bash
set -ev
which shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

PARENT_DIR=$(dirname "$0")

if [ "$TRAVIS_EVENT_TYPE" == "pull_request" ] && [ -n "$EXPENSIVE_TEST" ]; then
    (git log -1 "$TRAVIS_COMMIT_RANGE" | grep '\[run expensive tests\]' > /dev/null) || exit 0;
fi

if [ "$BUILD_MODE" = "lint" ]; then
    "$PARENT_DIR"/lint.sh
else
    "$PARENT_DIR"/build.sh
fi
