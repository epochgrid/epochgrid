#!/bin/bash
# Hook: .git/hooks/commit-msg
set -u

COMMIT_MSG_FILE="$1"
MSG=$(cat "$COMMIT_MSG_FILE")

echo "=== Reviewing commit message ==="
echo "Message:"
echo "$MSG" | head -4

# Check for conventional commits prefix
if echo "$MSG" | grep -qE "^[a-z]+(\(.*?\))?:\s"; then
    echo ""
    echo "✅ Commit message uses conventional commits format (good!)"
else
    echo ""
    echo "⚠️  Suggestion: Consider using conventional commits:"
    echo "   - Prefix with: fix|feat|docs|refactor|style|test|chore"
    echo "   Example: 'fix(core): resolve authentication bug in handler'"
fi

# Check message contains at least one word
if ! echo "$MSG" | grep -qiE '\S'; then
    echo "❌ Commit message is too short or empty"
    exit 1
fi
