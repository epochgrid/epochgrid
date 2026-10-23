#!/bin/bash
# Hook: .git/hooks/pre-rebase
# Prevent rebasing protected branches like main

set -u

BASE_BRANCH="${GIT_REBASE_HEAD:-origin/main}"

case "$BASE_BRANCH" in
    *main*|master)
        echo "⚠️  Warning: Rebase may rewrite protected branch '$BASE_BRANCH'"
        
        # Check if main is a remote and we're rebasing onto it
        git rev-parse origin/main >/dev/null 2>&1 && {
            echo ""
            echo "⚠️  Rebased commit(s) will NOT be included in the PR"
            echo "    Use: git push --force-with-lease origin $BASE_BRANCH"
            echo ""
            read -p 'Press enter to continue...'
        }
        ;;
esac

echo "✓ Proceeding with rebase"
