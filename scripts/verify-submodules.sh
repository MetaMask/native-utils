#!/bin/bash

# Script to verify that submodules are pinned to expected commits
# This prevents accidental submodule updates

set -e

echo "🔍 Verifying submodule commits..."

# Expected commits (update these when intentionally changing submodules)
EXPECTED_SECP256K1="a660a4976efe880bae7982ee410b9e0dc59ac983"
EXPECTED_BOTAN="07e1cfe0a06b224bbb37ad534736924931184246"

# Get actual commits
ACTUAL_SECP256K1=$(git ls-tree HEAD cpp/secp256k1 | awk '{print $3}')
ACTUAL_BOTAN=$(git ls-tree HEAD cpp/botan | awk '{print $3}')

# Verify secp256k1
if [ "$ACTUAL_SECP256K1" = "$EXPECTED_SECP256K1" ]; then
    echo "✅ cpp/secp256k1 is correctly pinned to $EXPECTED_SECP256K1"
else
    echo "❌ cpp/secp256k1 commit mismatch!"
    echo "   Expected: $EXPECTED_SECP256K1"
    echo "   Actual:   $ACTUAL_SECP256K1"
    echo ""
    echo "If this change is intentional:"
    echo "1. Update EXPECTED_SECP256K1 in this script"
    echo "2. Update SUBMODULES.md with the new commit hash"
    echo "3. Ensure the change has been security reviewed"
    exit 1
fi

# Verify botan
if [ "$ACTUAL_BOTAN" = "$EXPECTED_BOTAN" ]; then
    echo "✅ cpp/botan is correctly pinned to $EXPECTED_BOTAN"
else
    echo "❌ cpp/botan commit mismatch!"
    echo "   Expected: $EXPECTED_BOTAN"
    echo "   Actual:   $ACTUAL_BOTAN"
    echo ""
    echo "If this change is intentional:"
    echo "1. Update EXPECTED_BOTAN in this script"
    echo "2. Update SUBMODULES.md with the new commit hash"
    echo "3. Ensure the change has been security reviewed"
    exit 1
fi

echo "🎉 All submodules are correctly pinned!"
