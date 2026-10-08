#!/bin/bash
echo "========================================"
echo "  ZTA Device Posture Check — $(hostname)"
echo "========================================"
echo ""

SCORE=100
ISSUES=()

echo "--- Check 1: Patch management tooling ---"
if command -v apt &>/dev/null || command -v yum &>/dev/null || command -v dnf &>/dev/null; then
    PKG=$(command -v apt || command -v yum || command -v dnf)
    echo "  ✓ Found: $PKG"
else
    echo "  ✗ No patch management tooling detected (-30)"
    SCORE=$((SCORE - 30))
    ISSUES+=("No patch-management tooling detected")
fi

echo ""
echo "--- Check 2: Disk encryption (LUKS) ---"
if lsblk -o NAME,FSTYPE 2>/dev/null | grep -qi crypto_luks; then
    echo "  ✓ LUKS encryption detected"
else
    echo "  ✗ Disk encryption not detected (-25)"
    SCORE=$((SCORE - 25))
    ISSUES+=("Disk encryption not detected")
fi

echo ""
echo "--- Posture Score: $SCORE/100 ---"

if [ ${#ISSUES[@]} -gt 0 ]; then
    echo "  Issues:"
    for i in "${ISSUES[@]}"; do echo "    - $i"; done
fi

echo ""
if [ $SCORE -ge 70 ]; then
    echo "  DECISION: ✓ ALLOWED (score >= 70)"
elif [ $SCORE -ge 40 ]; then
    echo "  DECISION: ⚠ LIMITED ACCESS (score >= 40)"
else
    echo "  DECISION: ✗ DENIED (score < 40)"
fi

echo ""
echo "========================================"
