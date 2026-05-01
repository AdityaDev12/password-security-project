#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# STEP 3: John the Ripper Cracking Attacks
# ═══════════════════════════════════════════════════════════════
# This script runs 4 types of attacks on each hash file:
#   1. Dictionary Attack   — tries every word in rockyou.txt
#   2. Rule-Based Attack   — mutates dictionary words (adds numbers, symbols, etc.)
#   3. Hybrid Attack       — dictionary words + number/symbol patterns appended
#   4. Mask Attack         — targeted brute-force for predictable patterns
#
# Usage: bash step3_run_john.sh /path/to/rockyou.txt
# Example: bash step3_run_john.sh ~/rockyou.txt
# ═══════════════════════════════════════════════════════════════

ROCKYOU=${1:-"$HOME/rockyou.txt"}   # Path to rockyou wordlist (passed as argument)
JOHN="john"                          # John the Ripper command (installed via brew)
RESULTS_DIR="results"
HASHES_DIR="hashes"
TIME_LIMIT=300                       # Max seconds per attack (5 minutes)

mkdir -p "$RESULTS_DIR"

# Check that John is installed
if ! command -v "$JOHN" &> /dev/null; then
    echo "❌ John the Ripper not found! Run: brew install john-jumbo"
    exit 1
fi

# Check that rockyou.txt exists
if [ ! -f "$ROCKYOU" ]; then
    echo "❌ RockYou wordlist not found at: $ROCKYOU"
    echo "   Download it with:"
    echo "   curl -L -o ~/rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
    exit 1
fi

echo "═══════════════════════════════════════════════════════"
echo "  John the Ripper — Password Cracking Experiment"
echo "  RockYou: $ROCKYOU"
echo "  Time limit per attack: ${TIME_LIMIT}s"
echo "═══════════════════════════════════════════════════════"
echo ""

# ─────────────────────────────────────────────
# FUNCTION: Run one attack and save results
# ─────────────────────────────────────────────
run_attack() {
    local LABEL=$1       # e.g. "md5_dictionary"
    local HASH_FILE=$2   # e.g. "hashes/john_md5.txt"
    local FORMAT=$3      # e.g. "raw-md5"
    local ATTACK_CMD=$4  # the john command options

    local POT_FILE="$RESULTS_DIR/${LABEL}.pot"
    local LOG_FILE="$RESULTS_DIR/${LABEL}.log"

    echo "──────────────────────────────────────────────"
    echo "  Attack : $LABEL"
    echo "  File   : $HASH_FILE"
    echo "  Format : $FORMAT"
    echo "──────────────────────────────────────────────"

    # Clear previous john.pot so results don't carry over
    rm -f ~/.john/john.pot 2>/dev/null

    # Run John with time limit, capture output
    START=$(date +%s)
    timeout "$TIME_LIMIT" $JOHN "$HASH_FILE" \
        --format="$FORMAT" \
        $ATTACK_CMD \
        --pot="$POT_FILE" \
        > "$LOG_FILE" 2>&1
    END=$(date +%s)
    ELAPSED=$((END - START))

    # Show cracked passwords
    CRACKED=$($JOHN "$HASH_FILE" --format="$FORMAT" --pot="$POT_FILE" --show 2>/dev/null | grep -c ":")
    echo "  ✓ Cracked : $CRACKED passwords in ${ELAPSED}s"
    echo "  ✓ Results → $POT_FILE"
    echo ""
}

# ═══════════════════════════════════════════════════════
# ATTACK SET 1: MD5 Hashes
# MD5 is extremely fast to crack — John can test billions/sec
# ═══════════════════════════════════════════════════════
echo "▶ ATTACK SET 1: MD5"
echo ""

# 1a. Dictionary Attack — just try every word in RockYou
run_attack "md5_dictionary" \
    "$HASHES_DIR/john_md5.txt" \
    "raw-md5" \
    "--wordlist=$ROCKYOU"

# 1b. Rule-Based Attack — mutate wordlist words
#     --rules=best64 applies 64 common mutations:
#     capitalizing, adding numbers, l33t substitutions, etc.
run_attack "md5_rules" \
    "$HASHES_DIR/john_md5.txt" \
    "raw-md5" \
    "--wordlist=$ROCKYOU --rules=best64"

# 1c. Hybrid Attack — dictionary word + 2-digit number suffix
#     This catches passwords like "password12", "dragon99"
run_attack "md5_hybrid" \
    "$HASHES_DIR/john_md5.txt" \
    "raw-md5" \
    "--wordlist=$ROCKYOU --rules=hybrid1"

# 1d. Mask Attack — brute-force predictable 6-char patterns
#     ?u=uppercase ?l=lowercase ?d=digit ?s=symbol
#     Mask: ?u?l?l?l?d?d = one cap, 3 lower, 2 digits (e.g. "Apple42")
run_attack "md5_mask" \
    "$HASHES_DIR/john_md5.txt" \
    "raw-md5" \
    "--mask=?u?l?l?l?d?d"


# ═══════════════════════════════════════════════════════
# ATTACK SET 2: SHA-1 Hashes
# Faster than SHA-256, slower than MD5
# ═══════════════════════════════════════════════════════
echo "▶ ATTACK SET 2: SHA-1"
echo ""

run_attack "sha1_dictionary" \
    "$HASHES_DIR/john_sha1.txt" \
    "raw-sha1" \
    "--wordlist=$ROCKYOU"

run_attack "sha1_rules" \
    "$HASHES_DIR/john_sha1.txt" \
    "raw-sha1" \
    "--wordlist=$ROCKYOU --rules=best64"

run_attack "sha1_hybrid" \
    "$HASHES_DIR/john_sha1.txt" \
    "raw-sha1" \
    "--wordlist=$ROCKYOU --rules=hybrid1"

run_attack "sha1_mask" \
    "$HASHES_DIR/john_sha1.txt" \
    "raw-sha1" \
    "--mask=?u?l?l?l?d?d"


# ═══════════════════════════════════════════════════════
# ATTACK SET 3: SHA-256 Hashes
# Slower than MD5/SHA-1 but still crackable without salting
# ═══════════════════════════════════════════════════════
echo "▶ ATTACK SET 3: SHA-256"
echo ""

run_attack "sha256_dictionary" \
    "$HASHES_DIR/john_sha256.txt" \
    "raw-sha256" \
    "--wordlist=$ROCKYOU"

run_attack "sha256_rules" \
    "$HASHES_DIR/john_sha256.txt" \
    "raw-sha256" \
    "--wordlist=$ROCKYOU --rules=best64"

run_attack "sha256_hybrid" \
    "$HASHES_DIR/john_sha256.txt" \
    "raw-sha256" \
    "--wordlist=$ROCKYOU --rules=hybrid1"

run_attack "sha256_mask" \
    "$HASHES_DIR/john_sha256.txt" \
    "raw-sha256" \
    "--mask=?u?l?l?l?d?d"


# ═══════════════════════════════════════════════════════
# ATTACK SET 4: bcrypt cost=10
# bcrypt is slow by design — very few hashes per second
# ═══════════════════════════════════════════════════════
echo "▶ ATTACK SET 4: bcrypt (cost=10)"
echo ""

run_attack "bcrypt10_dictionary" \
    "$HASHES_DIR/john_bcrypt10.txt" \
    "bcrypt" \
    "--wordlist=$ROCKYOU"

run_attack "bcrypt10_rules" \
    "$HASHES_DIR/john_bcrypt10.txt" \
    "bcrypt" \
    "--wordlist=$ROCKYOU --rules=best64"


# ═══════════════════════════════════════════════════════
# ATTACK SET 5: bcrypt cost=12 and cost=14
# Even slower — demonstrates the security-performance tradeoff
# ═══════════════════════════════════════════════════════
echo "▶ ATTACK SET 5: bcrypt (cost=12)"
echo ""

run_attack "bcrypt12_dictionary" \
    "$HASHES_DIR/john_bcrypt12.txt" \
    "bcrypt" \
    "--wordlist=$ROCKYOU"

echo "▶ ATTACK SET 6: bcrypt (cost=14)"
echo ""

run_attack "bcrypt14_dictionary" \
    "$HASHES_DIR/john_bcrypt14.txt" \
    "bcrypt" \
    "--wordlist=$ROCKYOU"


# ═══════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════
echo "═══════════════════════════════════════════════════════"
echo "  ALL ATTACKS COMPLETE"
echo "  Results saved in: $RESULTS_DIR/"
echo "  Next step: python3 step4_analyze_results.py"
echo "═══════════════════════════════════════════════════════"
