#!/bin/bash
# Step 3: Run John the Ripper attacks against all hash files
# Usage: bash step3_run_john.sh /path/to/rockyou.txt

ROCKYOU=${1:-"$HOME/rockyou.txt"}
JOHN="john"
RESULTS_DIR="results"
HASHES_DIR="hashes"
TIME_LIMIT=300

mkdir -p "$RESULTS_DIR"

if ! command -v "$JOHN" &> /dev/null; then
    echo "John the Ripper not found. Run: brew install john-jumbo"
    exit 1
fi

if [ ! -f "$ROCKYOU" ]; then
    echo "RockYou wordlist not found at: $ROCKYOU"
    echo "Download: curl -L -o ~/rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
    exit 1
fi

echo "Starting attacks | RockYou: $ROCKYOU | Time limit: ${TIME_LIMIT}s"
echo ""

# Run a single attack, save .pot and .log files to results/
run_attack() {
    local LABEL=$1
    local HASH_FILE=$2
    local FORMAT=$3
    local ATTACK_CMD=$4

    local POT_FILE="$RESULTS_DIR/${LABEL}.pot"
    local LOG_FILE="$RESULTS_DIR/${LABEL}.log"

    echo "Running: $LABEL"

    rm -f ~/.john/john.pot 2>/dev/null

    START=$(date +%s)
    timeout "$TIME_LIMIT" $JOHN "$HASH_FILE" \
        --format="$FORMAT" \
        $ATTACK_CMD \
        --pot="$POT_FILE" \
        > "$LOG_FILE" 2>&1
    END=$(date +%s)

    CRACKED=$($JOHN "$HASH_FILE" --format="$FORMAT" --pot="$POT_FILE" --show 2>/dev/null | grep -c ":")
    echo "  Cracked: $CRACKED passwords in $((END - START))s -> $POT_FILE"
    echo ""
}

# MD5 — 4 attack types
echo "--- MD5 ---"
run_attack "md5_dictionary" "$HASHES_DIR/john_md5.txt" "raw-md5" "--wordlist=$ROCKYOU"
run_attack "md5_rules"      "$HASHES_DIR/john_md5.txt" "raw-md5" "--wordlist=$ROCKYOU --rules=best64"
run_attack "md5_hybrid"     "$HASHES_DIR/john_md5.txt" "raw-md5" "--wordlist=$ROCKYOU --rules=hybrid1"
run_attack "md5_mask"       "$HASHES_DIR/john_md5.txt" "raw-md5" "--mask=?u?l?l?l?d?d"

# SHA-1 — 4 attack types
echo "--- SHA-1 ---"
run_attack "sha1_dictionary" "$HASHES_DIR/john_sha1.txt" "raw-sha1" "--wordlist=$ROCKYOU"
run_attack "sha1_rules"      "$HASHES_DIR/john_sha1.txt" "raw-sha1" "--wordlist=$ROCKYOU --rules=best64"
run_attack "sha1_hybrid"     "$HASHES_DIR/john_sha1.txt" "raw-sha1" "--wordlist=$ROCKYOU --rules=hybrid1"
run_attack "sha1_mask"       "$HASHES_DIR/john_sha1.txt" "raw-sha1" "--mask=?u?l?l?l?d?d"

# SHA-256 — 4 attack types
echo "--- SHA-256 ---"
run_attack "sha256_dictionary" "$HASHES_DIR/john_sha256.txt" "raw-sha256" "--wordlist=$ROCKYOU"
run_attack "sha256_rules"      "$HASHES_DIR/john_sha256.txt" "raw-sha256" "--wordlist=$ROCKYOU --rules=best64"
run_attack "sha256_hybrid"     "$HASHES_DIR/john_sha256.txt" "raw-sha256" "--wordlist=$ROCKYOU --rules=hybrid1"
run_attack "sha256_mask"       "$HASHES_DIR/john_sha256.txt" "raw-sha256" "--mask=?u?l?l?l?d?d"

# bcrypt cost 10 — dictionary and rules only (too slow for hybrid/mask)
echo "--- bcrypt cost=10 ---"
run_attack "bcrypt10_dictionary" "$HASHES_DIR/john_bcrypt10.txt" "bcrypt" "--wordlist=$ROCKYOU"
run_attack "bcrypt10_rules"      "$HASHES_DIR/john_bcrypt10.txt" "bcrypt" "--wordlist=$ROCKYOU --rules=best64"

# bcrypt cost 12 and 14 — dictionary only
echo "--- bcrypt cost=12 ---"
run_attack "bcrypt12_dictionary" "$HASHES_DIR/john_bcrypt12.txt" "bcrypt" "--wordlist=$ROCKYOU"

echo "--- bcrypt cost=14 ---"
run_attack "bcrypt14_dictionary" "$HASHES_DIR/john_bcrypt14.txt" "bcrypt" "--wordlist=$ROCKYOU"

echo "All attacks complete. Results in: $RESULTS_DIR/"