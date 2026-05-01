"""
STEP 2: Hash Generation
========================
Takes every password from Step 1 and hashes it using:
  1. MD5              - Fast, outdated, broken
  2. SHA-1            - Fast, outdated, deprecated
  3. SHA-256          - Faster modern hash (no salt here = still vulnerable)
  4. Salted SHA-256   - SHA-256 + random salt (much better)
  5. bcrypt (cost 10) - Adaptive, slow, modern standard
  6. bcrypt (cost 12) - Slower = more secure
  7. bcrypt (cost 14) - Even slower = even more secure

Output: One hash file per algorithm in the hashes/ folder.
        Also a master CSV with every password + all its hashes.

Run: python3 step2_generate_hashes.py
NOTE: bcrypt hashing is intentionally slow — be patient!
      On your Mac this may take 10-20 minutes for 150 passwords.
      That slowness is exactly the point — it shows why bcrypt is secure!

Set TEST_MODE = False to use fast bcrypt (cost=4) for a quick trial run.
Set TEST_MODE = False (default) for real costs (10, 12, 14) for your report.
"""

TEST_MODE = False   # ← Change to True for a quick test on your Mac

import hashlib
import bcrypt
import os
import csv
import json
import time

os.makedirs("hashes", exist_ok=True)

# ─────────────────────────────────────────────────────────
# LOAD PASSWORDS FROM STEP 1
# ─────────────────────────────────────────────────────────
categories = ["common", "human_modified", "short_complex", "passphrases", "random"]
all_passwords = []  # List of (password, category) tuples

for category in categories:
    filepath = f"passwords/{category}.txt"
    with open(filepath, "r") as f:
        for line in f:
            pwd = line.strip()
            if pwd:
                all_passwords.append((pwd, category))

print(f"[✓] Loaded {len(all_passwords)} passwords from Step 1\n")


# ─────────────────────────────────────────────────────────
# HASHING FUNCTIONS — each one explained simply
# ─────────────────────────────────────────────────────────

def hash_md5(password):
    """MD5: Fast, old, broken. Takes milliseconds to compute."""
    return hashlib.md5(password.encode()).hexdigest()

def hash_sha1(password):
    """SHA-1: Slightly better than MD5 but still fast and deprecated."""
    return hashlib.sha1(password.encode()).hexdigest()

def hash_sha256(password):
    """SHA-256: Modern but still fast without a salt — vulnerable to rainbow tables."""
    return hashlib.sha256(password.encode()).hexdigest()

def hash_salted_sha256(password):
    """
    Salted SHA-256: A random 'salt' (extra random string) is added
    before hashing. This means two identical passwords will produce
    different hashes — defeating rainbow table attacks.
    We store the salt alongside the hash so we can verify later.
    """
    salt = os.urandom(16).hex()          # 16 random bytes → hex string
    salted = salt + password             # prepend salt to password
    hashed = hashlib.sha256(salted.encode()).hexdigest()
    return f"{salt}${hashed}"           # store as "salt$hash"

def hash_bcrypt(password, cost):
    """
    bcrypt: Intentionally SLOW hashing algorithm.
    The 'cost' factor controls how slow it is:
      cost=10 → ~100ms per hash
      cost=12 → ~400ms per hash
      cost=14 → ~1.6 seconds per hash
    This makes brute-force attacks extremely expensive for attackers.
    """
    pwd_bytes = password.encode("utf-8")
    hashed = bcrypt.hashpw(pwd_bytes, bcrypt.gensalt(rounds=cost))
    return hashed.decode("utf-8")


# ─────────────────────────────────────────────────────────
# GENERATE ALL HASHES
# ─────────────────────────────────────────────────────────
print("Generating hashes... (bcrypt will take a few minutes — that's normal!)\n")

results = []   # Will hold one dict per password with all hashes

# Track timing per algorithm
timing = {
    "md5": 0, "sha1": 0, "sha256": 0,
    "salted_sha256": 0, "bcrypt_10": 0, "bcrypt_12": 0, "bcrypt_14": 0
}

for i, (password, category) in enumerate(all_passwords):
    row = {"password": password, "category": category}

    t = time.time(); row["md5"]           = hash_md5(password);              timing["md5"]          += time.time() - t
    t = time.time(); row["sha1"]          = hash_sha1(password);             timing["sha1"]         += time.time() - t
    t = time.time(); row["sha256"]        = hash_sha256(password);           timing["sha256"]       += time.time() - t
    t = time.time(); row["salted_sha256"] = hash_salted_sha256(password);    timing["salted_sha256"]+= time.time() - t
    bcrypt_costs = (4, 5, 6) if TEST_MODE else (10, 12, 14)
    t = time.time(); row["bcrypt_10"]     = hash_bcrypt(password, cost=bcrypt_costs[0]);  timing["bcrypt_10"]    += time.time() - t
    t = time.time(); row["bcrypt_12"]     = hash_bcrypt(password, cost=bcrypt_costs[1]);  timing["bcrypt_12"]    += time.time() - t
    t = time.time(); row["bcrypt_14"]     = hash_bcrypt(password, cost=bcrypt_costs[2]);  timing["bcrypt_14"]    += time.time() - t

    results.append(row)

    # Progress update every 10 passwords
    if (i + 1) % 10 == 0 or (i + 1) == len(all_passwords):
        print(f"  Progress: {i+1}/{len(all_passwords)} passwords hashed...")

print("\n[✓] All hashing complete!\n")


# ─────────────────────────────────────────────────────────
# SAVE MASTER CSV (password + category + all hashes)
# ─────────────────────────────────────────────────────────
csv_path = "hashes/all_hashes.csv"
fieldnames = ["password", "category", "md5", "sha1", "sha256",
              "salted_sha256", "bcrypt_10", "bcrypt_12", "bcrypt_14"]

with open(csv_path, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(results)

print(f"[✓] Master CSV saved → {csv_path}")


# ─────────────────────────────────────────────────────────
# SAVE JOHN THE RIPPER COMPATIBLE HASH FILES
# John the Ripper needs hashes in a specific format.
# Format: username:hash  (one per line)
# ─────────────────────────────────────────────────────────

# MD5 — John format: just the raw md5 hash
with open("hashes/john_md5.txt", "w") as f:
    for i, row in enumerate(results):
        f.write(f"user{i}:{row['md5']}\n")
print("[✓] John-ready MD5 hashes → hashes/john_md5.txt")

# SHA-1 — John format: raw sha1 hash
with open("hashes/john_sha1.txt", "w") as f:
    for i, row in enumerate(results):
        f.write(f"user{i}:{row['sha1']}\n")
print("[✓] John-ready SHA-1 hashes → hashes/john_sha1.txt")

# SHA-256 — John format: raw sha256 hash
with open("hashes/john_sha256.txt", "w") as f:
    for i, row in enumerate(results):
        f.write(f"user{i}:{row['sha256']}\n")
print("[✓] John-ready SHA-256 hashes → hashes/john_sha256.txt")

# bcrypt cost=10 — John format: the full bcrypt string (already includes cost/salt)
with open("hashes/john_bcrypt10.txt", "w") as f:
    for i, row in enumerate(results):
        f.write(f"user{i}:{row['bcrypt_10']}\n")
print("[✓] John-ready bcrypt(10) hashes → hashes/john_bcrypt10.txt")

with open("hashes/john_bcrypt12.txt", "w") as f:
    for i, row in enumerate(results):
        f.write(f"user{i}:{row['bcrypt_12']}\n")
print("[✓] John-ready bcrypt(12) hashes → hashes/john_bcrypt12.txt")

with open("hashes/john_bcrypt14.txt", "w") as f:
    for i, row in enumerate(results):
        f.write(f"user{i}:{row['bcrypt_14']}\n")
print("[✓] John-ready bcrypt(14) hashes → hashes/john_bcrypt14.txt")


# ─────────────────────────────────────────────────────────
# SAVE TIMING DATA (useful for the report)
# ─────────────────────────────────────────────────────────
timing_path = "hashes/hashing_times.json"
with open(timing_path, "w") as f:
    json.dump(timing, f, indent=2)

print(f"\n[✓] Hashing times saved → {timing_path}")

print("\n─── Hashing Time Summary ───")
print(f"{'Algorithm':<20} {'Total Time':>12} {'Per Hash':>12}")
print("─" * 46)
for algo, total in timing.items():
    per_hash = total / len(all_passwords)
    print(f"{algo:<20} {total:>10.3f}s  {per_hash*1000:>9.3f}ms")

print("\n[✓] Step 2 complete! Move on to step3_run_john.sh")
