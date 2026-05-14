# Step 2: Hash Generation
# Hashes all 150 passwords using 7 algorithms and saves John-compatible hash files.
# Run: python3 step2_generate_hashes.py

TEST_MODE = False  # Set True to use bcrypt cost 4/5/6 for a quick test run

import hashlib
import bcrypt
import os
import csv
import json
import time

os.makedirs("hashes", exist_ok=True)

# Load passwords from step 1
categories = ["common", "human_modified", "short_complex", "passphrases", "random"]
all_passwords = []

for category in categories:
    with open(f"passwords/{category}.txt") as f:
        for line in f:
            pwd = line.strip()
            if pwd:
                all_passwords.append((pwd, category))

print(f"Loaded {len(all_passwords)} passwords\n")


# Hashing functions

def hash_md5(password):
    return hashlib.md5(password.encode()).hexdigest()

def hash_sha1(password):
    return hashlib.sha1(password.encode()).hexdigest()

def hash_sha256(password):
    return hashlib.sha256(password.encode()).hexdigest()

def hash_salted_sha256(password):
    # Random 16-byte salt prepended before hashing, stored as salt$hash
    salt = os.urandom(16).hex()
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}${hashed}"

def hash_bcrypt(password, cost):
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=cost))
    return hashed.decode("utf-8")


# Generate all hashes and track timing per algorithm
print("Hashing passwords... (bcrypt will take several minutes)\n")

results = []
timing = {
    "md5": 0, "sha1": 0, "sha256": 0,
    "salted_sha256": 0, "bcrypt_10": 0, "bcrypt_12": 0, "bcrypt_14": 0
}

bcrypt_costs = (4, 5, 6) if TEST_MODE else (10, 12, 14)

for i, (password, category) in enumerate(all_passwords):
    row = {"password": password, "category": category}

    t = time.time(); row["md5"]           = hash_md5(password);                       timing["md5"]           += time.time() - t
    t = time.time(); row["sha1"]          = hash_sha1(password);                      timing["sha1"]          += time.time() - t
    t = time.time(); row["sha256"]        = hash_sha256(password);                    timing["sha256"]        += time.time() - t
    t = time.time(); row["salted_sha256"] = hash_salted_sha256(password);             timing["salted_sha256"] += time.time() - t
    t = time.time(); row["bcrypt_10"]     = hash_bcrypt(password, bcrypt_costs[0]);   timing["bcrypt_10"]     += time.time() - t
    t = time.time(); row["bcrypt_12"]     = hash_bcrypt(password, bcrypt_costs[1]);   timing["bcrypt_12"]     += time.time() - t
    t = time.time(); row["bcrypt_14"]     = hash_bcrypt(password, bcrypt_costs[2]);   timing["bcrypt_14"]     += time.time() - t

    results.append(row)

    if (i + 1) % 10 == 0 or (i + 1) == len(all_passwords):
        print(f"  {i+1}/{len(all_passwords)} hashed...")

print("\nDone.\n")


# Save master CSV
fieldnames = ["password", "category", "md5", "sha1", "sha256",
              "salted_sha256", "bcrypt_10", "bcrypt_12", "bcrypt_14"]

with open("hashes/all_hashes.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(results)

print("Saved -> hashes/all_hashes.csv")


# Save John the Ripper hash files (format: user0:hash)
john_files = {
    "john_md5.txt":      "md5",
    "john_sha1.txt":     "sha1",
    "john_sha256.txt":   "sha256",
    "john_bcrypt10.txt": "bcrypt_10",
    "john_bcrypt12.txt": "bcrypt_12",
    "john_bcrypt14.txt": "bcrypt_14",
}

for filename, field in john_files.items():
    with open(f"hashes/{filename}", "w") as f:
        for i, row in enumerate(results):
            f.write(f"user{i}:{row[field]}\n")
    print(f"Saved -> hashes/{filename}")


# Save timing data
with open("hashes/hashing_times.json", "w") as f:
    json.dump(timing, f, indent=2)

print("\nHashing time per algorithm:")
print(f"{'Algorithm':<20} {'Total':>10} {'Per Hash':>12}")
for algo, total in timing.items():
    per_hash = total / len(all_passwords)
    print(f"{algo:<20} {total:>8.3f}s  {per_hash*1000:>9.3f}ms")