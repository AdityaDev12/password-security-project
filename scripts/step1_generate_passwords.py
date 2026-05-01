"""
STEP 1: Password Dataset Generation
=====================================
Creates a synthetic password dataset organized into 5 categories
that reflect realistic user behavior patterns.

Categories:
  1. Common passwords       - Weak, frequently used passwords from leaked databases
  2. Human-modified         - Common words with typical substitutions (e.g., p@ssw0rd)
  3. Short complex          - Short but include symbols and numbers
  4. Passphrases            - Long multi-word phrases
  5. Random high-entropy    - Randomly generated strong passwords

Run: python3 step1_generate_passwords.py
"""

import random
import string
import os

# Create the passwords directory if it doesn't exist
os.makedirs("passwords", exist_ok=True)

# ─────────────────────────────────────────────────────────
# CATEGORY 1: Common / Weak Passwords
# Real passwords that appear frequently in leaked databases.
# These should be the easiest to crack.
# ─────────────────────────────────────────────────────────
common_passwords = [
    "123456", "password", "123456789", "12345678", "12345",
    "111111", "1234567", "sunshine", "qwerty", "iloveyou",
    "admin", "letmein", "monkey", "dragon", "master",
    "abc123", "pass123", "welcome", "login", "soccer",
    "football", "shadow", "superman", "michael", "jessica",
    "password1", "batman", "trustno1", "baseball", "princess"
]

# ─────────────────────────────────────────────────────────
# CATEGORY 2: Human-Modified Passwords
# People often take a common word and swap letters for
# numbers/symbols (e.g., 'a' → '@', 'o' → '0', 'e' → '3').
# These look complex but follow predictable patterns.
# ─────────────────────────────────────────────────────────
human_modified_passwords = [
    "P@ssw0rd",   "P@ssword1",  "S3cur1ty!",  "W3lc0me!",
    "L3tm31n!",   "Adm1n@123",  "Dr@g0n99",   "M0nk3y!1",
    "Sunsh1ne@",  "Tr0uble!2",  "H@cker123",  "Qu3rty!",
    "Sup3rman1",  "B@tm@n99",   "Fl00tball1", "J3ssica!",
    "M1chael@1",  "Pr1nc3ss!",  "Sh@dow123",  "S0ccer!1",
    "Passw0rd!",  "Secur1ty@",  "L0g1n#123",  "Welc0me@",
    "Adm1n!456",  "Mas7er@99",  "Dr3am0n!",   "Tru5tno1!",
    "B@s3ball1",  "Sun5hine@2"
]

# ─────────────────────────────────────────────────────────
# CATEGORY 3: Short Complex Passwords
# 6-8 characters with uppercase, lowercase, digits, symbols.
# They look strong due to complexity but are short,
# making brute-force more feasible.
# ─────────────────────────────────────────────────────────
short_complex_passwords = [
    "aB3!xY", "Zk9@mP", "Lp2#Qr", "Wn7$Vc", "Td4%Hj",
    "Fs8^Nb", "Gq1&Ew", "Ry5*Ui", "Cx6(Op", "Mv0)As",
    "Jb3!Df", "Kh7@Gl", "Nt2#Hk", "Bw9$Mj", "Qz4%Xv",
    "Py6^Wc", "Oa1&Rb", "Ie8*Ts", "Uf5(Lp", "Sd0)Nq",
    "aZ3!bY", "Xk8@cP", "Vm2#dR", "Wu7$eC", "Tj4%fH",
    "Sr9^gN", "Pq1&hE", "On6*iW", "Ml3(jU", "Lk0)kT"
]

# ─────────────────────────────────────────────────────────
# CATEGORY 4: Passphrases
# Long sequences of words strung together.
# High length = high entropy even without complex characters.
# These should be the hardest for brute-force.
# ─────────────────────────────────────────────────────────
passphrases = [
    "correct horse battery staple",
    "my cat loves sunny days",
    "the quick brown fox jumps",
    "blue sky over the mountain",
    "coffee and rain every morning",
    "open sesame magic door now",
    "never gonna give you up",
    "time flies when having fun",
    "bright stars light the dark sky",
    "dogs are better than cats here",
    "sunshine makes the flowers grow fast",
    "dragons fly over the green hills",
    "rivers run deep beneath the earth",
    "music fills the empty room tonight",
    "bread butter honey warm morning toast",
    "apple orange banana grape kiwi mango",
    "the moon rises over the ocean",
    "clouds move slowly across the sky",
    "books and coffee on rainy days",
    "long walks through quiet forest paths",
    "winter snow covers the silent town",
    "spring flowers bloom after the rain",
    "autumn leaves fall on the ground",
    "summer heat beats down on sand",
    "children laugh and play in parks",
    "the old clock ticks in silence",
    "a gentle breeze stirs the curtains",
    "waves crash against the rocky shore",
    "candles flicker in the cool night",
    "dreams fade with the morning light"
]

# ─────────────────────────────────────────────────────────
# CATEGORY 5: Random High-Entropy Passwords
# Truly random — no words, no patterns.
# Maximum resistance to all attack types.
# ─────────────────────────────────────────────────────────
def generate_random_password(length=16):
    """Generate a truly random password using all character types."""
    characters = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(random.choice(characters) for _ in range(length))

random.seed(42)  # Seed for reproducibility — same results every run
random_passwords = [generate_random_password(16) for _ in range(30)]

# ─────────────────────────────────────────────────────────
# SAVE ALL CATEGORIES TO SEPARATE FILES
# Each file = one category, one password per line
# ─────────────────────────────────────────────────────────
categories = {
    "common":         common_passwords,
    "human_modified": human_modified_passwords,
    "short_complex":  short_complex_passwords,
    "passphrases":    passphrases,
    "random":         random_passwords
}

all_passwords = []

for category_name, password_list in categories.items():
    filepath = f"passwords/{category_name}.txt"
    with open(filepath, "w") as f:
        for pwd in password_list:
            f.write(pwd + "\n")
    print(f"[✓] Saved {len(password_list):>2} passwords → {filepath}")
    all_passwords.extend([(pwd, category_name) for pwd in password_list])

# Also save a master list (all passwords together, no labels)
with open("passwords/all_passwords.txt", "w") as f:
    for pwd, _ in all_passwords:
        f.write(pwd + "\n")

print(f"\n[✓] Master list saved → passwords/all_passwords.txt")
print(f"[✓] Total passwords: {len(all_passwords)}")
print("\nCategory breakdown:")
for cat, pwds in categories.items():
    print(f"   {cat:<20} → {len(pwds)} passwords")
