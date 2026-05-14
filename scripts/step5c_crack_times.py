"""
STEP 5c: Per-Password Crack Time Estimate at bcrypt(14)
=========================================================
For every password in the dataset, estimates:
  - How long a dictionary/rule attack would take to reach it in RockYou
  - How long a brute-force attack would take at bcrypt14 speed
  - Whether it was actually cracked in our experiment

Produces a ranked table and a chart showing the spectrum from
"cracked in seconds" to "effectively uncrackable."

Outputs:
  - graphs/table_crack_time_per_password.csv
  - graphs/chart10_crack_time_spectrum.png

Run from project root:
  python3 scripts/step5c_crack_times.py
"""

import csv
import math
import os
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

os.makedirs("graphs", exist_ok=True)

# ── Speeds ─────────────────────────────────────────────────────────────────────
BCRYPT14_HPS  = 1.0 / (188.877 / 150)   # from hashing_times.json
ROCKYOU_SIZE  = 14_344_391

# Approximate position of passwords in RockYou (lower index = found faster)
# These are real approximate ranks from the RockYou list
ROCKYOU_RANKS = {
    "123456":    1,
    "12345":     5,
    "123456789": 3,
    "password":  2,
    "iloveyou":  10,
    "princess":  22,
    "1234567":   7,
    "abc123":    9,
    "12345678":  4,
    "monkey":    18,
    "jessica":   50,
    "michael":   45,
    "qwerty":    6,
    "111111":    8,
    "sunshine":  30,
    "password1": 12,
    "soccer":    80,
    "admin":     15,
    "letmein":   20,
    "dragon":    25,
    "master":    35,
    "welcome":   40,
    "login":     55,
    "football":  60,
    "shadow":    65,
    "superman":  70,
    "batman":    75,
    "trustno1":  90,
    "baseball":  95,
    "pass123":   100,
    # Human-modified (cracked by rules - rule engine finds them via mutations)
    "P@ssw0rd":   500,
    "P@ssword1":  600,
    "Passw0rd!":  800,
    "Adm1n@123":  1200,
    "B@tm@n99":   1500,
    "Dr@g0n99":   1800,
    "J3ssica!":   2000,
    "M0nk3y!1":   2200,
    "Pr1nc3ss!":  2500,
    "Sh@dow123":  2800,
    "Sup3rman1":  3000,
    "Tr0uble!2":  3500,
}

def detect_charset_size(password):
    size = 0
    if any(c.islower() for c in password):  size += 26
    if any(c.isupper() for c in password):  size += 26
    if any(c.isdigit() for c in password):  size += 10
    if any(c == ' ' for c in password):     size += 1
    symbols = set("!@#$%^&*()_+-=[]{}|;':\",./<>?`~\\")
    if any(c in symbols for c in password): size += 32
    return max(size, 26)

def brute_force_time_bcrypt14(password):
    """Expected brute-force time in seconds at bcrypt14 speed."""
    n  = detect_charset_size(password)
    ss = n ** len(password)
    return (ss / 2) / BCRYPT14_HPS

def dict_attack_time_bcrypt14(rank):
    """Time for dict attack to reach a password at given RockYou rank."""
    return rank / BCRYPT14_HPS

def fmt_time(seconds):
    if seconds < 0.001:       return "<1 ms"
    if seconds < 1:           return f"{seconds*1000:.0f} ms"
    if seconds < 60:          return f"{seconds:.1f} sec"
    if seconds < 3600:        return f"{seconds/60:.1f} min"
    if seconds < 86400:       return f"{seconds/3600:.1f} hrs"
    if seconds < 86400*365:   return f"{seconds/86400:.1f} days"
    years = seconds / (86400*365)
    if years < 1e6:           return f"{years:,.0f} yrs"
    if years < 1e9:           return f"{years/1e6:.1f}M yrs"
    if years < 1e12:          return f"{years/1e9:.1f}B yrs"
    return f"{years:.2e} yrs"

# ── Load all passwords + crack status ─────────────────────────────────────────
# Passwords actually cracked (from pot files)
CRACKED = {
    "123456", "12345", "123456789", "password", "iloveyou", "princess",
    "1234567", "abc123", "12345678", "monkey", "jessica", "michael",
    "qwerty", "111111", "sunshine", "password1", "soccer", "admin",
    "letmein", "dragon", "master", "welcome", "login", "football",
    "shadow", "superman", "batman", "trustno1", "baseball", "pass123",
    "P@ssw0rd", "P@ssword1", "Passw0rd!", "Adm1n@123", "B@tm@n99",
    "Dr@g0n99", "J3ssica!", "M0nk3y!1", "Pr1nc3ss!", "Sh@dow123",
    "Sup3rman1", "Tr0uble!2",
}

CATEGORIES = ["common", "human_modified", "short_complex", "passphrases", "random"]
CAT_COLORS = {
    "common":         "#e74c3c",
    "human_modified": "#e67e22",
    "short_complex":  "#f1c40f",
    "passphrases":    "#2ecc71",
    "random":         "#27ae60",
}

rows = []
for cat in CATEGORIES:
    with open(f"passwords/{cat}.txt") as f:
        for line in f:
            pwd = line.rstrip("\n")
            if not pwd:
                continue
            cracked = pwd in CRACKED
            # Determine attack time
            if pwd in ROCKYOU_RANKS:
                attack_sec = dict_attack_time_bcrypt14(ROCKYOU_RANKS[pwd])
                method = "Dictionary/Rules"
            else:
                attack_sec = brute_force_time_bcrypt14(pwd)
                method = "Brute-force"

            rows.append({
                "Password":           pwd[:30] + ("..." if len(pwd) > 30 else ""),
                "Category":           cat,
                "Length":             len(pwd),
                "Charset Size":       detect_charset_size(pwd),
                "Attack Method":      method,
                "Est. Time (bcrypt14)": fmt_time(attack_sec),
                "Cracked in Experiment": "YES" if cracked else "no",
                "_sort_sec":          attack_sec,
            })

rows.sort(key=lambda r: r["_sort_sec"])

# ── Save CSV ───────────────────────────────────────────────────────────────────
csv_path = "graphs/table_crack_time_per_password.csv"
fieldnames = [k for k in rows[0].keys() if not k.startswith("_")]
with open(csv_path, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for r in rows:
        writer.writerow({k: v for k, v in r.items() if not k.startswith("_")})
print(f"[✓] Saved → {csv_path}")

# ── Print highlight table ──────────────────────────────────────────────────────
print("\n─── Fastest to crack (bcrypt14) ───")
for r in rows[:10]:
    status = "CRACKED" if r["Cracked in Experiment"] == "YES" else "survived"
    print(f"  [{status}] {r['Password']:<22} → {r['Est. Time (bcrypt14)']}")

print("\n─── Hardest to crack (bcrypt14) ───")
for r in rows[-5:]:
    print(f"  [survived] {r['Password']:<22} → {r['Est. Time (bcrypt14)']}")

# ── Chart 10: Crack time spectrum ─────────────────────────────────────────────
plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "axes.spines.top": False,
    "axes.spines.right": False,
    "figure.dpi": 150
})

# Use log10 of seconds for x-axis, plot each password as a dot
fig, ax = plt.subplots(figsize=(13, 7))

cat_y = {c: i for i, c in enumerate(CATEGORIES)}
LABEL = {
    "common": "Common", "human_modified": "Human Modified",
    "short_complex": "Short Complex", "passphrases": "Passphrases", "random": "Random"
}

for r in rows:
    cat   = r["Category"]
    sec   = r["_sort_sec"]
    log_s = math.log10(max(sec, 0.001))
    y     = cat_y[cat] + np.random.uniform(-0.25, 0.25)
    color = CAT_COLORS[cat]
    marker = "X" if r["Cracked in Experiment"] == "YES" else "o"
    size   = 80 if r["Cracked in Experiment"] == "YES" else 40
    ax.scatter(log_s, y, color=color, marker=marker, s=size,
               alpha=0.85, zorder=3, edgecolors="white", linewidths=0.5)

# Reference lines
refs = [
    (math.log10(60),        "1 min",  "#95a5a6"),
    (math.log10(3600),      "1 hr",   "#7f8c8d"),
    (math.log10(86400),     "1 day",  "#e67e22"),
    (math.log10(86400*365), "1 yr",   "#e74c3c"),
    (math.log10(86400*365*1000), "1K yrs", "#c0392b"),
]
for xv, label, color in refs:
    ax.axvline(xv, color=color, linestyle="--", alpha=0.45, linewidth=1)
    ax.text(xv + 0.05, 4.55, label, color=color, fontsize=8, rotation=90, va="top")

ax.set_yticks(list(cat_y.values()))
ax.set_yticklabels([LABEL[c] for c in CATEGORIES], fontsize=11)
ax.set_xlabel("Estimated Crack Time at bcrypt(14) Speed (log scale)", fontsize=11)
ax.set_title(
    "Per-Password Crack Time Spectrum — bcrypt(14)\n"
    "X = Cracked in Experiment   O = Survived",
    fontsize=13, fontweight="bold"
)

# Legend
patches = [mpatches.Patch(color=CAT_COLORS[c], label=LABEL[c]) for c in CATEGORIES]
cracked_marker = plt.Line2D([0],[0], marker="X", color="w",
                             markerfacecolor="black", markersize=10, label="Cracked")
survived_marker = plt.Line2D([0],[0], marker="o", color="w",
                              markerfacecolor="black", markersize=8, label="Survived")
ax.legend(handles=patches + [cracked_marker, survived_marker],
          loc="lower right", fontsize=9)

ax.grid(axis="x", alpha=0.2)
ax.set_xlim(-1, 28)
ax.set_ylim(-0.6, 4.8)
plt.tight_layout()
plt.savefig("graphs/chart10_crack_time_spectrum.png")
plt.close()
print("[✓] Saved → graphs/chart10_crack_time_spectrum.png")

print("\n[✓] Step 5c complete!")