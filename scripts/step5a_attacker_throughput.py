# Step 5a: Attacker throughput extrapolation
# Computes guesses/sec, RockYou exhaustion time, and brute-force times per algorithm.
# Run: python3 scripts/step5a_attacker_throughput.py

import json
import csv
import math
import os
import matplotlib.pyplot as plt

os.makedirs("graphs", exist_ok=True)

with open("hashes/hashing_times.json") as f:
    timing = json.load(f)

TOTAL_PASSWORDS = 150
ROCKYOU_SIZE    = 14_344_391
CHARSET_6       = (26+26+10+32) ** 6
CHARSET_8       = (26+26+10+32) ** 8
CHARSET_16      = (26+26+10+32) ** 16

per_hash_sec = {
    "MD5":            timing["md5"]           / TOTAL_PASSWORDS,
    "SHA-1":          timing["sha1"]          / TOTAL_PASSWORDS,
    "SHA-256":        timing["sha256"]        / TOTAL_PASSWORDS,
    "Salted SHA-256": timing["salted_sha256"] / TOTAL_PASSWORDS,
    "bcrypt (10)":    timing["bcrypt_10"]     / TOTAL_PASSWORDS,
    "bcrypt (12)":    timing["bcrypt_12"]     / TOTAL_PASSWORDS,
    "bcrypt (14)":    timing["bcrypt_14"]     / TOTAL_PASSWORDS,
}


def fmt_num(n):
    if n >= 1e12: return f"{n/1e12:.1f}T"
    if n >= 1e9:  return f"{n/1e9:.1f}B"
    if n >= 1e6:  return f"{n/1e6:.1f}M"
    if n >= 1e3:  return f"{n/1e3:.1f}K"
    return str(int(n))


def fmt_time(seconds):
    if seconds < 1:         return f"{seconds*1000:.2f} ms"
    if seconds < 60:        return f"{seconds:.1f} sec"
    if seconds < 3600:      return f"{seconds/60:.1f} min"
    if seconds < 86400:     return f"{seconds/3600:.1f} hrs"
    if seconds < 86400*365: return f"{seconds/86400:.1f} days"
    years = seconds / (86400*365)
    if years < 1e6: return f"{years:,.0f} yrs"
    if years < 1e9: return f"{years/1e6:.1f}M yrs"
    return f"{years:.2e} yrs"


rows = []
for algo, sph in per_hash_sec.items():
    hps = 1.0 / sph
    rows.append({
        "Algorithm":             algo,
        "Time per Hash":         fmt_time(sph),
        "Hashes/sec":            fmt_num(hps),
        "Guesses in 1 min":      fmt_num(hps * 60),
        "Guesses in 1 hr":       fmt_num(hps * 3600),
        "Guesses in 1 day":      fmt_num(hps * 86400),
        "Exhaust RockYou (14M)": fmt_time(ROCKYOU_SIZE / hps),
        "Brute-force 6-char":    fmt_time(CHARSET_6 / hps),
        "Brute-force 8-char":    fmt_time(CHARSET_8 / hps),
        "Brute-force 16-char":   fmt_time(CHARSET_16 / hps),
    })

with open("graphs/table_attacker_throughput.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
print("Saved -> graphs/table_attacker_throughput.csv")

for r in rows:
    print(f"\n  {r['Algorithm']}")
    for k, v in r.items():
        if k != "Algorithm":
            print(f"    {k:<30} {v}")

# Chart settings
plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.alpha": 0.3,
    "figure.dpi": 150
})

algos    = list(per_hash_sec.keys())
hps_vals = [1.0 / s for s in per_hash_sec.values()]
colors   = ["#e74c3c","#e67e22","#3498db","#95a5a6","#2ecc71","#27ae60","#1a6b40"]

# Chart 6: Hashes per second (log scale)
fig, ax = plt.subplots(figsize=(11, 6))
bars = ax.bar(algos, hps_vals, color=colors, edgecolor="white", linewidth=1.5, width=0.6)
for bar, val in zip(bars, hps_vals):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() * 1.8,
            fmt_num(val) + "/s", ha="center", va="bottom", fontsize=9, fontweight="bold")
ax.set_yscale("log")
ax.set_ylim(0.1, max(hps_vals) * 200)
ax.set_ylabel("Attacker Guesses per Second (log scale)", fontsize=11)
ax.set_xlabel("Hashing Algorithm", fontsize=11)
ax.set_title("Attacker Guessing Speed by Algorithm\n(Apple M2 Pro, Single Core)", fontsize=13, fontweight="bold")
ax.axhline(1e6, color="#e74c3c", linestyle="--", alpha=0.4, linewidth=1)
ax.axhline(1,   color="#2ecc71", linestyle="--", alpha=0.4, linewidth=1)
ax.text(6.45, 1e6 * 1.5, "1M/s", color="#e74c3c", fontsize=8, ha="right")
ax.text(6.45, 1 * 1.5,   "1/s",  color="#2ecc71", fontsize=8, ha="right")
plt.xticks(rotation=15, ha="right")
plt.tight_layout()
plt.savefig("graphs/chart6_attacker_throughput.png")
plt.close()
print("Saved -> graphs/chart6_attacker_throughput.png")

# Chart 7: Time to exhaust RockYou (log scale)
rockyou_times = [ROCKYOU_SIZE / (1.0/s) for s in per_hash_sec.values()]

fig, ax = plt.subplots(figsize=(11, 6))
bars = ax.bar(algos, rockyou_times, color=colors, edgecolor="white", linewidth=1.5, width=0.6)
for bar, val in zip(bars, rockyou_times):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() * 1.8,
            fmt_time(val), ha="center", va="bottom", fontsize=9, fontweight="bold")
ax.set_yscale("log")
ax.set_ylabel("Time to Exhaust RockYou Wordlist (log scale)", fontsize=11)
ax.set_xlabel("Hashing Algorithm", fontsize=11)
ax.set_title("Time to Try All 14 Million RockYou Passwords\n(Single Core)", fontsize=13, fontweight="bold")
ax.axhline(300,   color="#e74c3c", linestyle="--", alpha=0.5, linewidth=1)
ax.axhline(86400, color="#e67e22", linestyle="--", alpha=0.5, linewidth=1)
ax.text(6.45, 300*1.5,   "5 min", color="#e74c3c", fontsize=8, ha="right")
ax.text(6.45, 86400*1.5, "1 day", color="#e67e22", fontsize=8, ha="right")
plt.xticks(rotation=15, ha="right")
plt.tight_layout()
plt.savefig("graphs/chart7_rockyou_exhaustion_time.png")
plt.close()
print("Saved -> graphs/chart7_rockyou_exhaustion_time.png")