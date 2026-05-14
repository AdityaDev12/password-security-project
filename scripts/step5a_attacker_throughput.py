"""
STEP 5a: Attacker Throughput Extrapolation
==========================================
Uses real benchmark timing data to compute:
  - Hashes per second per algorithm
  - Guesses an attacker could make in 1 min, 1 hr, 1 day, 1 year
  - Time to exhaust RockYou (14M passwords) per algorithm
  - Time to crack a 6-char, 8-char, 16-char random password brute-force

Outputs:
  - graphs/table_attacker_throughput.csv
  - graphs/chart6_attacker_throughput.png

Run: python3 step5a_attacker_throughput.py
"""

import json
import csv
import math
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import os

os.makedirs("graphs", exist_ok=True)

# ── Load real timing data ──────────────────────────────────────────────────────
with open("hashes/hashing_times.json") as f:
    timing = json.load(f)

TOTAL_PASSWORDS = 150

# seconds per hash (per single password, not total)
per_hash_sec = {
    "MD5":            timing["md5"]          / TOTAL_PASSWORDS,
    "SHA-1":          timing["sha1"]         / TOTAL_PASSWORDS,
    "SHA-256":        timing["sha256"]       / TOTAL_PASSWORDS,
    "Salted SHA-256": timing["salted_sha256"]/ TOTAL_PASSWORDS,
    "bcrypt (10)":    timing["bcrypt_10"]    / TOTAL_PASSWORDS,
    "bcrypt (12)":    timing["bcrypt_12"]    / TOTAL_PASSWORDS,
    "bcrypt (14)":    timing["bcrypt_14"]    / TOTAL_PASSWORDS,
}

# ── Compute attacker metrics ───────────────────────────────────────────────────
ROCKYOU_SIZE    = 14_344_391   # real rockyou.txt line count
CHARSET_6_FULL  = (26+26+10+32) ** 6   # upper+lower+digit+symbol, len 6
CHARSET_8_FULL  = (26+26+10+32) ** 8
CHARSET_16_FULL = (26+26+10+32) ** 16

def fmt_num(n):
    if n >= 1e12: return f"{n/1e12:.1f}T"
    if n >= 1e9:  return f"{n/1e9:.1f}B"
    if n >= 1e6:  return f"{n/1e6:.1f}M"
    if n >= 1e3:  return f"{n/1e3:.1f}K"
    return str(int(n))

def fmt_time(seconds):
    if seconds < 1:        return f"{seconds*1000:.2f} ms"
    if seconds < 60:       return f"{seconds:.1f} sec"
    if seconds < 3600:     return f"{seconds/60:.1f} min"
    if seconds < 86400:    return f"{seconds/3600:.1f} hrs"
    if seconds < 86400*365:return f"{seconds/86400:.1f} days"
    years = seconds / (86400*365)
    if years < 1e6:        return f"{years:,.0f} yrs"
    if years < 1e9:        return f"{years/1e6:.1f}M yrs"
    return f"{years:.2e} yrs"

rows = []
for algo, sec_per_hash in per_hash_sec.items():
    hps = 1.0 / sec_per_hash  # hashes per second

    rows.append({
        "Algorithm":             algo,
        "Time per Hash":         fmt_time(sec_per_hash),
        "Hashes/sec":            fmt_num(hps),
        "Guesses in 1 min":      fmt_num(hps * 60),
        "Guesses in 1 hr":       fmt_num(hps * 3600),
        "Guesses in 1 day":      fmt_num(hps * 86400),
        "Exhaust RockYou (14M)": fmt_time(ROCKYOU_SIZE / hps),
        "Brute-force 6-char":    fmt_time(CHARSET_6_FULL / hps),
        "Brute-force 8-char":    fmt_time(CHARSET_8_FULL / hps),
        "Brute-force 16-char":   fmt_time(CHARSET_16_FULL / hps),
    })

# ── Save CSV ───────────────────────────────────────────────────────────────────
csv_path = "graphs/table_attacker_throughput.csv"
with open(csv_path, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
print(f"[✓] Saved → {csv_path}")

# ── Print table ────────────────────────────────────────────────────────────────
print("\n─── Attacker Throughput Table ───")
for r in rows:
    print(f"\n  {r['Algorithm']}")
    for k, v in r.items():
        if k != "Algorithm":
            print(f"    {k:<30} {v}")

# ── Chart 6: Hashes per second (log bar) ──────────────────────────────────────
plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.alpha": 0.3,
    "figure.dpi": 150
})

algos  = list(per_hash_sec.keys())
hps_vals = [1.0 / s for s in per_hash_sec.values()]
colors = ["#e74c3c","#e67e22","#3498db","#95a5a6","#2ecc71","#27ae60","#1a6b40"]

fig, ax = plt.subplots(figsize=(11, 6))
bars = ax.bar(algos, hps_vals, color=colors, edgecolor="white", linewidth=1.5, width=0.6)

for bar, val in zip(bars, hps_vals):
    label = fmt_num(val) + "/s"
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() * 1.8,
            label, ha="center", va="bottom", fontsize=9, fontweight="bold")

ax.set_yscale("log")
ax.set_ylabel("Attacker Guesses per Second (log scale)", fontsize=11)
ax.set_xlabel("Hashing Algorithm", fontsize=11)
ax.set_title(
    "Attacker Guessing Speed by Algorithm\n"
    "(Based on Real Benchmark — Apple M2 Pro, Single Core)",
    fontsize=13, fontweight="bold"
)
ax.set_ylim(0.1, max(hps_vals) * 200)

# Annotate danger zones
ax.axhline(1e6,  color="#e74c3c", linestyle="--", alpha=0.4, linewidth=1)
ax.axhline(1,    color="#2ecc71", linestyle="--", alpha=0.4, linewidth=1)
ax.text(6.45, 1e6 * 1.5, "1M/s threshold", color="#e74c3c", fontsize=8, ha="right")
ax.text(6.45, 1 * 1.5,   "1/s threshold",  color="#2ecc71", fontsize=8, ha="right")

plt.xticks(rotation=15, ha="right")
plt.tight_layout()
plt.savefig("graphs/chart6_attacker_throughput.png")
plt.close()
print("[✓] Saved → graphs/chart6_attacker_throughput.png")

# ── Chart 7: Time to exhaust RockYou ──────────────────────────────────────────
rockyou_times_sec = [ROCKYOU_SIZE / (1.0/s) for s in per_hash_sec.values()]

fig, ax = plt.subplots(figsize=(11, 6))
bar_colors_2 = colors
bars2 = ax.bar(algos, rockyou_times_sec, color=bar_colors_2, edgecolor="white", linewidth=1.5, width=0.6)

for bar, val in zip(bars2, rockyou_times_sec):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() * 1.8,
            fmt_time(val), ha="center", va="bottom", fontsize=9, fontweight="bold")

ax.set_yscale("log")
ax.set_ylabel("Time to Exhaust Full RockYou Wordlist (log scale)", fontsize=11)
ax.set_xlabel("Hashing Algorithm", fontsize=11)
ax.set_title(
    "Time to Try All 14 Million RockYou Passwords\n"
    "(Single Core — Real Benchmark Timing)",
    fontsize=13, fontweight="bold"
)

# Reference lines
ax.axhline(300,   color="#e74c3c", linestyle="--", alpha=0.5, linewidth=1)
ax.axhline(86400, color="#e67e22", linestyle="--", alpha=0.5, linewidth=1)
ax.text(6.45, 300*1.5,   "5 min (our limit)", color="#e74c3c", fontsize=8, ha="right")
ax.text(6.45, 86400*1.5, "1 day",             color="#e67e22", fontsize=8, ha="right")

plt.xticks(rotation=15, ha="right")
plt.tight_layout()
plt.savefig("graphs/chart7_rockyou_exhaustion_time.png")
plt.close()
print("[✓] Saved → graphs/chart7_rockyou_exhaustion_time.png")

print("\n[✓] Step 5a complete!")