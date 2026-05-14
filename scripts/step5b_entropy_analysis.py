"""
STEP 5b: Password Entropy and Search Space Analysis
=====================================================
Computes for each password in our dataset:
  - Character set size used
  - Shannon entropy (bits)
  - Theoretical search space size
  - Estimated brute-force time at MD5 and bcrypt14 speeds

Outputs:
  - graphs/table_entropy_by_category.csv   (per-category summary)
  - graphs/chart8_entropy_by_category.png  (box plot of entropy distribution)
  - graphs/chart9_searchspace.png          (search space comparison)

Run from project root:
  python3 scripts/step5b_entropy_analysis.py
"""

import csv
import math
import string
import os
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

os.makedirs("graphs", exist_ok=True)

# ── Real benchmark speeds (from hashing_times.json, per-hash) ─────────────────
# hashes per second
MD5_HPS      = 48_600        # from step5a output
BCRYPT14_HPS = 0.794         # 1 / 1.259s

# ── Load passwords ─────────────────────────────────────────────────────────────
CATEGORIES = ["common", "human_modified", "short_complex", "passphrases", "random"]
CAT_LABELS  = {
    "common":         "Common",
    "human_modified": "Human Modified",
    "short_complex":  "Short Complex",
    "passphrases":    "Passphrases",
    "random":         "Random",
}

def detect_charset_size(password):
    """Estimate the character set an attacker would need to cover this password."""
    size = 0
    if any(c.islower() for c in password):       size += 26
    if any(c.isupper() for c in password):       size += 26
    if any(c.isdigit() for c in password):       size += 10
    if any(c == ' ' for c in password):          size += 1
    symbols = set("!@#$%^&*()_+-=[]{}|;':\",./<>?`~\\")
    if any(c in symbols for c in password):      size += 32
    return max(size, 26)

def entropy_bits(password):
    """Shannon entropy: L * log2(N) where L=length, N=charset size."""
    n = detect_charset_size(password)
    return len(password) * math.log2(n)

def search_space(password):
    """Theoretical brute-force search space = N^L."""
    n = detect_charset_size(password)
    return n ** len(password)

def crack_time(space, hps):
    """Expected crack time in seconds (search space / 2 on average, / hps)."""
    return (space / 2) / hps

def fmt_time(seconds):
    if seconds < 1:          return f"{seconds*1000:.1f} ms"
    if seconds < 60:         return f"{seconds:.1f} sec"
    if seconds < 3600:       return f"{seconds/60:.1f} min"
    if seconds < 86400:      return f"{seconds/3600:.1f} hrs"
    if seconds < 86400*365:  return f"{seconds/86400:.1f} days"
    years = seconds / (86400*365)
    if years < 1e6:          return f"{years:,.0f} yrs"
    if years < 1e9:          return f"{years/1e6:.1f}M yrs"
    if years < 1e12:         return f"{years/1e9:.1f}B yrs"
    return f"{years:.2e} yrs"

# ── Analyze all passwords ──────────────────────────────────────────────────────
all_data   = []   # list of dicts, one per password
cat_data   = {c: [] for c in CATEGORIES}

for cat in CATEGORIES:
    with open(f"passwords/{cat}.txt") as f:
        for line in f:
            pwd = line.rstrip("\n")
            if not pwd:
                continue
            eb  = entropy_bits(pwd)
            ss  = search_space(pwd)
            ct_md5     = crack_time(ss, MD5_HPS)
            ct_bcrypt  = crack_time(ss, BCRYPT14_HPS)
            record = {
                "category":       cat,
                "password":       pwd,
                "length":         len(pwd),
                "charset_size":   detect_charset_size(pwd),
                "entropy_bits":   round(eb, 1),
                "search_space":   ss,
                "crack_time_md5":      fmt_time(ct_md5),
                "crack_time_bcrypt14": fmt_time(ct_bcrypt),
            }
            all_data.append(record)
            cat_data[cat].append(eb)

# ── Per-category summary table ─────────────────────────────────────────────────
summary_rows = []
for cat in CATEGORIES:
    bits = cat_data[cat]
    avg_bits  = sum(bits) / len(bits)
    min_bits  = min(bits)
    max_bits  = max(bits)
    # avg search space -> crack time
    avg_ss    = 10 ** (avg_bits / math.log2(10))  # approximate
    summary_rows.append({
        "Category":           CAT_LABELS[cat],
        "Avg Entropy (bits)": round(avg_bits, 1),
        "Min Entropy (bits)": round(min_bits, 1),
        "Max Entropy (bits)": round(max_bits, 1),
        "Avg Crack Time (MD5)":      fmt_time(crack_time(avg_ss, MD5_HPS)),
        "Avg Crack Time (bcrypt14)": fmt_time(crack_time(avg_ss, BCRYPT14_HPS)),
    })

csv_path = "graphs/table_entropy_by_category.csv"
with open(csv_path, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=summary_rows[0].keys())
    writer.writeheader()
    writer.writerows(summary_rows)
print(f"[✓] Saved → {csv_path}")

print("\n─── Entropy Summary by Category ───")
for r in summary_rows:
    print(f"  {r['Category']:<20} avg={r['Avg Entropy (bits)']} bits  "
          f"MD5: {r['Avg Crack Time (MD5)']:<18} bcrypt14: {r['Avg Crack Time (bcrypt14)']}")

# ── Chart 8: Box plot of entropy distribution per category ────────────────────
plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.alpha": 0.3,
    "figure.dpi": 150
})

BOX_COLORS = ["#e74c3c","#e67e22","#f1c40f","#2ecc71","#27ae60"]

fig, ax = plt.subplots(figsize=(10, 6))
data_to_plot = [cat_data[c] for c in CATEGORIES]
labels       = [CAT_LABELS[c].replace(" ", "\n") for c in CATEGORIES]

bp = ax.boxplot(data_to_plot, patch_artist=True, notch=False,
                medianprops=dict(color="black", linewidth=2),
                whiskerprops=dict(linewidth=1.5),
                capprops=dict(linewidth=1.5))

for patch, color in zip(bp["boxes"], BOX_COLORS):
    patch.set_facecolor(color)
    patch.set_alpha(0.8)

# Overlay individual points
for i, (cat, color) in enumerate(zip(CATEGORIES, BOX_COLORS), start=1):
    jitter = np.random.normal(0, 0.08, len(cat_data[cat]))
    ax.scatter([i + j for j in jitter], cat_data[cat],
               color=color, alpha=0.5, s=25, zorder=3)

# Annotate medians
for i, cat in enumerate(CATEGORIES, start=1):
    med = sorted(cat_data[cat])[len(cat_data[cat])//2]
    ax.text(i, med + 1.5, f"{med:.0f}b", ha="center", fontsize=9, fontweight="bold")

ax.set_xticks(range(1, len(CATEGORIES)+1))
ax.set_xticklabels(labels, fontsize=10)
ax.set_ylabel("Entropy (bits)", fontsize=11)
ax.set_xlabel("Password Category", fontsize=11)
ax.set_title(
    "Password Entropy Distribution by Category\n"
    "(Higher = Harder to Brute-Force)",
    fontsize=13, fontweight="bold"
)

# NIST minimum reference line (72 bits recommended)
ax.axhline(72, color="#e74c3c", linestyle="--", alpha=0.6, linewidth=1.5)
ax.text(5.45, 73.5, "NIST 72-bit min", color="#e74c3c", fontsize=8, ha="right")

plt.tight_layout()
plt.savefig("graphs/chart8_entropy_distribution.png")
plt.close()
print("[✓] Saved → graphs/chart8_entropy_distribution.png")

# ── Chart 9: Average entropy per category (clean bar) ────────────────────────
avg_entropies = [sum(cat_data[c])/len(cat_data[c]) for c in CATEGORIES]

fig, ax = plt.subplots(figsize=(10, 5))
bars = ax.bar(
    [CAT_LABELS[c].replace(" ", "\n") for c in CATEGORIES],
    avg_entropies,
    color=BOX_COLORS,
    edgecolor="white", linewidth=1.5, width=0.55
)
for bar, val in zip(bars, avg_entropies):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
            f"{val:.1f} bits", ha="center", va="bottom", fontsize=11, fontweight="bold")

ax.axhline(72, color="#e74c3c", linestyle="--", alpha=0.6, linewidth=1.5)
ax.text(4.45, 73.5, "NIST 72-bit min", color="#e74c3c", fontsize=8, ha="right")

ax.set_ylabel("Average Entropy (bits)", fontsize=11)
ax.set_xlabel("Password Category", fontsize=11)
ax.set_title(
    "Average Password Entropy by Category\n"
    "(Theoretical Brute-Force Resistance — Higher is Better)",
    fontsize=13, fontweight="bold"
)
ax.set_ylim(0, max(avg_entropies) * 1.15)
plt.tight_layout()
plt.savefig("graphs/chart9_avg_entropy_by_category.png")
plt.close()
print("[✓] Saved → graphs/chart9_avg_entropy_by_category.png")

print("\n[✓] Step 5b complete!")