# Step 4: Parse John the Ripper results and generate charts
# Run: python3 step4_analyze_results.py

import os
import csv
import json
import matplotlib.pyplot as plt
import pandas as pd
from collections import defaultdict

os.makedirs("graphs", exist_ok=True)

# Load password database and build plaintext -> category lookup
passwords_by_index = {}
with open("hashes/all_hashes.csv") as f:
    for i, row in enumerate(csv.DictReader(f)):
        passwords_by_index[f"user{i}"] = {
            "password": row["password"],
            "category": row["category"]
        }

plaintext_to_category = {v["password"]: v["category"] for v in passwords_by_index.values()}
total_passwords = len(passwords_by_index)
print(f"Loaded {total_passwords} passwords")


def parse_pot_file(pot_path):
    cracked = set()
    if not os.path.exists(pot_path):
        return cracked
    with open(pot_path, errors="ignore") as f:
        for line in f:
            line = line.strip()
            if ":" in line:
                plaintext = line.split(":")[-1]
                if plaintext:
                    cracked.add(plaintext)
    return cracked


def count_by_category(cracked_set):
    counts = defaultdict(int)
    for pwd in cracked_set:
        cat = plaintext_to_category.get(pwd, "unknown")
        counts[cat] += 1
    return counts


CATEGORIES   = ["common", "human_modified", "short_complex", "passphrases", "random"]
ALGORITHMS   = ["md5", "sha1", "sha256", "bcrypt10", "bcrypt12", "bcrypt14"]
ATTACK_TYPES = ["dictionary", "rules", "hybrid", "mask"]
CAT_SIZE     = 30

pot_files = {
    ("md5",      "dictionary"): "results/md5_dictionary.pot",
    ("md5",      "rules"):      "results/md5_rules.pot",
    ("md5",      "hybrid"):     "results/md5_hybrid.pot",
    ("md5",      "mask"):       "results/md5_mask.pot",
    ("sha1",     "dictionary"): "results/sha1_dictionary.pot",
    ("sha1",     "rules"):      "results/sha1_rules.pot",
    ("sha1",     "hybrid"):     "results/sha1_hybrid.pot",
    ("sha1",     "mask"):       "results/sha1_mask.pot",
    ("sha256",   "dictionary"): "results/sha256_dictionary.pot",
    ("sha256",   "rules"):      "results/sha256_rules.pot",
    ("sha256",   "hybrid"):     "results/sha256_hybrid.pot",
    ("sha256",   "mask"):       "results/sha256_mask.pot",
    ("bcrypt10", "dictionary"): "results/bcrypt10_dictionary.pot",
    ("bcrypt10", "rules"):      "results/bcrypt10_rules.pot",
    ("bcrypt12", "dictionary"): "results/bcrypt12_dictionary.pot",
    ("bcrypt14", "dictionary"): "results/bcrypt14_dictionary.pot",
}

real_results = {}
for key, path in pot_files.items():
    cracked_set = parse_pot_file(path)
    real_results[key] = count_by_category(cracked_set)
    print(f"  {key[0]:<10} {key[1]:<12} -> {sum(real_results[key].values())} cracked")

# Chart style
plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.alpha": 0.3,
    "figure.dpi": 150
})

COLORS = {
    "common": "#e74c3c", "human_modified": "#e67e22",
    "short_complex": "#f1c40f", "passphrases": "#2ecc71", "random": "#27ae60",
    "md5": "#e74c3c", "sha1": "#e67e22", "sha256": "#3498db",
    "bcrypt10": "#2ecc71", "bcrypt12": "#27ae60", "bcrypt14": "#1a6b40",
    "dictionary": "#3498db", "rules": "#9b59b6", "hybrid": "#e67e22", "mask": "#e74c3c",
}


# Chart 1: Crack rate by password category (best attack per category)
cat_crack_rates = {
    cat: round(max(real_results.get(k, {}).get(cat, 0) for k in real_results) / CAT_SIZE * 100, 1)
    for cat in CATEGORIES
}

fig, ax = plt.subplots(figsize=(9, 5))
bars = ax.bar(
    [c.replace("_", "\n") for c in CATEGORIES],
    [cat_crack_rates[c] for c in CATEGORIES],
    color=[COLORS[c] for c in CATEGORIES],
    edgecolor="white", linewidth=1.5, width=0.55
)
for bar, val in zip(bars, cat_crack_rates.values()):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
            f"{val}%", ha="center", va="bottom", fontsize=11, fontweight="bold")
ax.set_ylabel("Passwords Cracked (%)", fontsize=11)
ax.set_xlabel("Password Category", fontsize=11)
ax.set_title("Crack Rate by Password Category\n(Best Attack per Category)", fontsize=13, fontweight="bold")
ax.set_ylim(0, 115)
plt.tight_layout()
plt.savefig("graphs/chart1_crack_rate_by_category.png")
plt.close()
print("Saved -> graphs/chart1_crack_rate_by_category.png")


# Chart 2: Crack rate by hashing algorithm (best attack per algorithm)
algo_crack_rates = {
    algo: round(max(sum(real_results.get((algo, atk), {}).values()) for atk in ATTACK_TYPES) / total_passwords * 100, 1)
    for algo in ALGORITHMS
}

fig, ax = plt.subplots(figsize=(9, 5))
bars = ax.bar(
    ALGORITHMS,
    [algo_crack_rates[a] for a in ALGORITHMS],
    color=[COLORS[a] for a in ALGORITHMS],
    edgecolor="white", linewidth=1.5, width=0.55
)
for bar, val in zip(bars, algo_crack_rates.values()):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
            f"{val}%", ha="center", va="bottom", fontsize=11, fontweight="bold")
ax.set_ylabel("Passwords Cracked (%)", fontsize=11)
ax.set_xlabel("Hashing Algorithm", fontsize=11)
ax.set_title("Crack Rate by Hashing Algorithm\n(Best Attack, 5-Minute Time Limit)", fontsize=13, fontweight="bold")
ax.set_ylim(0, 60)
plt.tight_layout()
plt.savefig("graphs/chart2_crack_rate_by_algorithm.png")
plt.close()
print("Saved -> graphs/chart2_crack_rate_by_algorithm.png")


# Chart 3: Dictionary vs rules grouped bar (md5, sha1, sha256, bcrypt10)
algos_for_chart = ["md5", "sha1", "sha256", "bcrypt10"]
x = list(range(len(algos_for_chart)))
width = 0.35

fig, ax = plt.subplots(figsize=(10, 5))
for j, atk in enumerate(["dictionary", "rules"]):
    values = [round(sum(real_results.get((algo, atk), {}).values()) / total_passwords * 100, 1)
              for algo in algos_for_chart]
    bars = ax.bar([xi + (j - 0.5) * width for xi in x], values, width,
                  label=atk.capitalize(), color=COLORS[atk], edgecolor="white", linewidth=1)
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3,
                f"{val}%", ha="center", va="bottom", fontsize=9)
ax.set_ylabel("Passwords Cracked (%)", fontsize=11)
ax.set_xlabel("Hashing Algorithm", fontsize=11)
ax.set_title("Dictionary vs Rule-Based Attack Effectiveness\n(5-Minute Time Limit)", fontsize=13, fontweight="bold")
ax.set_xticks(x)
ax.set_xticklabels(algos_for_chart)
ax.set_ylim(0, 50)
ax.legend(title="Attack Type", fontsize=10)
plt.tight_layout()
plt.savefig("graphs/chart3_attack_type_effectiveness.png")
plt.close()
print("Saved -> graphs/chart3_attack_type_effectiveness.png")


# Chart 4: Hashing time per algorithm (log scale)
with open("hashes/hashing_times.json") as f:
    timing_data = json.load(f)

algo_labels = list(timing_data.keys())
per_hash_ms = [timing_data[a] / total_passwords * 1000 for a in algo_labels]

fig, ax = plt.subplots(figsize=(9, 5))
bars = ax.bar(algo_labels, per_hash_ms,
              color=["#e74c3c","#e67e22","#3498db","#95a5a6","#2ecc71","#27ae60","#1a6b40"],
              edgecolor="white", linewidth=1.5, width=0.55)
for bar, val in zip(bars, per_hash_ms):
    label = f"{val:.3f}ms" if val < 1 else (f"{val:.1f}ms" if val < 1000 else f"{val/1000:.1f}s")
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() * 1.3,
            label, ha="center", va="bottom", fontsize=8, fontweight="bold")
ax.set_ylabel("Time per Hash (ms, log scale)", fontsize=11)
ax.set_xlabel("Hashing Algorithm", fontsize=11)
ax.set_title("Time to Compute One Hash\n(Lower = Faster for Attacker = Less Secure)", fontsize=13, fontweight="bold")
ax.set_yscale("log")
ax.set_ylim(0.001, max(per_hash_ms) * 20)
plt.tight_layout()
plt.savefig("graphs/chart4_hashing_time_per_algorithm.png")
plt.close()
print("Saved -> graphs/chart4_hashing_time_per_algorithm.png")


# Chart 5: bcrypt cost factor vs passwords cracked (dual axis)
bcrypt_data = {
    "bcrypt(10)": sum(real_results.get(("bcrypt10", "dictionary"), {}).values()),
    "bcrypt(12)": sum(real_results.get(("bcrypt12", "dictionary"), {}).values()),
    "bcrypt(14)": sum(real_results.get(("bcrypt14", "dictionary"), {}).values()),
}
bcrypt_times = {k: timing_data[f"bcrypt_{k.split('(')[1].rstrip(')')}"] / total_passwords * 1000
                for k in bcrypt_data}

fig, ax1 = plt.subplots(figsize=(8, 5))
ax2 = ax1.twinx()
x = list(range(len(bcrypt_data)))
labels = list(bcrypt_data.keys())

bars = ax1.bar(x, list(bcrypt_data.values()),
               color=["#2ecc71", "#27ae60", "#1a6b40"],
               width=0.4, edgecolor="white", linewidth=1.5, label="Passwords Cracked")
ax2.plot(x, list(bcrypt_times.values()), "o--", color="#e74c3c", linewidth=2, markersize=8, label="Hash Time (ms)")

for bar, val in zip(bars, bcrypt_data.values()):
    ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.2,
             f"{val}", ha="center", va="bottom", fontsize=12, fontweight="bold")

ax1.set_ylabel("Passwords Cracked (out of 150)", fontsize=11)
ax2.set_ylabel("Time per Hash (ms)", fontsize=11, color="#e74c3c")
ax1.set_xlabel("bcrypt Cost Factor", fontsize=11)
ax1.set_title("bcrypt Cost Factor: Security vs Performance Tradeoff\n(Dictionary Attack, 5-Minute Limit)", fontsize=13, fontweight="bold")
ax1.set_xticks(x)
ax1.set_xticklabels(labels)
ax1.set_ylim(0, 25)
lines1, labels1 = ax1.get_legend_handles_labels()
lines2, labels2 = ax2.get_legend_handles_labels()
ax1.legend(lines1 + lines2, labels1 + labels2, fontsize=9)
plt.tight_layout()
plt.savefig("graphs/chart5_bcrypt_cost_tradeoff.png")
plt.close()
print("Saved -> graphs/chart5_bcrypt_cost_tradeoff.png")


# Save summary CSV
rows = []
for (algo, atk), cat_counts in real_results.items():
    total = sum(cat_counts.values())
    rows.append({
        "Algorithm":        algo,
        "Attack Type":      atk,
        "Common (30)":      cat_counts.get("common", 0),
        "Human Mod (30)":   cat_counts.get("human_modified", 0),
        "Short Cplx (30)":  cat_counts.get("short_complex", 0),
        "Passphrases (30)": cat_counts.get("passphrases", 0),
        "Random (30)":      cat_counts.get("random", 0),
        "Total Cracked":    total,
        "Crack Rate (%)":   round(total / total_passwords * 100, 1)
    })

df = pd.DataFrame(rows)
df.to_csv("graphs/summary_table.csv", index=False)
print("Saved -> graphs/summary_table.csv")
print("\n" + df.to_string(index=False))