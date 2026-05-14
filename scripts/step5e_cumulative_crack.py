"""
STEP 5e: Cumulative Passwords Cracked Over Time (Simulated)
=============================================================
Simulates how many of the 42 crackable passwords would fall
over a 24-hour attack window, for each algorithm.

Uses real benchmark speeds + approximate RockYou rank positions
to model when each password would be reached in a dictionary attack.

Outputs:
  - graphs/chart12_cumulative_crack_over_time.png

Run from project root:
  python3 scripts/step5e_cumulative_crack.py
"""

import os
import math
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

os.makedirs("graphs", exist_ok=True)

# ── Algorithm speeds (hashes/sec from our benchmark) ─────────────────────────
ALGO_SPEEDS = {
    "MD5":        48_600,
    "SHA-1":      242_300,
    "SHA-256":    239_500,
    "bcrypt(10)": 12.6,
    "bcrypt(12)": 3.17,
    "bcrypt(14)": 0.794,
}

ALGO_COLORS = {
    "MD5":        "#e74c3c",
    "SHA-1":      "#e67e22",
    "SHA-256":    "#3498db",
    "bcrypt(10)": "#2ecc71",
    "bcrypt(12)": "#27ae60",
    "bcrypt(14)": "#1a6b40",
}

# ── Crackable passwords with their approximate RockYou rank ──────────────────
# Lower rank = found sooner in a dictionary attack
CRACKABLE = [
    # Common passwords (30) - verbatim in RockYou
    ("123456",    1),    ("password",   2),    ("123456789", 3),
    ("12345678",  4),    ("12345",      5),    ("qwerty",    6),
    ("1234567",   7),    ("111111",     8),    ("abc123",    9),
    ("iloveyou",  10),   ("admin",      15),   ("letmein",   20),
    ("monkey",    18),   ("dragon",     25),   ("master",    35),
    ("pass123",   100),  ("welcome",    40),   ("login",     55),
    ("soccer",    80),   ("football",   60),   ("shadow",    65),
    ("superman",  70),   ("michael",    45),   ("jessica",   50),
    ("password1", 12),   ("batman",     75),   ("trustno1",  90),
    ("baseball",  95),   ("princess",   22),   ("sunshine",  30),
    # Human-modified (3 verbatim in RockYou)
    ("P@ssw0rd",  500),  ("P@ssword1",  600),  ("Passw0rd!", 800),
    # Human-modified cracked by rules (best64 applies transforms after scanning wordlist)
    # Rules run AFTER full wordlist pass, so effective rank is ~full_wordlist + offset
    ("Adm1n@123", 14_344_391 + 100),
    ("B@tm@n99",  14_344_391 + 200),
    ("Dr@g0n99",  14_344_391 + 300),
    ("J3ssica!",  14_344_391 + 400),
    ("M0nk3y!1",  14_344_391 + 500),
    ("Pr1nc3ss!", 14_344_391 + 600),
    ("Sh@dow123", 14_344_391 + 700),
    ("Sup3rman1", 14_344_391 + 800),
    ("Tr0uble!2", 14_344_391 + 900),
]

TOTAL_CRACKABLE = len(CRACKABLE)  # 42

# ── Time axis: 0 to 24 hours in seconds ──────────────────────────────────────
TIME_MAX_SEC  = 24 * 3600
time_points   = np.linspace(0, TIME_MAX_SEC, 5000)

# ── For each algo, compute cumulative cracked at each time point ───────────────
def cumulative_cracked(speed_hps, time_points):
    """At each time t, how many guesses have been made? Count passwords found."""
    results = []
    for t in time_points:
        guesses = speed_hps * t
        count = sum(1 for _, rank in CRACKABLE if rank <= guesses)
        results.append(count)
    return results

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.alpha": 0.25,
    "figure.dpi": 150
})

fig, ax = plt.subplots(figsize=(12, 7))

for algo, speed in ALGO_SPEEDS.items():
    counts = cumulative_cracked(speed, time_points)
    ax.plot(time_points / 3600, counts,
            label=algo, color=ALGO_COLORS[algo], linewidth=2.5)

# ── Reference lines ────────────────────────────────────────────────────────────
ax.axhline(30, color="#95a5a6", linestyle=":", linewidth=1.2, alpha=0.7)
ax.axhline(42, color="#7f8c8d", linestyle=":", linewidth=1.2, alpha=0.7)
ax.text(23.8, 30.5, "30 cracked\n(all common)", ha="right", fontsize=8, color="#7f8c8d")
ax.text(23.8, 42.5, "42 cracked\n(max possible)", ha="right", fontsize=8, color="#7f8c8d")

# 5-min mark (our experiment limit)
ax.axvline(5/60, color="#e74c3c", linestyle="--", linewidth=1.2, alpha=0.6)
ax.text(5/60 + 0.1, 1, "5 min\n(our limit)", color="#e74c3c", fontsize=8)

ax.set_xlabel("Attack Duration (hours)", fontsize=11)
ax.set_ylabel("Cumulative Passwords Cracked (out of 42 crackable)", fontsize=11)
ax.set_title(
    "Simulated Cumulative Crack Progress Over 24 Hours\n"
    "(Dictionary + Rule Attack — Real Benchmark Speeds)",
    fontsize=13, fontweight="bold"
)
ax.set_ylim(-1, 48)
ax.set_xlim(0, 24)
ax.legend(title="Algorithm", fontsize=10, title_fontsize=10, loc="center right")

# Annotate final counts at 24h
for algo, speed in ALGO_SPEEDS.items():
    final = sum(1 for _, rank in CRACKABLE if rank <= speed * TIME_MAX_SEC)
    ax.annotate(f"{final}", xy=(24, final),
                xytext=(23.5, final + (0.5 if final < 41 else -1.5)),
                fontsize=9, color=ALGO_COLORS[algo], fontweight="bold")

plt.tight_layout()
plt.savefig("graphs/chart12_cumulative_crack_over_time.png")
plt.close()
print("[✓] Saved → graphs/chart12_cumulative_crack_over_time.png")

# ── Print summary ──────────────────────────────────────────────────────────────
print("\n─── Cumulative crack at key time points ───")
checkpoints = [
    ("5 min",   300),
    ("1 hour",  3600),
    ("6 hours", 21600),
    ("24 hours",86400),
]
print(f"{'Algorithm':<14}", end="")
for label, _ in checkpoints:
    print(f"  {label:>10}", end="")
print()
print("-" * 60)

for algo, speed in ALGO_SPEEDS.items():
    print(f"{algo:<14}", end="")
    for label, t in checkpoints:
        guesses = speed * t
        count = sum(1 for _, rank in CRACKABLE if rank <= guesses)
        print(f"  {count:>10}", end="")
    print()

print(f"\n  Max crackable in our dataset: {TOTAL_CRACKABLE} passwords")
print("\n[✓] Step 5e complete!")