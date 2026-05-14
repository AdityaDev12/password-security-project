# Step 5e: Simulate cumulative passwords cracked over 24 hours per algorithm
# Uses real benchmark speeds and RockYou rank positions to model crack progress.
# Run: python3 scripts/step5e_cumulative_crack.py

import os
import numpy as np
import matplotlib.pyplot as plt

os.makedirs("graphs", exist_ok=True)

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

ROCKYOU_SIZE = 14_344_391

# Each crackable password with its effective RockYou rank
# Rule-cracked passwords are found after the full wordlist pass
CRACKABLE = [
    ("123456",    1),   ("password",   2),   ("123456789", 3),
    ("12345678",  4),   ("12345",      5),   ("qwerty",    6),
    ("1234567",   7),   ("111111",     8),   ("abc123",    9),
    ("iloveyou",  10),  ("password1",  12),  ("admin",     15),
    ("monkey",    18),  ("letmein",    20),  ("princess",  22),
    ("dragon",    25),  ("sunshine",   30),  ("master",    35),
    ("welcome",   40),  ("michael",    45),  ("jessica",   50),
    ("login",     55),  ("football",   60),  ("shadow",    65),
    ("superman",  70),  ("batman",     75),  ("soccer",    80),
    ("trustno1",  90),  ("baseball",   95),  ("pass123",   100),
    ("P@ssw0rd",  500), ("P@ssword1",  600), ("Passw0rd!", 800),
    ("Adm1n@123", ROCKYOU_SIZE + 100),
    ("B@tm@n99",  ROCKYOU_SIZE + 200),
    ("Dr@g0n99",  ROCKYOU_SIZE + 300),
    ("J3ssica!",  ROCKYOU_SIZE + 400),
    ("M0nk3y!1",  ROCKYOU_SIZE + 500),
    ("Pr1nc3ss!", ROCKYOU_SIZE + 600),
    ("Sh@dow123", ROCKYOU_SIZE + 700),
    ("Sup3rman1", ROCKYOU_SIZE + 800),
    ("Tr0uble!2", ROCKYOU_SIZE + 900),
]

TIME_MAX_SEC = 24 * 3600
time_points  = np.linspace(0, TIME_MAX_SEC, 5000)


def cumulative_cracked(speed_hps, time_points):
    return [sum(1 for _, rank in CRACKABLE if rank <= speed_hps * t) for t in time_points]


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
    ax.plot(time_points / 3600, cumulative_cracked(speed, time_points),
            label=algo, color=ALGO_COLORS[algo], linewidth=2.5)

ax.axhline(30, color="#95a5a6", linestyle=":", linewidth=1.2, alpha=0.7)
ax.axhline(42, color="#7f8c8d", linestyle=":", linewidth=1.2, alpha=0.7)
ax.text(23.8, 30.5, "30 (all common)",  ha="right", fontsize=8, color="#7f8c8d")
ax.text(23.8, 42.5, "42 (max possible)", ha="right", fontsize=8, color="#7f8c8d")
ax.axvline(5/60, color="#e74c3c", linestyle="--", linewidth=1.2, alpha=0.6)
ax.text(5/60 + 0.1, 1, "5 min\n(our limit)", color="#e74c3c", fontsize=8)

ax.set_xlabel("Attack Duration (hours)", fontsize=11)
ax.set_ylabel("Cumulative Passwords Cracked (out of 42 crackable)", fontsize=11)
ax.set_title("Simulated Cumulative Crack Progress Over 24 Hours\n(Dictionary + Rule Attack, Real Benchmark Speeds)",
             fontsize=13, fontweight="bold")
ax.set_ylim(-1, 48)
ax.set_xlim(0, 24)
ax.legend(title="Algorithm", fontsize=10, title_fontsize=10, loc="center right")

for algo, speed in ALGO_SPEEDS.items():
    final = sum(1 for _, rank in CRACKABLE if rank <= speed * TIME_MAX_SEC)
    ax.annotate(f"{final}", xy=(24, final),
                xytext=(23.5, final + (0.5 if final < 41 else -1.5)),
                fontsize=9, color=ALGO_COLORS[algo], fontweight="bold")

plt.tight_layout()
plt.savefig("graphs/chart12_cumulative_crack_over_time.png")
plt.close()
print("Saved -> graphs/chart12_cumulative_crack_over_time.png")

# Summary table
print("\nCumulative cracked at key time points:")
checkpoints = [("5 min", 300), ("1 hour", 3600), ("6 hours", 21600), ("24 hours", 86400)]
print(f"{'Algorithm':<14}", end="")
for label, _ in checkpoints:
    print(f"  {label:>10}", end="")
print()
print("-" * 58)
for algo, speed in ALGO_SPEEDS.items():
    print(f"{algo:<14}", end="")
    for _, t in checkpoints:
        count = sum(1 for _, rank in CRACKABLE if rank <= speed * t)
        print(f"  {count:>10}", end="")
    print()