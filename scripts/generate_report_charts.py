"""ScanOps 보고서용 차트 생성 스크립트.

생성 차트:
  1. 학습 곡선 비교 (Gemma-2 LoRA vs Qwen QLoRA)
  2. 벤치마크 탐지율 / 지연시간 비교
  3. CWE 분포 (훈련 데이터)
  4. RAG 파이프라인 진화 (v1 vs v2 vs 파인튜닝 목표)
"""

import json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
OUT  = BASE / "reports" / "charts"
OUT.mkdir(parents=True, exist_ok=True)

plt.rcParams.update({
    "figure.dpi": 150,
    "font.family": "DejaVu Sans",
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.alpha": 0.3,
})

COLORS = {
    "gemma":  "#E67E22",
    "qwen":   "#2980B9",
    "qwen_v4":"#1ABC9C",
    "tiny":   "#9B59B6",
    "eval":   "#E74C3C",
    "train":  "#3498DB",
}

# ── 1. 학습 곡선 비교 ────────────────────────────────────────────────────────────

gemma_loss = [
    (10, 2.909), (20, 1.649), (30, 1.320), (40, 1.108),
    (50, 1.021), (60, 0.914), (70, 0.844), (80, 0.797),
    (90, 0.808), (100, 0.710), (110, 0.698), (120, 0.711), (130, 0.692),
]

qwen_train = [
    (10, 2.891), (20, 2.021), (30, 1.519), (40, 1.142),
    (50, 0.977), (60, 0.879), (70, 0.797), (80, 0.737),
    (90, 0.698), (100, 0.692), (110, 0.656),
]
qwen_eval = [
    (23, 1.532), (46, 0.964), (69, 0.801), (92, 0.726), (115, 0.701),
]

# Qwen v4 초기 실측값 (epoch 1 기준, lora_train_v4.jsonl 재훈련 중)
qwen_v4_partial = [
    (10, 2.811), (20, 1.939), (30, 1.375),
]

fig, axes = plt.subplots(1, 2, figsize=(14, 5))
fig.suptitle("Learning Curves: Gemma-2 LoRA vs Qwen2.5 QLoRA", fontsize=14, fontweight="bold", y=1.02)

# 왼쪽: Gemma-2 LoRA
ax = axes[0]
gx, gy = zip(*gemma_loss)
ax.plot(gx, gy, color=COLORS["gemma"], lw=2, marker="o", ms=4, label="Gemma-2 2B LoRA (train)")
ax.set_title("Gemma-2 2B LoRA\n(203 samples · rank=16 · 5 epochs)", fontsize=11)
ax.set_xlabel("Training Step")
ax.set_ylabel("Loss")
ax.set_ylim(0, 3.2)
ax.axhline(0.692, color=COLORS["gemma"], ls="--", alpha=0.5, label=f"Final: 0.692")
ax.legend(fontsize=9)

# 오른쪽: Qwen QLoRA (v2 + v4 partial)
ax = axes[1]
tx, ty = zip(*qwen_train)
ex, ey = zip(*qwen_eval)
v4x, v4y = zip(*qwen_v4_partial)

ax.plot(tx, ty, color=COLORS["qwen"], lw=2, marker="o", ms=4, label="Qwen QLoRA v2 train")
ax.plot(ex, ey, color=COLORS["eval"], lw=2, marker="s", ms=5, ls="--", label="Qwen QLoRA v2 eval")
ax.plot(v4x, v4y, color=COLORS["qwen_v4"], lw=2, marker="^", ms=6, ls="-.", label="Qwen QLoRA v4 (in progress)")
ax.set_title("Qwen2.5-Coder-1.5B QLoRA\n(v2: 203 samples · v4: 291 samples · rank=32)", fontsize=11)
ax.set_xlabel("Training Step")
ax.set_ylabel("Loss")
ax.set_ylim(0, 3.2)
ax.axhline(0.656, color=COLORS["qwen"], ls="--", alpha=0.5, label="v2 final train: 0.656")
ax.axhline(0.701, color=COLORS["eval"], ls=":", alpha=0.5, label="v2 final eval: 0.701")
ax.legend(fontsize=8)

plt.tight_layout()
out1 = OUT / "01_learning_curves.png"
plt.savefig(out1, bbox_inches="tight")
plt.close()
print(f"[chart] {out1}")

# ── 2. 벤치마크 비교 ─────────────────────────────────────────────────────────────

models = [
    "Gemma:2b\n(base)",
    "Qwen2.5-Coder\n1.5B (base)",
    "Grok-3\n(API)",
    "ScanOps RAG v1\n(ChromaDB+Grok-3)",
    "ScanOps RAG v2\n(Qdrant+Grok-3)",
]
detection = [90, 85, 95, 90, 100]
cwe_acc   = [0,   5,  None, 25, None]
latency   = [4.3, 1.8, 17.7, 3.85, 5.45]

x = np.arange(len(models))
w = 0.35

fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(13, 9))
fig.suptitle("ScanOps Benchmark Comparison (20 Test Cases)", fontsize=14, fontweight="bold")

# 탐지율
bar_colors = ["#E67E22", "#2980B9", "#8E44AD", "#27AE60", "#1ABC9C"]
bars = ax1.bar(x, detection, color=bar_colors, alpha=0.85, width=0.55, edgecolor="white")
for bar, val in zip(bars, detection):
    ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.8,
             f"{val}%", ha="center", va="bottom", fontweight="bold", fontsize=11)
ax1.set_xticks(x)
ax1.set_xticklabels(models, fontsize=9)
ax1.set_ylabel("Vulnerability Detection Rate (%)")
ax1.set_title("Detection Rate by Model", fontsize=12)
ax1.set_ylim(0, 115)
ax1.axhline(100, color="red", ls="--", alpha=0.3, label="100% target")
ax1.legend()

# 지연시간 (로그 스케일)
bar2 = ax2.bar(x, latency, color=bar_colors, alpha=0.85, width=0.55, edgecolor="white")
for bar, val in zip(bar2, latency):
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.2,
             f"{val}s", ha="center", va="bottom", fontweight="bold", fontsize=11)
ax2.set_xticks(x)
ax2.set_xticklabels(models, fontsize=9)
ax2.set_ylabel("Average Latency (seconds)")
ax2.set_title("Average Response Latency (lower is better)", fontsize=12)

plt.tight_layout()
out2 = OUT / "02_benchmark_comparison.png"
plt.savefig(out2, bbox_inches="tight")
plt.close()
print(f"[chart] {out2}")

# ── 3. CWE 분포 ──────────────────────────────────────────────────────────────────

cwe_data = {
    "CWE-79 (XSS)": 46,
    "CWE-89 (SQL Injection)": 33,
    "CWE-78 (Command Injection)": 32,
    "CWE-284 (Access Control)": 28,
    "CWE-22 (Path Traversal)": 25,
    "CWE-77 (Code Injection)": 14,
    "CWE-416 (Use-After-Free)": 12,
    "CWE-798 (Hardcoded Creds)": 11,
    "CWE-502 (Deserialization)": 10,
    "Others (10 CWEs)": 80,
}

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
fig.suptitle("Training Data Composition — lora_train_v4.jsonl (291 samples)", fontsize=13, fontweight="bold")

# 파이 차트
labels = list(cwe_data.keys())
sizes  = list(cwe_data.values())
palette = plt.cm.tab10(np.linspace(0, 1, len(labels)))
wedges, texts, autotexts = ax1.pie(
    sizes, labels=None, autopct="%1.1f%%",
    colors=palette, startangle=140,
    pctdistance=0.82, wedgeprops=dict(linewidth=0.5, edgecolor="white")
)
for at in autotexts:
    at.set_fontsize(8)
ax1.legend(wedges, labels, loc="center left", bbox_to_anchor=(-0.35, 0.5), fontsize=8)
ax1.set_title("CWE Category Distribution")

# 심각도 분포
sev_labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
sev_counts = [104, 163, 21, 3]
sev_colors = ["#C0392B", "#E67E22", "#F1C40F", "#27AE60"]
bars = ax2.barh(sev_labels, sev_counts, color=sev_colors, edgecolor="white")
for bar, val in zip(bars, sev_counts):
    ax2.text(bar.get_width() + 1, bar.get_y() + bar.get_height()/2,
             str(val), va="center", fontweight="bold")
ax2.set_xlabel("Number of Samples")
ax2.set_title("Severity Distribution")
ax2.set_xlim(0, 190)

plt.tight_layout()
out3 = OUT / "03_training_data_distribution.png"
plt.savefig(out3, bbox_inches="tight")
plt.close()
print(f"[chart] {out3}")

# ── 4. 시스템 아키텍처 진화 타임라인 ─────────────────────────────────────────────

fig, ax = plt.subplots(figsize=(14, 6))
ax.set_xlim(0, 14)
ax.set_ylim(-1, 5)
ax.axis("off")
fig.patch.set_facecolor("#F8F9FA")

stages = [
    (1,   3.5, "Phase 1\nBase LLM\n(Qwen2.5-Coder\n1.5B)", "#2980B9", "Detection: 85%\nLatency: 1.8s"),
    (3.5, 3.5, "Phase 2\nGemma-2 LoRA\n(2B · rank=16\n203 samples)", "#E67E22", "Train loss: 0.692\nEpochs: 5"),
    (6,   3.5, "Phase 3\nQwen QLoRA\n(1.5B · rank=16\n203 samples)", "#8E44AD", "Train loss: 0.656\nEval loss: 0.701"),
    (8.5, 3.5, "Phase 4\nRAG Integration\n(Qdrant + BGE\nNVD CVE 2024-25)", "#27AE60", "CVE hit: 25%\nDetection: 90%"),
    (11,  3.5, "Phase 5\nQwen QLoRA v4\n(rank=32 · 291 samples\nclean format)", "#1ABC9C", "In Progress\n8 epochs"),
]

for i, (x, y, label, color, note) in enumerate(stages):
    circle = plt.Circle((x, y), 0.5, color=color, zorder=3)
    ax.add_patch(circle)
    ax.text(x, y, str(i+1), ha="center", va="center", fontsize=13,
            fontweight="bold", color="white", zorder=4)
    ax.text(x, y - 1.1, label, ha="center", va="top", fontsize=8,
            fontweight="bold", multialignment="center")
    ax.text(x, y + 1.0, note, ha="center", va="bottom", fontsize=7.5,
            color="#555", multialignment="center",
            bbox=dict(boxstyle="round,pad=0.3", facecolor="white", edgecolor=color, alpha=0.7))
    if i < len(stages) - 1:
        ax.annotate("", xy=(stages[i+1][0] - 0.5, y), xytext=(x + 0.5, y),
                    arrowprops=dict(arrowstyle="->", color="#AAA", lw=1.5))

ax.set_title("ScanOps Development Roadmap", fontsize=14, fontweight="bold", pad=20)

plt.tight_layout()
out4 = OUT / "04_system_roadmap.png"
plt.savefig(out4, bbox_inches="tight")
plt.close()
print(f"[chart] {out4}")

# ── 5. 학습 하이퍼파라미터 비교 테이블 ───────────────────────────────────────────

fig, ax = plt.subplots(figsize=(12, 4))
ax.axis("off")

columns = ["Parameter", "TinyLlama LoRA", "Gemma-2 LoRA", "Qwen QLoRA v2", "Qwen QLoRA v4"]
rows = [
    ["Base Model",       "TinyLlama 1.1B", "Gemma-2 2B-IT", "Qwen2.5-Coder 1.5B", "Qwen2.5-Coder 1.5B"],
    ["Training Method",  "LoRA",           "LoRA",           "QLoRA (MPS)",         "QLoRA (MPS)"],
    ["LoRA Rank (r)",    "8",              "16",             "16",                  "32"],
    ["LoRA Alpha",       "16",             "32",             "32",                  "64"],
    ["Target Modules",   "q,v",            "q,k,v,o",        "q,k,v,o",             "q,k,v,o"],
    ["Training Samples", "~50",            "203",            "203",                 "291"],
    ["Epochs",           "5",              "5",              "5",                   "8"],
    ["Learning Rate",    "2e-4",           "1e-4",           "1e-4",                "1e-4"],
    ["Batch Size",       "1",              "1",              "1",                   "1"],
    ["Grad Accum Steps", "4",              "8",              "8",                   "8"],
    ["Max Seq Length",   "512",            "768",            "768",                 "768"],
    ["Final Train Loss", "~1.05",          "0.692",          "0.656",               "TBD"],
    ["Final Eval Loss",  "N/A",            "N/A",            "0.701",               "TBD"],
]

cell_colors = []
for row in rows:
    cell_colors.append(["#F0F4F8"] + ["white"] * 4)

table = ax.table(
    cellText=rows,
    colLabels=columns,
    cellLoc="center",
    loc="center",
    cellColours=cell_colors,
)
table.auto_set_font_size(False)
table.set_fontsize(9)
table.scale(1, 1.4)

for j in range(len(columns)):
    table[0, j].set_facecolor("#2C3E50")
    table[0, j].set_text_props(color="white", fontweight="bold")

ax.set_title("Hyperparameter Comparison Across All Models", fontsize=13, fontweight="bold", pad=20)

plt.tight_layout()
out5 = OUT / "05_hyperparameter_table.png"
plt.savefig(out5, bbox_inches="tight")
plt.close()
print(f"[chart] {out5}")

print("\n✅ All charts saved to:", OUT)
print("Files:")
for f in sorted(OUT.glob("*.png")):
    print(f"  {f.name}")
