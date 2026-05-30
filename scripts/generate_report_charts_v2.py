"""ScanOps 보고서용 차트 생성 스크립트 v2 — 실측 데이터 기반.

생성 차트:
  1. 학습 곡선 비교 (Gemma-2 LoRA vs Qwen QLoRA)
  2. 전체 벤치마크 비교 (9개 구성, 실측값)
  3. CWE 분포 (훈련 데이터 v4)
  4. 시스템 개발 로드맵
  5. 하이퍼파라미터 비교 표
"""

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
    "gemma":      "#E67E22",
    "qwen":       "#2980B9",
    "qwen_v4":    "#1ABC9C",
    "grok":       "#8E44AD",
    "rag_chroma": "#27AE60",
    "rag_qdrant": "#16A085",
    "qlora":      "#C0392B",
    "qlora_rag":  "#E74C3C",
    "eval":       "#E74C3C",
    "train":      "#3498DB",
}

# ── 1. 학습 곡선 ────────────────────────────────────────────────────────────────

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
qwen_v4_partial = [
    (10, 2.811), (20, 1.939), (30, 1.375),
]

fig, axes = plt.subplots(1, 2, figsize=(14, 5))
fig.suptitle("Learning Curves: Gemma-2 LoRA vs Qwen2.5 QLoRA", fontsize=14, fontweight="bold", y=1.02)

ax = axes[0]
gx, gy = zip(*gemma_loss)
ax.plot(gx, gy, color=COLORS["gemma"], lw=2, marker="o", ms=4, label="Gemma-2 2B LoRA (train)")
ax.set_title("Gemma-2 2B LoRA\n(203 samples · rank=16 · 5 epochs · 47.6min)", fontsize=10)
ax.set_xlabel("Training Step")
ax.set_ylabel("Loss")
ax.set_ylim(0, 3.2)
ax.axhline(0.692, color=COLORS["gemma"], ls="--", alpha=0.5, label="Final: 0.692")
ax.legend(fontsize=9)

ax = axes[1]
tx, ty = zip(*qwen_train)
ex, ey = zip(*qwen_eval)
v4x, v4y = zip(*qwen_v4_partial)
ax.plot(tx, ty, color=COLORS["qwen"], lw=2, marker="o", ms=4, label="Qwen QLoRA 1차 train")
ax.plot(ex, ey, color=COLORS["eval"], lw=2, marker="s", ms=5, ls="--", label="Qwen QLoRA 1차 eval")
ax.plot(v4x, v4y, color=COLORS["qwen_v4"], lw=2, marker="^", ms=6, ls="-.", label="Qwen QLoRA 2차 (in progress)")
ax.set_title("Qwen2.5-Coder-1.5B QLoRA\n(1차: 203 samples · 9.3min | 2차: 291 samples · rank=32)", fontsize=10)
ax.set_xlabel("Training Step")
ax.set_ylabel("Loss")
ax.set_ylim(0, 3.2)
ax.axhline(0.656, color=COLORS["qwen"], ls="--", alpha=0.5, label="1차 final train: 0.656")
ax.axhline(0.701, color=COLORS["eval"], ls=":", alpha=0.5, label="1차 final eval: 0.701")
ax.legend(fontsize=8)

plt.tight_layout()
out1 = OUT / "01_learning_curves.png"
plt.savefig(out1, bbox_inches="tight")
plt.close()
print(f"[chart] {out1}")

# ── 2. 벤치마크 비교 (실측값 전체) ───────────────────────────────────────────────

# 실측 데이터 (2026-05-26 측정)
models = [
    "Gemma:2b\n(BASE)",
    "Qwen2.5-Coder\n1.5B (BASE)",
    "Grok-3\n(API)",
    "RAG v1\n(Chroma+Grok)",
    "RAG v2\n(Qdrant+Grok)",
    "Qwen BASE\n+Qdrant RAG",
    "QLoRA 1차\n(no RAG)",
    "QLoRA 1차\n+Qdrant RAG",
]
detection = [90,  85,  95,  90,  100, 80,  5,   55]
latency   = [4.29, 1.16, 17.66, 3.85, 5.45, 1.48, 1.53, 3.89]

# 색상 그룹: base, grok, rag(grok), qwen시스템, qlora
bar_colors = [
    "#E67E22",  # Gemma base
    "#2980B9",  # Qwen base
    "#8E44AD",  # Grok-3
    "#27AE60",  # RAG v1
    "#16A085",  # RAG v2
    "#1ABC9C",  # Qwen base + RAG
    "#C0392B",  # QLoRA no RAG
    "#E74C3C",  # QLoRA + RAG
]

x = np.arange(len(models))
fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(15, 10))
fig.suptitle("ScanOps Benchmark — 전체 비교 (20개 테스트 케이스, 실측값)", fontsize=14, fontweight="bold")

# 탐지율
bars = ax1.bar(x, detection, color=bar_colors, alpha=0.85, width=0.6, edgecolor="white")
for bar, val in zip(bars, detection):
    ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.8,
             f"{val}%", ha="center", va="bottom", fontweight="bold", fontsize=10)
ax1.set_xticks(x)
ax1.set_xticklabels(models, fontsize=9)
ax1.set_ylabel("Vulnerability Detection Rate (%)")
ax1.set_title("Detection Rate by Model Configuration", fontsize=12)
ax1.set_ylim(0, 118)
ax1.axhline(100, color="red", ls="--", alpha=0.3, label="100% target")
ax1.legend()

# 지연시간
bars2 = ax2.bar(x, latency, color=bar_colors, alpha=0.85, width=0.6, edgecolor="white")
for bar, val in zip(bars2, latency):
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.15,
             f"{val}s", ha="center", va="bottom", fontweight="bold", fontsize=10)
ax2.set_xticks(x)
ax2.set_xticklabels(models, fontsize=9)
ax2.set_ylabel("Average Latency (seconds)")
ax2.set_title("Average Response Latency (lower is better)", fontsize=12)

# 범례
legend_patches = [
    mpatches.Patch(color="#E67E22", label="Base Models (Gemma/Qwen)"),
    mpatches.Patch(color="#8E44AD", label="Grok-3 API"),
    mpatches.Patch(color="#27AE60", label="RAG + Grok-3"),
    mpatches.Patch(color="#1ABC9C", label="Qwen BASE + Qdrant RAG"),
    mpatches.Patch(color="#C0392B", label="QLoRA Fine-tuned"),
    mpatches.Patch(color="#E74C3C", label="QLoRA Fine-tuned + RAG"),
]
ax2.legend(handles=legend_patches, fontsize=8, loc="upper right")

plt.tight_layout()
out2 = OUT / "02_benchmark_comparison.png"
plt.savefig(out2, bbox_inches="tight")
plt.close()
print(f"[chart] {out2}")

# ── 3. CWE 분포 (v4 훈련 데이터) ─────────────────────────────────────────────────

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
fig.suptitle("Training Data — lora_train_v4.jsonl (291 samples)", fontsize=13, fontweight="bold")

labels  = list(cwe_data.keys())
sizes   = list(cwe_data.values())
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

# ── 4. 시스템 개발 로드맵 ─────────────────────────────────────────────────────────

fig, ax = plt.subplots(figsize=(16, 6))
ax.set_xlim(0, 16)
ax.set_ylim(-1.5, 5)
ax.axis("off")
fig.patch.set_facecolor("#F8F9FA")

stages = [
    (1.2,  3.5, "Phase 1\nBase LLM\n(Qwen2.5-Coder\n1.5B)",         "#2980B9", "탐지: 85%\n응답: 1.16s"),
    (3.4,  3.5, "Phase 2\nGemma-2 LoRA\n(2B · rank=16\n203 samples)","#E67E22", "Train loss: 0.692\n47.6분"),
    (5.6,  3.5, "Phase 3\nQwen QLoRA 1차\n(1.5B · rank=16\n203 samples)","#8E44AD","Train loss: 0.656\nEval: 0.701 · 9.3분"),
    (7.8,  3.5, "Phase 4\nRAG 구축\n(Qdrant+BGE\n792 CVEs)",         "#27AE60", "Qwen+RAG: 80%\nGrok+RAG: 100%"),
    (10.0, 3.5, "Phase 5\nQwen QLoRA 2차\n(rank=32 · 291 samples\nclean format)", "#1ABC9C", "In Progress\n8 epochs"),
    (12.5, 3.5, "목표\nQLoRA + RAG\n(로컬 완전 자립)",              "#16A085", "QLoRA+RAG: 55%→↑\n(재훈련 완료 후)"),
]

for i, (x, y, label, color, note) in enumerate(stages):
    circle = plt.Circle((x, y), 0.55, color=color, zorder=3)
    ax.add_patch(circle)
    ax.text(x, y, str(i+1) if i < 5 else "★", ha="center", va="center", fontsize=12,
            fontweight="bold", color="white", zorder=4)
    ax.text(x, y - 1.2, label, ha="center", va="top", fontsize=7.5,
            fontweight="bold", multialignment="center")
    ax.text(x, y + 1.05, note, ha="center", va="bottom", fontsize=7,
            color="#555", multialignment="center",
            bbox=dict(boxstyle="round,pad=0.3", facecolor="white", edgecolor=color, alpha=0.7))
    if i < len(stages) - 1:
        ax.annotate("", xy=(stages[i+1][0] - 0.55, y), xytext=(x + 0.55, y),
                    arrowprops=dict(arrowstyle="->", color="#AAA", lw=1.5))

ax.set_title("ScanOps Development Roadmap", fontsize=14, fontweight="bold", pad=20)
plt.tight_layout()
out4 = OUT / "04_system_roadmap.png"
plt.savefig(out4, bbox_inches="tight")
plt.close()
print(f"[chart] {out4}")

# ── 5. 하이퍼파라미터 비교 표 ─────────────────────────────────────────────────────

fig, ax = plt.subplots(figsize=(14, 4.5))
ax.axis("off")

columns = ["Parameter", "TinyLlama LoRA", "Gemma-2 LoRA", "Qwen QLoRA 1차", "Qwen QLoRA 2차"]
rows = [
    ["Base Model",         "TinyLlama 1.1B",    "Gemma-2 2B-IT",       "Qwen2.5-Coder 1.5B",  "Qwen2.5-Coder 1.5B"],
    ["Training Method",    "LoRA",              "LoRA",                "QLoRA (MPS float16)", "QLoRA (MPS float16)"],
    ["LoRA Rank (r)",      "8",                 "16",                  "16",                  "32"],
    ["LoRA Alpha",         "16",                "32",                  "32",                  "64"],
    ["Target Modules",     "q,v",               "q,k,v,o",             "q,k,v,o",             "q,k,v,o"],
    ["Training Samples",   "~50",               "203",                 "203",                 "291"],
    ["Epochs",             "5",                 "5",                   "5",                   "8"],
    ["Learning Rate",      "2e-4",              "1e-4",                "1e-4",                "1e-4"],
    ["Grad Accum Steps",   "4",                 "8",                   "8",                   "8"],
    ["Max Seq Length",     "512",               "768",                 "768",                 "768"],
    ["Training Time",      "~15분",             "47.6분",              "9.3분",               "진행 중"],
    ["Final Train Loss",   "~1.05",             "0.692",               "0.656",               "TBD"],
    ["Final Eval Loss",    "N/A",               "N/A",                 "0.701",               "TBD"],
    ["Q4 GGUF Size",       "N/A",               "~1.6GB (배포 불가)",  "986MB ✓",             "변환 예정"],
]

cell_colors = [["#F0F4F8"] + ["white"] * 4 for _ in rows]

table = ax.table(
    cellText=rows,
    colLabels=columns,
    cellLoc="center",
    loc="center",
    cellColours=cell_colors,
)
table.auto_set_font_size(False)
table.set_fontsize(8.5)
table.scale(1, 1.4)

for j in range(len(columns)):
    table[0, j].set_facecolor("#2C3E50")
    table[0, j].set_text_props(color="white", fontweight="bold")

# 학습시간 행 강조 (수정된 값)
time_row_idx = next(i for i, r in enumerate(rows) if r[0] == "Training Time") + 1
table[time_row_idx, 3].set_facecolor("#FFF3CD")  # Qwen QLoRA 1차 학습시간 강조

ax.set_title("Hyperparameter Comparison Across All Models", fontsize=13, fontweight="bold", pad=20)
plt.tight_layout()
out5 = OUT / "05_hyperparameter_table.png"
plt.savefig(out5, bbox_inches="tight")
plt.close()
print(f"[chart] {out5}")

print("\n✅ All charts saved to:", OUT)
for f in sorted(OUT.glob("*.png")):
    print(f"  {f.name}")
