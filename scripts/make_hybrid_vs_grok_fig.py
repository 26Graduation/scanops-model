"""reports/figures/hybrid_vs_grok.png 재생성 — OWASP 110케이스 최신 수치.
실행:  .venv/bin/python scripts/make_hybrid_vs_grok_fig.py"""
import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager

BASE = Path(__file__).resolve().parents[1]
for f in ("AppleGothic", "Apple SD Gothic Neo", "NanumGothic", "Malgun Gothic"):
    if any(f in n for n in font_manager.fontManager.get_font_names()):
        plt.rcParams["font.family"] = f
        break
plt.rcParams["axes.unicode_minus"] = False

m = json.load(open(BASE / "reports" / "results_hybrid_owasp.json"))
H, G, L = m["hybrid_metrics"], m["grok_metrics"], m["llm_metrics"]
metrics = ["F1", "재현율", "정확도", "오탐률↓"]
llm = [L["f1"], L["recall"], L["accuracy"], L["fpr"]]
hyb = [H["f1"], H["recall"], H["accuracy"], H["fpr"]]
grok = [G["f1"], G["recall"], G["accuracy"], G["fpr"]]

import numpy as np
x = np.arange(len(metrics)); w = 0.26
fig, ax = plt.subplots(figsize=(8.2, 4.6))
b1 = ax.bar(x - w, llm, w, label="LLM(3B) 단독", color="#cbd5e1")
b2 = ax.bar(x, hyb, w, label="ScanOps 하이브리드(LLM+그래프)", color="#2563eb")
b3 = ax.bar(x + w, grok, w, label="Grok-3-mini (상용)", color="#f59e0b")
for bars in (b1, b2, b3):
    for b in bars:
        ax.annotate(f"{b.get_height():.1f}", (b.get_x()+b.get_width()/2, b.get_height()),
                    ha="center", va="bottom", fontsize=8)
ax.set_xticks(x); ax.set_xticklabels(metrics, fontsize=11)
ax.set_ylabel("점수 (%)"); ax.set_ylim(0, 100)
ax.set_title("OWASP Benchmark 110케이스 — 하이브리드가 Grok 전 지표 능가\n"
             "(재현율 81.8% vs 60.0%, F1 83.3 vs 62.9, 오탐률 14.5% vs 30.9%)", fontsize=11)
ax.legend(fontsize=9, loc="upper right")
ax.grid(axis="y", alpha=0.25)
fig.tight_layout()
out = BASE / "reports" / "figures" / "hybrid_vs_grok.png"
fig.savefig(out, dpi=150)
print("saved", out)
