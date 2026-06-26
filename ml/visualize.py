"""
ScanOps 보안 모델 — 학습/평가 시각화
================================================================
ML 보고서에 넣을 그림들을 생성한다:
  1. 학습곡선 (train/eval loss vs step)       — 수렴·과적합 진단
  2. 혼동행렬 (TP/FN/FP/TN 히트맵)             — 분류 성능 한눈에
  3. 지표 막대 (F1/정밀도/재현율/오탐률/정확도) — ScanOps vs Grok
  4. 카테고리별 정확도                          — 어떤 취약점에 강/약한지
  5. 모델 버전 추이 (v4→v8 오탐률·재현율 개선)  — 반복 학습 효과

실행:
  python -m ml.visualize --tag v8                 # 단일 모델 그림
  python -m ml.visualize --tag v8 --compare-versions  # 버전 추이 포함
출력:
  reports/figures/*.png
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from ml.config import MODELS_DIR, REPORTS_DIR

FIG_DIR = REPORTS_DIR / "figures"
plt.rcParams["font.family"] = ["AppleGothic", "NanumGothic", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False


def _load(path: Path) -> dict | list | None:
    return json.loads(path.read_text()) if path.exists() else None


# ── 1. 학습곡선 ──────────────────────────────────────────────────────────────
def plot_learning_curve(tag: str) -> Path | None:
    log = _load(MODELS_DIR / f"qwen-security-qlora-{tag}" / "train_loss.json")
    if not log:
        print(f"[viz] {tag} 학습로그 없음 — 학습곡선 건너뜀")
        return None
    tr = [(e["step"], e["loss"]) for e in log if e.get("loss") is not None]
    ev = [(e["step"], e["eval_loss"]) for e in log if e.get("eval_loss") is not None]
    fig, ax = plt.subplots(figsize=(7, 4.2), facecolor="white")
    if tr:
        ax.plot(*zip(*tr), "-o", ms=3, color="#2980B9", label="train loss")
    if ev:
        ax.plot(*zip(*ev), "-s", ms=6, color="#E74C3C", label="eval loss")
    ax.set_xlabel("step"); ax.set_ylabel("cross-entropy loss")
    ax.set_title(f"학습곡선 — QLoRA {tag} (낮을수록 수렴)", fontweight="bold")
    ax.grid(True, ls="--", alpha=0.4); ax.legend()
    out = FIG_DIR / f"learning_curve_{tag}.png"
    fig.tight_layout(); fig.savefig(out, dpi=150); plt.close(fig)
    print(f"[viz] {out}")
    return out


# ── 2. 혼동행렬 ──────────────────────────────────────────────────────────────
def plot_confusion(tag: str) -> Path | None:
    ev = _load(REPORTS_DIR / f"eval_owasp_{tag}.json")
    if not ev:
        print(f"[viz] {tag} 평가결과 없음 — 혼동행렬 건너뜀")
        return None
    systems = [("ScanOps " + tag, ev["scanops"]["metrics"]["confusion_matrix"])]
    if ev.get("grok"):
        systems.append(("Grok-3-mini", ev["grok"]["metrics"]["confusion_matrix"]))
    fig, axes = plt.subplots(1, len(systems), figsize=(5 * len(systems), 4.2), facecolor="white")
    if len(systems) == 1:
        axes = [axes]
    for ax, (name, cm) in zip(axes, systems):
        mat = np.array([[cm["tp"], cm["fn"]], [cm["fp"], cm["tn"]]])
        ax.imshow(mat, cmap="Blues")
        for (i, j), v in np.ndenumerate(mat):
            ax.text(j, i, str(v), ha="center", va="center", fontsize=16, fontweight="bold",
                    color="white" if v > mat.max() / 2 else "black")
        ax.set_xticks([0, 1]); ax.set_xticklabels(["취약 예측", "안전 예측"])
        ax.set_yticks([0, 1]); ax.set_yticklabels(["실제 취약", "실제 안전"])
        ax.set_title(f"{name}\n혼동행렬", fontweight="bold")
    out = FIG_DIR / f"confusion_{tag}.png"
    fig.tight_layout(); fig.savefig(out, dpi=150); plt.close(fig)
    print(f"[viz] {out}")
    return out


# ── 3. 지표 막대 (ScanOps vs Grok) ───────────────────────────────────────────
def plot_metrics_bar(tag: str) -> Path | None:
    ev = _load(REPORTS_DIR / f"eval_owasp_{tag}.json")
    if not ev:
        return None
    labels = ["F1", "정밀도", "재현율", "정확도", "CWE정확"]
    keys = ["f1", "precision", "recall", "accuracy", "cwe_category_accuracy"]
    so = [ev["scanops"]["metrics"][k] for k in keys]
    fig, ax = plt.subplots(figsize=(8, 4.2), facecolor="white")
    x = np.arange(len(labels)); w = 0.38
    ax.bar(x - w / 2, so, w, label=f"ScanOps {tag}", color="#27AE60", zorder=3)
    if ev.get("grok"):
        gk = [ev["grok"]["metrics"][k] for k in keys]
        ax.bar(x + w / 2, gk, w, label="Grok-3-mini", color="#3498DB", zorder=3)
    # 오탐률은 별도(낮을수록 좋음)로 텍스트 표기
    so_fpr = ev["scanops"]["metrics"]["false_positive_rate"]
    note = f"오탐률(FPR, 낮을수록↑): ScanOps {so_fpr}%"
    if ev.get("grok"):
        note += f" / Grok {ev['grok']['metrics']['false_positive_rate']}%"
    ax.set_xticks(x); ax.set_xticklabels(labels); ax.set_ylim(0, 105)
    ax.set_ylabel("%"); ax.set_title(f"분류 지표 — OWASP 외부 벤치마크\n{note}", fontweight="bold", fontsize=11)
    ax.grid(True, axis="y", ls="--", alpha=0.4); ax.legend()
    out = FIG_DIR / f"metrics_{tag}.png"
    fig.tight_layout(); fig.savefig(out, dpi=150); plt.close(fig)
    print(f"[viz] {out}")
    return out


# ── 4. 카테고리별 정확도 ─────────────────────────────────────────────────────
def plot_by_category(tag: str) -> Path | None:
    ev = _load(REPORTS_DIR / f"eval_owasp_{tag}.json")
    if not ev:
        return None
    bc = ev["scanops"]["by_category"]
    cats = sorted(bc)
    so = [bc[c]["accuracy"] for c in cats]
    fig, ax = plt.subplots(figsize=(9, 4.2), facecolor="white")
    x = np.arange(len(cats)); w = 0.38
    ax.bar(x - w / 2, so, w, label=f"ScanOps {tag}", color="#27AE60", zorder=3)
    if ev.get("grok"):
        gbc = ev["grok"]["by_category"]
        ax.bar(x + w / 2, [gbc[c]["accuracy"] for c in cats], w, label="Grok-3-mini", color="#3498DB", zorder=3)
    ax.set_xticks(x); ax.set_xticklabels(cats, rotation=30, ha="right", fontsize=8)
    ax.set_ylim(0, 105); ax.set_ylabel("정확도 %")
    ax.set_title(f"취약점 카테고리별 정확도 — {tag}", fontweight="bold")
    ax.grid(True, axis="y", ls="--", alpha=0.4); ax.legend()
    out = FIG_DIR / f"by_category_{tag}.png"
    fig.tight_layout(); fig.savefig(out, dpi=150); plt.close(fig)
    print(f"[viz] {out}")
    return out


# ── 5. 모델 버전 추이 ────────────────────────────────────────────────────────
def plot_version_trend() -> Path | None:
    pts = []
    for tag in ["v4", "v5", "v6", "v7", "v8"]:
        ev = _load(REPORTS_DIR / f"eval_owasp_{tag}.json")
        if ev:
            m = ev["scanops"]["metrics"]
            pts.append((tag, m["recall"], m["false_positive_rate"], m["f1"]))
    if len(pts) < 2:
        print("[viz] 버전별 평가결과 2개 미만 — 추이 그래프 건너뜀")
        return None
    tags = [p[0] for p in pts]
    fig, ax = plt.subplots(figsize=(8, 4.2), facecolor="white")
    ax.plot(tags, [p[1] for p in pts], "-o", color="#27AE60", label="재현율(탐지율)")
    ax.plot(tags, [p[2] for p in pts], "-s", color="#E74C3C", label="오탐률(FPR, 낮을수록↑)")
    ax.plot(tags, [p[3] for p in pts], "-^", color="#2980B9", label="F1")
    ax.set_ylim(0, 105); ax.set_ylabel("%")
    ax.set_title("모델 버전별 성능 추이 (반복 학습 효과)", fontweight="bold")
    ax.grid(True, ls="--", alpha=0.4); ax.legend()
    out = FIG_DIR / "version_trend.png"
    fig.tight_layout(); fig.savefig(out, dpi=150); plt.close(fig)
    print(f"[viz] {out}")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True)
    ap.add_argument("--compare-versions", action="store_true")
    args = ap.parse_args()
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    plot_learning_curve(args.tag)
    plot_confusion(args.tag)
    plot_metrics_bar(args.tag)
    plot_by_category(args.tag)
    if args.compare_versions:
        plot_version_trend()
    print("[viz] 완료 — reports/figures/")


if __name__ == "__main__":
    main()
