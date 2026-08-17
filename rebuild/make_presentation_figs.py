"""발표용 그림 4장 (PNG). 라벨은 영문 — 한글 폰트 폴백을 피한다(사양 §9).

palette: dataviz 기준 팔레트에서 4슬롯을 뽑아 validator 통과를 확인했다
  #2a78d6(blue) #eb6834(orange) #1baf7a(aqua) #eda100(yellow)
  → CVD 최악 인접쌍 ΔE 9.1(protan) / 22.9(normal), 대비 WARN 은 **직접 라벨**로 해소한다.

규약(적용한 것):
  - 축은 하나. 이중 축 없음.
  - 막대는 직접 라벨을 단다(대비 WARN 해소 조건).
  - 그리드는 후퇴색 hairline, 값 텍스트는 잉크색(시리즈 색을 글자에 쓰지 않는다).
  - 자명 기준선은 회색 점선으로 같은 축에 병기한다.

실행: python rebuild/make_presentation_figs.py
출력: presentation/fig1..fig4 *.png
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"
FIG = ROOT.parent / "presentation"
FIG.mkdir(exist_ok=True)

C = {"S1": "#2a78d6", "S2": "#1baf7a", "C1": "#eb6834", "C2": "#eda100",
     "ours": "#2a78d6", "claude": "#eb6834"}
INK, INK2, MUTED, GRID, BASE = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7"
SURF = "#fcfcfb"

plt.rcParams.update({
    "figure.facecolor": SURF, "axes.facecolor": SURF,
    "axes.edgecolor": BASE, "axes.labelcolor": INK2,
    "text.color": INK, "xtick.color": MUTED, "ytick.color": MUTED,
    "font.size": 10, "axes.grid": True, "grid.color": GRID,
    "grid.linewidth": 0.8, "axes.axisbelow": True,
    "axes.spines.top": False, "axes.spines.right": False,
})


def load(p: Path):
    return json.loads(p.read_text()) if p.exists() else None


def bar_labels(ax, bars, fmt="{:.2f}", dy=0.012):
    for b in bars:
        h = b.get_height()
        ax.text(b.get_x() + b.get_width() / 2, h + dy, fmt.format(h),
                ha="center", va="bottom", fontsize=9, color=INK)


# ── 그림 1: 레포 벤치 recall (전체 / cross-file / single-file) ───────────────
def fig1():
    m = load(OUT / "repo_bench_juice-shop_metrics.json")
    if not m:
        print("fig1 skip: metrics 없음")
        return
    arms = [a for a in ("S1", "S2", "C1", "C2") if a in m["arms"]]
    groups = [("All in-scope", "recall_loc"),
              ("Cross-file", "recall_loc_cross_file"),
              ("Single-file", "recall_loc_single_file")]
    fig, ax = plt.subplots(figsize=(7.6, 4.0))
    w = 0.8 / len(arms)
    for i, a in enumerate(arms):
        vals = [(m["arms"][a][k] or 0) for _, k in groups]
        xs = [j + (i - (len(arms) - 1) / 2) * w for j in range(len(groups))]
        bars = ax.bar(xs, vals, width=w * 0.9, color=C[a],
                      label=f"{a} {'ScanOps' if a.startswith('S') else 'Claude'}")
        bar_labels(ax, bars)
    n = m["truth_in_scope_scored"]
    ax.set_xticks(range(len(groups)))
    ax.set_xticklabels([f"{g}\n(n={n if k=='recall_loc' else (m['n_cross_file'] if 'cross' in k else m['n_single_file'])})"
                        for g, k in groups])
    ax.set_ylim(0, 1.15)
    ax.set_ylabel("Recall (file-level match)")
    ax.set_title("Repo benchmark — OWASP Juice Shop, 257 TS files, 33 annotated findings",
                 color=INK, fontsize=11, pad=12)
    ax.legend(frameon=False, ncol=len(arms), loc="upper center",
              bbox_to_anchor=(0.5, -0.16))
    fig.text(0.5, -0.02,
             "Ground truth = in-repo `vuln-code-snippet vuln-line` markers, committed before any scan.",
             ha="center", fontsize=8, color=MUTED)
    fig.tight_layout()
    fig.savefig(FIG / "fig1_repo_recall.png", dpi=200, bbox_inches="tight")
    print("fig1 저장")


# ── 그림 2: PR 쌍 P0 → P2 ────────────────────────────────────────────────────
def fig2():
    # v1 값은 DIFF_AWARE_RESULTS.md §6-1 (위치 상쇄 acc_cb)
    ours = {"P0 (current)": 0.4600, "P2 ([DIFF] marker)": 0.6050}
    cl = {}
    for tag, key in (("P0 (current)", "dw_P0"), ("P2 ([DIFF] marker)", "dw_P2")):
        r = load(OUT / f"h2h_claude_{key}_parity_report.json")
        if r and "pairwise" in r:
            cl[tag] = r["pairwise"]["pair_correct"]["rate"]
    fig, ax = plt.subplots(figsize=(6.8, 4.0))
    xs = range(2)
    b1 = ax.bar([x - 0.19 for x in xs], list(ours.values()), width=0.34,
                color=C["ours"], label="ScanOps v1 — pair rank acc (position-balanced)")
    bar_labels(ax, b1)
    if cl:
        b2 = ax.bar([x + 0.19 for x in xs], [cl.get(k, 0) for k in ours], width=0.34,
                    color=C["claude"], label="Claude Opus 5 — pair-correct rate (discrete)")
        bar_labels(ax, b2)
    ax.axhline(0.50, color=MUTED, ls="--", lw=1)
    ax.text(1.42, 0.512, "chance 0.50", fontsize=8, color=MUTED, ha="right")
    ax.set_xticks(list(xs))
    ax.set_xticklabels(list(ours))
    ax.set_ylim(0, 1.0)
    ax.set_ylabel("Pair discrimination")
    ax.set_title("Patch-vs-vulnerable pair task (similarity ≥ 0.95, 200 pairs)",
                 color=INK, fontsize=11, pad=12)
    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.16), fontsize=8)
    fig.text(0.5, -0.03,
             "Two different metrics on the same 200 pairs — not directly comparable heights; read each series separately.",
             ha="center", fontsize=8, color=MUTED)
    fig.tight_layout()
    fig.savefig(FIG / "fig2_pr_pairs.png", dpi=200, bbox_inches="tight")
    print("fig2 저장")


# ── 그림 3: recall vs FPR 산점 (단건 벤치) ───────────────────────────────────
def fig3():
    pts = []
    v1 = {"internal test 1197": (0.7971, 0.1566)}
    for name, f in (("internal test 1197", "h2h_claude_test_parity_report.json"),
                    ("CyberNative 154", "h2h_claude_cybernative154_parity_report.json"),
                    ("CVEfixes 157", "h2h_claude_cvefixes157_parity_report.json")):
        r = load(OUT / f)
        if r:
            pts.append((name, r["overall"]["recall"], r["overall"]["fpr"], "claude"))
    for name, (rc, fp) in v1.items():
        pts.append((name, rc, fp, "ours"))
    # v1 CyberNative/CVEfixes 는 oppoint_op_v1.json OP-0 에서
    op = load(OUT / "oppoint_op_v1.json")
    if op:
        for bench, label in (("cybernative154", "CyberNative 154"),
                             ("cvefixes157", "CVEfixes 157")):
            try:
                row = op[bench]["OP-0"]
                pts.append((label, row["recall"], row["fpr"], "ours"))
            except (KeyError, TypeError):
                pass
    if not pts:
        print("fig3 skip")
        return
    fig, ax = plt.subplots(figsize=(6.4, 4.4))
    for who, lab in (("ours", "ScanOps v1 (τ=0, deployed)"),
                     ("claude", "Claude Opus 5 (PARITY)")):
        xs = [p[2] for p in pts if p[3] == who]
        ys = [p[1] for p in pts if p[3] == who]
        ax.scatter(xs, ys, s=90, color=C[who], label=lab, zorder=3,
                   edgecolors=SURF, linewidths=2)
        for p in [p for p in pts if p[3] == who]:
            ax.annotate(p[0], (p[2], p[1]), textcoords="offset points",
                        xytext=(7, -3), fontsize=8, color=INK2)
    ax.plot([0, 1], [0, 1], color=MUTED, ls="--", lw=1)
    ax.text(0.72, 0.68, "chance", fontsize=8, color=MUTED, rotation=32)
    ax.set_xlim(-0.03, 1.0)
    ax.set_ylim(0, 1.05)
    ax.set_xlabel("False-positive rate (lower is better) →")
    ax.set_ylabel("Recall ↑")
    ax.set_title("Single-snippet benchmarks — recall vs false alarms",
                 color=INK, fontsize=11, pad=12)
    ax.legend(frameon=False, loc="lower right", fontsize=9)
    fig.tight_layout()
    fig.savefig(FIG / "fig3_recall_fpr.png", dpi=200, bbox_inches="tight")
    print("fig3 저장")


# ── 그림 4: 벤치별 F1 + 자명 기준선 ─────────────────────────────────────────
def fig4():
    rows = [
        ("internal test\n1197", 0.8051, 0.6312),
        ("CyberNative\n154", 0.7761, 0.6667),
        ("CVEfixes\n157", 0.8046, 0.6751),
        ("CleanVul_v2\n2706", 0.5146, 0.6667),
        ("PrimeVul\n288", 0.3030, 0.6667),
    ]
    fig, ax = plt.subplots(figsize=(7.4, 4.0))
    xs = range(len(rows))
    bars = ax.bar(xs, [r[1] for r in rows], width=0.55, color=C["ours"],
                  label="ScanOps v1 F1 (OP-0)")
    bar_labels(ax, bars)
    for i, r in enumerate(rows):
        ax.plot([i - 0.32, i + 0.32], [r[2], r[2]], color=MUTED, ls="--", lw=1.6,
                zorder=4)
        ax.text(i + 0.34, r[2], f"{r[2]:.3f}", fontsize=8, color=MUTED, va="center")
    ax.plot([], [], color=MUTED, ls="--", lw=1.6, label="trivial baseline (all-vuln) F1")
    ax.set_xticks(list(xs))
    ax.set_xticklabels([r[0] for r in rows])
    ax.set_ylim(0, 1.0)
    ax.set_ylabel("F1")
    ax.set_title("F1 always shown next to its trivial baseline", color=INK,
                 fontsize=11, pad=12)
    ax.legend(frameon=False, loc="upper right", fontsize=9)
    fig.text(0.5, -0.03,
             "The two commit-pair benchmarks (CleanVul_v2, PrimeVul) stay below the trivial baseline at every operating point.",
             ha="center", fontsize=8, color=MUTED)
    fig.tight_layout()
    fig.savefig(FIG / "fig4_f1_baseline.png", dpi=200, bbox_inches="tight")
    print("fig4 저장")


if __name__ == "__main__":
    fig1(); fig2(); fig3(); fig4()
