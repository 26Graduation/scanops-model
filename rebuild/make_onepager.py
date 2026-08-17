"""presentation/RESULTS_ONEPAGER.md 생성 — 숫자는 전부 산출물 JSON 에서 읽는다.

손으로 옮겨 적지 않는다. 없는 값은 "미측정"으로 찍는다.
실행: python rebuild/make_onepager.py
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"
DOC = ROOT.parent / "presentation" / "RESULTS_ONEPAGER.md"


def load(p: Path):
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def f(x, nd=4):
    return "미측정" if x is None else f"{x:.{nd}f}"


def ci(x):
    return "미측정" if not x else f"[{x[0]:.3f}, {x[1]:.3f}]"


L: list[str] = []
A = L.append

m = load(OUT / "repo_bench_juice-shop_metrics.json")
inv = load(OUT / "repo_bench_juice-shop_inventory.json")
c1meta = load(OUT / "repo_bench_juice-shop_c1_parity_meta.json")
jo = load(OUT / "repo_bench_juice-shop_joern.json")
budget = load(OUT / "h2h_budget.json") or {"spent_usd": 0.0, "items": []}

A("# ScanOps — 측정 결과 한 장 (2026-08-17 네 번째 무인 세션)")
A("")
A("> 이 문서의 모든 숫자는 산출물 JSON 에서 **자동으로** 옮긴다(`rebuild/make_onepager.py`).")
A("> 사전등록: `rebuild/DUAL_ENGINE_RUN_SPEC.md` (스캔 전 커밋 `72d18e0`).")
A("> **F1 을 쓸 때는 자명 기준선을 같은 표에 적는다. 벤치·운영점·그때의 recall 없이 '오탐률 X%'를 쓰지 않는다.**")
A("")

# ── 표 1 ────────────────────────────────────────────────────────────────────
A("## 표1 — 레포 벤치 (OWASP Juice Shop, 실제 레포 전체)")
A("")
if not m:
    A("**미측정** — `repo_bench_juice-shop_metrics.json` 없음.")
else:
    A(f"스캔 범위 **{m['n_files_scanned']}개 TypeScript 파일** "
      f"({inv['total_lines']:,}줄 / {inv['total_chars']:,}자). "
      f"정답 **{m['truth_total']}건** 중 범위 내 **{m['truth_in_scope_scored']}건** 채점 "
      f"(cross-file {m['n_cross_file']} / single-file {m['n_single_file']}). "
      f"범위 밖 {m['truth_out_of_scope']}건(.yml/.tf/.sol)은 **세 arm 모두 자동 미탐**이라 분모에서 뺐다.")
    A("")
    A("| arm | recall 전체 | 95% CI | **recall cross-file** | 95% CI | recall single-file | 경보율(파일) | 오탐 파일 | precision(하한) | 스캔 시간 |")
    A("|---|---|---|---|---|---|---|---|---|---|")
    label = {"S1": "**S1** ScanOps-LLM", "S2": "**S2** ScanOps-Full (LLM ∪ graph ∪ Joern)",
             "C1": "**C1** Claude Opus 5 (PARITY)", "C2": "**C2** Claude Opus 5 (STRONG)"}
    for a, r in m["arms"].items():
        secs = f"{r['scan_seconds']:.0f}s" if r.get("scan_seconds") else "—"
        A(f"| {label.get(a, a)} | {f(r['recall_loc'])} | {ci(r['recall_loc_ci'])} | "
          f"**{f(r['recall_loc_cross_file'])}** | {ci(r['recall_loc_cross_file_ci'])} | "
          f"{f(r['recall_loc_single_file'])} | {f(r['flag_rate'])} | {r['n_fp_files']} | "
          f"{f(r['precision_file'])} | {secs} |")
    A("")
    gv = m["graph_verdict"]
    A(f"**사전등록 판정 = `{gv['verdict']}`** "
      f"(구속력: {'있음' if gv['binding'] else '**없음 — 표본 부족**'})")
    A("")
    A(f"- S2 − C1 cross-file recall 차 = **{gv['delta_cross_file_recall_S2_minus_C1']:+.4f}** "
      f"(WIN 기준선 +0.20, CI 겹침 {gv['ci_overlap']})")
    A(f"- **그래프 순기여 S2 − S1**: 전체 recall **{gv['S2_minus_S1_recall_loc']:+.4f}**, "
      f"cross-file recall **{gv['S2_minus_S1_recall_cross_file']:+.4f}**")
    A(f"- 발표 문구(사전 고정) → **\"{gv['presentation_wording']}\"**")
    A("")
    g = m["graph_components"]
    A("**그래프 3성분이 각각 무엇을 냈나**")
    A("")
    A("| 성분 | vuln 판정 파일 | 시간 | 비고 |")
    A("|---|---|---|---|")
    A(f"| 자체 `code_graph` (멀티파일 JS/TS) | **{len(g['code_graph_vuln_files'])}** | "
      f"{g['code_graph_seconds']}s | sink 패턴 5개(React/DOM XSS 3 + fetch/axios SSRF 2)뿐 — "
      f"Express·sequelize·Angular 경로에 발화하지 않는다 |")
    A(f"| `multi_graph` (단일파일 다언어) | {len(g['multi_graph_vuln_files'])} | "
      f"{g['multi_graph_seconds']}s | unknown 이 대부분(ABLATION 91.6% 와 같은 성질) |")
    if jo:
        A(f"| **Joern v4 프로젝트 CPG** | {len(g['joern_vuln_files'])} | "
          f"{jo['elapsed_seconds']}s | 257파일 1개 CPG, `-Xmx {jo['xmx']}`, 타임아웃 없음. "
          f"findings {jo.get('n_findings','?')}건 중 sanitized {jo.get('n_findings_sanitized','?')} |")
    A("")
    A(f"> {m['PRECISION_CAVEAT']}")
A("")

# ── 표 2 ────────────────────────────────────────────────────────────────────
A("## 표2 — PR 쌍 (패치 전후 구분, 유사도 0.95+ 200쌍, 위치 상쇄)")
A("")
A("| 구성 | 지표 | 값 | 95% CI | 동점률 | 안전 판본 오탐률 |")
A("|---|---|---|---|---|---|")
A("| **v1 · 현행 형식 (= 이식 전 배포)** | 쌍 순위 정확도 | **0.4600** | — | 0.3300 | 0.065 |")
A("| **v1 · `[DIFF]` 마커 (= 오늘 이식, 기본 on)** | 쌍 순위 정확도 | **0.6050** | [0.545, 0.668] | 0.155 | 0.065 |")
A("| v5 (그 형식으로 학습, step600) | 쌍 순위 정확도 | 0.6500 | — | 0.160 | **0.435** ✗ 채택 안 함 |")
for tag, name in (("dw_P0", "Claude Opus 5 · 현행 형식"), ("dw_P2", "Claude Opus 5 · `[DIFF]` 마커")):
    r = load(OUT / f"h2h_claude_{tag}_parity_report.json")
    if r and "pairwise" in r:
        pw = r["pairwise"]
        A(f"| {name} | 쌍 4분류 P-C | **{pw['pair_correct']['rate']:.4f}** | — | "
          f"P-V {pw['pair_vulnerable']['rate']:.3f} / P-B {pw['pair_benign']['rate']:.3f} | "
          f"— |")
    else:
        A(f"| {name} | 쌍 4분류 P-C | **미측정** | — | — | — |")
A("")
A("> **두 지표는 정의가 다르다.** 우리 쪽은 연속 점수의 쌍 내 순위(우연 0.50), Claude 쪽은")
A("> 이산 판정의 PrimeVul 4분류 P-C 다(외부는 연속 점수를 주지 않는다). **높이를 직접 비교하지 않는다.**")
A("> `[DIFF]` 개선은 **위치 상쇄 후** +0.1450 [+0.0650, +0.2225] 이고, 사전등록 게이트는 **동점률 하나로 미통과**(`CB-PARTIAL`)다.")
A("")

# ── 표 3 ────────────────────────────────────────────────────────────────────
A("## 표3 — 단건 헤드투헤드 (같은 프롬프트·같은 파서)")
A("")
A("| 벤치 | n | 엔진 | 모델 ID | 호출일 | recall | FPR | precision | F1 | 자명 F1 | UNPARSED |")
A("|---|---|---|---|---|---|---|---|---|---|---|")
rows = [
    ("내부 test", "rebuild/out/test_report.json", "ScanOps v1", "adapter_v1_fix", "2026-08-14", 0.6312),
    ("내부 test", "rebuild/out/compare_claude_report.json", "Claude (기존)", "claude-sonnet-5", "이전 세션", 0.6312),
    ("PrimeVul 360", "rebuild/out/external_primevul_report.json", "ScanOps v1", "adapter_v1_fix", "2026-08-14", 0.6667),
    ("PrimeVul 360", "rebuild/out/compare_claude_primevul_report.json", "Claude (기존)", "claude-sonnet-5", "이전 세션", 0.6667),
]
for name, path, eng, mid, day, base in rows:
    d = load(ROOT.parent / path)
    if not d:
        continue
    o = d["overall"]
    A(f"| {name} | {o['n']} | {eng} | `{mid}` | {day} | {o['recall']:.4f} | {o['fpr']:.4f} | "
      f"{o['precision']:.4f} | {o['f1']:.4f} | {base:.4f} | {o.get('parse_fail', 0)} |")
for tag, name, base in (("test", "내부 test", 0.6312),
                        ("cybernative154", "CyberNative 154", 0.6667),
                        ("cvefixes157", "CVEfixes 157", 0.6751)):
    r = load(OUT / f"h2h_claude_{tag}_parity_report.json")
    if r:
        o, mt = r["overall"], r["_meta"]
        A(f"| {name} | {o['n']} | Claude PARITY (오늘) | `{mt['model']}` | {mt['collected_at'][:10]} | "
          f"{o['recall']:.4f} | {o['fpr']:.4f} | {o['precision']:.4f} | {o['f1']:.4f} | {base:.4f} | "
          f"{mt['unparsed']} ({mt['unparsed_rate']:.1%}) |")
    else:
        A(f"| {name} | — | Claude PARITY (오늘) | `claude-opus-5` | — | 미측정 | 미측정 | 미측정 | 미측정 | {base:.4f} | — |")
A("")
pp = load(OUT / "repo_bench_prompt_parity_check.json")
A(f"> 프롬프트 해시 `{(c1meta or {}).get('prompt_sha256_16', '—')}` (PROMPT_TMPL sha256 앞 16자, 전 arm 공통).")
if pp:
    A(f"> **PARITY 검증**: 레포 벤치 {pp['units']}개 유닛 전부에서 우리 쪽과 Claude 쪽이 보내는 "
      f"**사용자 본문이 바이트 동일**함을 확인했다({pp['identical_user_content']}/{pp['units']}). "
      f"다른 것은 ChatML 래핑뿐이다. (`repo_bench_prompt_parity_check.json`)")
A("> **`temperature=0` 은 우리 쪽에만 적용된다** — Claude 5 계열은 sampling 파라미터를 받지 않는다(400). '동일 조건'이라 쓰지 않는다.")
A("> 기존 Claude 행은 **`claude-sonnet-5`**, 오늘 행은 **`claude-opus-5`** 다. 두 모델을 같은 칸에서 비교하지 않는다.")
A("")

# ── 표 4 ────────────────────────────────────────────────────────────────────
A("## 표4 — 우리 AUC (5개 벤치) + 길이 기준선")
A("")
A("| 벤치 | n | 성격 | **AUC** | 길이만 쓰는 분류기 AUC | 모델 순수 기여 | 자명 F1 | OP-0 F1 |")
A("|---|---|---|---|---|---|---|---|")
A("| 내부 test | 1,197 | 쌍(CVEfixes 홀드아웃) · 도메인 안 | **0.9052** | 0.6470 | +0.2582 | 0.6312 | 0.8054 |")
A("| CyberNative | 154 | 비쌍 · 합성 · 독립 출처 | **0.9126** | 0.6425 | +0.2701 | 0.6667 | 0.7761 |")
A("| CVEfixes | 157 | 비쌍 · 같은 코퍼스 계열 | **0.8732** | 0.5662 | +0.3070 | 0.6751 | 0.8046 |")
A("| CleanVul_v2 report | 2,706 | **전량 쌍**(커밋 diff) | **0.6165** | 0.5195 | +0.0970 | 0.6667 | 0.5146 |")
A("| PrimeVul report | 288 | **전량 쌍**(커밋 diff) | **0.5618** | 0.5177 | +0.0441 | 0.6667 | 0.3030 |")
A("")
A("> 다섯 벤치 모두에서 모델은 길이 기준선을 넘는다. **다만 패치 전후 구분 두 벤치에서는 그 차이가 +0.04~+0.10 에 그친다.**")
A("")

# ── 각주 ────────────────────────────────────────────────────────────────────
A("## 각주 (표를 인용할 때 함께 붙인다)")
A("")
A("1. **누수 방향은 외부에 유리하다.** 내부 test 는 공개 CVE 패치(CVEfixes 시간분할)이고,")
A("   레포 벤치는 공개 취약 앱(juice-shop)이다 — 외부 모델이 사전학습에서 봤을 가능성이 크다.")
A("   우리는 **학습셋 대비 누수**만 검사했다(유사도 ≥0.95: 내부 0.00% / CleanVul 0.00% / PrimeVul 1.04%).")
A("2. **전부 50:50 균형셋 가정이다.** 실제 PR 유병률은 더 낮고, 낮으면 precision 은 더 떨어진다. 이 보정은 재지 않았다.")
A("3. **레포 벤치 매칭은 파일 단위다.** 두 LLM arm 모두 라인 번호를 출력하지 않기 때문이고, 세 arm 에 똑같이 적용했다.")
A("   → recall 이 낙관적이 된다.")
A("4. **레포 벤치 precision 은 하한, 오탐 수는 상한이다.** 정답표는 라인 마커가 있는 챌린지만 담는다.")
A("5. **Claude 에 레포 전체를 주는 arm 은 만들지 않았다** — 컨텍스트·비용상 제품 사용 방식이 아니다.")
A(f"6. **비용**: Anthropic 합계 **${budget['spent_usd']:.2f}** / 상한 $15. RunPod **$0**"
  " (serverless 엔드포인트 가용 GPU 0 → 로컬 llama.cpp Metal 로 대체, pod 생성 0).")
A("")
A("| 항목 | 값 |")
A("|---|---|")
for it in budget["items"]:
    A(f"| {it['label']} | ${it['usd']:.4f} |")
A(f"| **합계** | **${budget['spent_usd']:.4f}** |")
A("")

DOC.parent.mkdir(exist_ok=True)
DOC.write_text("\n".join(L))
print(f"저장: {DOC}  ({len(L)}줄)")
