"""FINAL_ARCHITECTURE_REPORT.md 에 §3-6(레포 벤치)과 §-1 STATUS 를 갱신한다.

기존 절은 건드리지 않고 **새 절을 덧붙인다**(읽기 전용 규율).
숫자는 산출물 JSON 에서 읽는다.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"
DOC = ROOT.parent / "FINAL_ARCHITECTURE_REPORT.md"


def load(p: Path):
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None


m = load(OUT / "repo_bench_juice-shop_metrics.json")
inv = load(OUT / "repo_bench_juice-shop_inventory.json")
jo = load(OUT / "repo_bench_juice-shop_joern.json")
fa = load(OUT / "repo_bench_juice-shop_failures.json")
bud = load(OUT / "h2h_budget.json") or {"spent_usd": 0.0}
if not (m and inv):
    raise SystemExit("metrics/inventory 없음 — 먼저 repo_bench_score.py 를 돌려라")

gv = m["graph_verdict"]
g = m["graph_components"]
A = m["arms"]


def row(a, name):
    r = A.get(a)
    if not r:
        return f"| {name} | 미측정 | | | | | |"
    return (f"| {name} | {r['recall_loc']:.4f} | [{r['recall_loc_ci'][0]:.3f}, {r['recall_loc_ci'][1]:.3f}] "
            f"| **{(r['recall_loc_cross_file'] or 0):.4f}** | {(r['recall_loc_single_file'] or 0):.4f} "
            f"| {r['flag_rate']:.4f} | {r['n_fp_files']} |")


sec = f"""

---

## §3-6 **레포 단위 벤치** — 멀티파일 주장을 실제 레포에서 잰다 (2026-08-17 네 번째 세션 신설)

> 사전등록: `rebuild/DUAL_ENGINE_RUN_SPEC.md` §6 (**스캔 전** 커밋 `72d18e0`).
> 결정 로그: `rebuild/out/SESSION_DECISIONS_20260817D.md` D-32~D-41.
> 산출: `rebuild/out/repo_bench_juice-shop_{{metrics,graph,joern,failures}}.json`,
> 정답표 `rebuild/data/repo_bench/juice-shop_truth.jsonl`.

### 왜 이 벤치가 필요했나

§3-1~§3-4 는 전부 **함수·스니펫 단위** 벤치다. 사업계획서 3.3 의
"**멀티파일 코드그래프 추적**" 주장은 그 벤치들로는 검정되지 않는다.
그래서 **실제 레포 전체**를 세 arm 으로 돌렸다.

### 재료

| 항목 | 값 |
|---|---|
| 레포 | OWASP Juice Shop `{inv.get('repo','juice-shop')}` @ `1618a611` (2026-08-10) |
| 스캔 범위 | `routes/**` + `lib/**` + `models/**` + `server.ts` + `app.ts` + `frontend/src/app/**` (`*.spec.ts` 제외) |
| 파일 | **{m['n_files_scanned']}개** TypeScript ({inv['total_lines']:,}줄 / {inv['total_chars']:,}자) |
| 정답표 | **{m['truth_total']}건** — 소스 안의 `// vuln-code-snippet vuln-line <key>` 마커 (레포 자신이 코딩 챌린지 정답 판정에 쓰는 값, `lib/codingChallenges.ts:76`) → confidence **high** |
| 채점 대상 | 범위 내 **{m['truth_in_scope_scored']}건** (cross-file {m['n_cross_file']} / single-file {m['n_single_file']}). 범위 밖 {m['truth_out_of_scope']}건(.yml/.tf/.sol)은 **세 arm 모두 자동 미탐** |
| 매칭 단위 | **파일** — LLM arm 두 개가 라인을 출력하지 않기 때문(사양 §11 S-1, 측정 전 기록) |

### 결과 (사전등록 판정 포함)

| arm | recall 전체 | 95% CI | **recall cross-file** | recall single-file | 경보율(파일) | 오탐 파일 |
|---|---|---|---|---|---|---|
{row('S1', '**S1** ScanOps-LLM')}
{row('S2', '**S2** ScanOps-Full (LLM ∪ graph ∪ Joern)')}
{row('C1', '**C1** Claude Opus 5 (PARITY, 파일 단위)')}
{row('C2', '**C2** Claude Opus 5 (STRONG)')}

### 판정 = **`{gv['verdict']}`** (구속력 {'있음' if gv['binding'] else '**없음 — 표본 부족**'})

- S2 − C1 cross-file recall = **{gv['delta_cross_file_recall_S2_minus_C1']:+.4f}** (WIN 기준선 +0.20)
- **그래프 순기여 S2 − S1**: 전체 **{gv['S2_minus_S1_recall_loc']:+.4f}** / cross-file **{gv['S2_minus_S1_recall_cross_file']:+.4f}**
- 사전 고정 발표 문구 → **"{gv['presentation_wording']}"** (결과를 보고 바꾸지 않았다)
- **표본 부족**: 범위 내 정답 {m['truth_in_scope_scored']}건 < 사전등록 최소 40건 (cross-file {m['n_cross_file']} ≥ 12 은 통과)

### 그래프 3성분이 각각 무엇을 냈나 — **가장 중요한 음성 결과**

| 성분 | vuln 판정 파일 | 시간 |
|---|---|---|
| 자체 `code_graph` (**멀티파일** JS/TS) | **{len(g['code_graph_vuln_files'])}** | {g['code_graph_seconds']}s |
| `multi_graph` (단일파일 다언어) | {len(g['multi_graph_vuln_files'])} | {g['multi_graph_seconds']}s |
| **Joern v4 프로젝트 CPG** | {len(g['joern_vuln_files'])} | {jo['elapsed_seconds'] if jo else '—'}s |

**자체 멀티파일 코드그래프는 이 레포에서 `vuln` 을 한 건도 내지 않았다.**
원인은 측정으로 특정된다 — `_extract_sinks` 의 sink 패턴이 **5개**뿐이다
(React/DOM XSS 3: `img src=`·`dangerouslySetInnerHTML`·`innerHTML`, SSRF 2: `fetch`·`axios`).
juice-shop 은 Express + sequelize + Angular 이라 이 패턴들이 발화하지 않는다.
증거 자체는 3행 나왔고 **전부 `unknown`** 이었다("Could not prove whether … is user-controlled").

**Joern 프로젝트 CPG 는 되는 것으로 확인됐다**: {m['n_files_scanned']}파일을
{jo['elapsed_seconds'] if jo else '—'}초에 CPG 1개로 올렸고(`-Xmx {jo['xmx'] if jo else '—'}`, 타임아웃 없음),
`JavaScriptImportResolverPass` 가 11,130건을 커밋했다 = **파일 간 import 가 실제로 해결됐다.**
다만 findings {jo.get('n_findings','?') if jo else '?'}건 중 {jo.get('n_findings_sanitized','?') if jo else '?'}건이
sanitizer 로 제외됐고, 남은 것도 카테고리가 `ssrf` 에 크게 쏠려 있다.

### 반드시 함께 읽을 것

1. **precision 과 오탐 수를 절대값으로 읽지 않는다.** 정답표는 라인 마커가 있는 챌린지만 담는다(9개 파일).
   juice-shop 은 의도적으로 취약한 앱이므로 **오탐 수는 상한, precision 은 하한**이다.
   해석 가능한 것은 (a) 같은 정답표로 잰 recall, (b) arm 간 상대 경보율뿐이다.
2. **매칭이 파일 단위라 recall 이 낙관적이다.** 세 arm 에 똑같이 적용했다.
3. **누수 방향은 외부에 유리하다.** juice-shop 은 공개 취약 앱이다.
4. **`temperature=0` 은 우리 쪽에만 적용된다** — Claude 5 계열은 sampling 파라미터를 받지 않는다(400).

### 실패 분석 (B-5)

{('| 원인 | 건수 |' + chr(10) + '|---|---|' + chr(10) + chr(10).join(f'| {k} | {v} |' for k, v in fa['cause_counts'].items()) + chr(10) + chr(10) + f"S2 가 놓친 정답 **{fa['n_missed_total']}건**(그중 cross-file {fa['n_missed_cross_file']}건). 전체 목록은 `repo_bench_juice-shop_failures.json`.") if fa else '미측정'}

### 비용

Anthropic **${bud['spent_usd']:.2f}** / 상한 $15. **RunPod $0** —
serverless 엔드포인트 가용 GPU 0(`throttled 2 / ready 0`)이라 **로컬 llama.cpp Metal** 로 대체했다(D-32).
pod 생성 0.
"""

txt = DOC.read_text()
if "## §3-6" in txt:
    txt = re.sub(r"\n---\n\n## §3-6.*?(?=\n---\n\n## |\Z)", "", txt, flags=re.S)
DOC.write_text(txt.rstrip() + "\n" + sec)
print(f"§3-6 갱신: {DOC}")
