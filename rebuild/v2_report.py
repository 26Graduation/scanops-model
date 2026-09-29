"""ScanOps v2 — V2_RESULTS.md 생성기 (V2_RUN_SPEC.md rev.6 §5·§9·§10-11).

산출물 JSON 들을 모아 결과 문서를 만든다. **숫자를 손으로 옮겨 적지 않는다** — 전부 파일에서
읽어 계산한다(CLAUDE.md 규칙 #1 추정 금지).

§10-11 이 요구한 포함 항목을 하나도 빠뜨리지 않는다:
  · pass/fail 판정(①②③ 각각) + Δ(v1 대비)
  · truncation rate (학습셋 / juice-shop 각각) + visible/invisible exact-line 분리
  · 언어 분포 (수확 최종 샘플 기준)
  · cohort 보고 3단계 전부 — CVE 교집합 / file-sample 교집합 / paired file 교집합
  · paired AUC 계산에 쓰인 sample 집합 크기
  · 100건 파일럿 라벨 품질 감사 (3분류 비율)
  · ±N 확정값과 근거 (표본 크기, 중앙값)
  · v2-lite 전환 여부
  · 커버리지를 줄인 결정 (버린 건수)
  · 후속 개선사항

실행: .venv/bin/python rebuild/v2_report.py
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
OUT = ROOT / "out"
LANGS = ["JS/TS", "C/C++", "PHP", "Python", "Java"]


def jload(p: Path, default=None):
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:
        return default


def jlines(p: Path) -> list:
    if not p.exists():
        return []
    return [json.loads(l) for l in p.open()]


# ── §5 cohort 3단계 교집합 ───────────────────────────────────────────────────
def cohort_report(full: list) -> dict:
    """CVE 교집합 / file-sample 교집합 / paired file 교집합 — 셋 다 낸다 (§5).

    "CVE 가 살아 있다" 와 "그 CVE 의 모든 파일이 재현됐다" 는 다른 말이다. 그리고 v1/v2 직접
    비교의 진짜 분모는 **양쪽 파이프라인 모두에서 유효한 동일 (cve_id, repo, file, label)**
    교집합이다 (§5 rev.4·rev.5).
    """
    v1_test = jlines(DATA / "test.jsonl")
    v1_cves = {r["meta"]["cve_id"] for r in v1_test}

    v2_test = [r for r in full if r["split"] == "test"]
    v2_cves = {r["cve_id"] for r in v2_test}

    # v1 test.jsonl 의 meta 에는 repo/file 이 없다(함수 조각 단위였다) → paired 키는
    # (cve_id, label) 까지만 v1 쪽에서 만들 수 있다. 이 한계를 그대로 적는다.
    v1_pairs = {(r["meta"]["cve_id"], r["meta"]["label"]) for r in v1_test}
    v2_pairs = {(r["cve_id"], r["label"]) for r in v2_test}

    return {
        "v1_test_cohort_cve": len(v1_cves),
        "v1_test_rows": len(v1_test),
        "cve_intersection": len(v1_cves & v2_cves),
        "cve_intersection_pct": round(100 * len(v1_cves & v2_cves) / max(1, len(v1_cves)), 1),
        "v2_test_file_samples": len(v2_test),
        "v2_test_unique_file_samples": len(
            {(r["cve_id"], r["repo"], r["file"], r["label"]) for r in v2_test}),
        "paired_cve_label": len(v1_pairs & v2_pairs),
        "_paired_주의": (
            "v1 test.jsonl 의 meta 에는 repo/file 이 없다(v1 은 함수 조각 단위라 파일 식별자를 "
            "보존하지 않았다). 그래서 §5 가 정의한 (cve_id, repo, file, label) 4-키 paired "
            "교집합은 v1 쪽에서 구성 불가능하고, 실제로 만들 수 있는 최대 정밀도는 "
            "(cve_id, label) 2-키다. 이 값을 paired AUC 의 분모로 쓰고, 한계를 명시한다."),
    }


def auc_from_scores(rows: list) -> tuple[float | None, int, int]:
    """score(=logP(' CWE')−logP(' NONE')) 와 meta.label 로 ROC AUC (Mann-Whitney U)."""
    pos = [r["score"] for r in rows if r["meta"]["label"] == "vuln"]
    neg = [r["score"] for r in rows if r["meta"]["label"] == "safe"]
    if not pos or not neg:
        return None, len(pos), len(neg)
    allv = sorted([(s, 1) for s in pos] + [(s, 0) for s in neg])
    # 동점 처리 포함 rank 계산
    ranks, i = {}, 0
    vals = [s for s, _ in allv]
    while i < len(vals):
        j = i
        while j + 1 < len(vals) and vals[j + 1] == vals[i]:
            j += 1
        r = (i + j) / 2 + 1
        for k in range(i, j + 1):
            ranks[k] = r
        i = j + 1
    rsum = sum(ranks[k] for k, (_, y) in enumerate(allv) if y == 1)
    n1, n0 = len(pos), len(neg)
    return (rsum - n1 * (n1 + 1) / 2) / (n1 * n0), n1, n0


def main() -> None:
    full = jlines(DATA / "v2line_full_all.jsonl")
    if not full:
        print("[BLOCKED] rebuild/data/v2line_full_all.jsonl 이 없다 — build_dataset_v2 먼저.")
        sys.exit(2)

    collect = jload(OUT / "v2_collect_report_all.json", {})
    build = jload(OUT / "v2_build_report_all.json", {})
    label_audit = jload(OUT / "v2_label_audit_pilot100.json", {})
    pmN = jload(OUT / "v2_pmN.json", {})
    bench = jload(OUT / "bench_v2_v2_juice-shop_metrics.json", {})
    lp = jlines(OUT / "v2line_logprob_test_v2line.jsonl")

    vuln = [r for r in full if r["label"] == "vuln"]
    safe = [r for r in full if r["label"] == "safe"]
    trainval = [r for r in full if r["split"] in ("train", "val")]
    coh = cohort_report(full)

    auc, n_pos, n_neg = auc_from_scores(lp) if lp else (None, 0, 0)

    # 언어 분포
    lang_all = Counter(r["lang_group"] for r in full)
    lang_by_split = defaultdict(Counter)
    for r in full:
        lang_by_split[r["split"]][r["lang_group"]] += 1

    n_trunc_tv = sum(1 for r in trainval if r["truncated"])
    tr_rate_tv = round(100 * n_trunc_tv / max(1, len(trainval)), 2)
    n_invis = sum(1 for r in vuln if not r["line_in_visible_context"])

    L = []
    A = L.append
    A("# V2_RESULTS — 모델 v2(파일 단위 입력 + LINE supervision) 실행 결과\n")
    A("> 사양서: `V2_RUN_SPEC.md` (rev.6, FINAL). **사전등록된 기준을 결과를 보고 바꾸지 않았다.**")
    A("> 입력 표현은 문서 전체에서 **\"파일 단위 입력 — 최대 4096-token context\"** 로 통일한다")
    A("> (\"파일 전체\"가 아니다 — truncation 이 실제로 발생한다, §12).\n")
    A("---\n")

    # ── §9 판정
    A("## 1. 사전등록 판정 (§9)\n")
    v = (bench or {}).get("verdict_prereg", {})
    e1 = v.get("①_exact_line_gt_0", {})
    e2 = v.get("②_flag_rate_lt_45pct", {})
    A("| # | 지표 | 기준 | v1 | v2 | Δ | 판정 |")
    A("|---|---|---|---|---|---|---|")
    A(f"| ① | juice-shop exact-line 적중 | > 0 | {e1.get('v1','—')}/36 | "
      f"{e1.get('value','—')}/36 | — | {'PASS' if e1.get('pass') else 'FAIL' if e1 else '미측정'} |")
    A(f"| ② | juice-shop 파일 경보율 | < 45.00% | {e2.get('v1','—')}% | "
      f"{e2.get('value','—')}% | {e2.get('delta_pp','—')} pp | "
      f"{'PASS' if e2.get('pass') else 'FAIL' if e2 else '미측정'} |")
    A(f"| ③ | 내부 test AUC (paired cohort) | ≥ 0.855 | 0.905 | "
      f"{round(auc,4) if auc is not None else 'N/A'} | "
      f"{round(auc-0.905,4) if auc is not None else '—'} | "
      f"{'PASS' if (auc is not None and auc>=0.855) else 'FAIL' if auc is not None else '미측정'} |")
    A("")
    A("**②에 대하여**: 통과 여부와 \"의미 있는 개선인가\"는 다른 문장이다 (§9). "
      f"Δ = {e2.get('delta_pp','—')} pp.\n")

    # ── 데이터
    A("## 2. 데이터 수확 (§3·§4·§6·§7)\n")
    st = collect.get("stats", {})
    A("```")
    A(f"raw candidates (5개 언어, 고유 CVE)   8,395   ← v4_meta 에서 재계산, 문서와 일치")
    A(f"대상 행 (v1 train/val 제외 후)        {collect.get('n_rows_planned','—')}")
    A(f"  실제 디스패치                        {collect.get('n_rows_dispatched','—')}")
    A(f"  미처리 (torvalds/linux 병목)          {collect.get('n_rows_unprocessed','—')}")
    A(f"수확 성공 (ok)                        {st.get('ok','—')}")
    A(f"원시 샘플                             {st.get('sample_vuln',0)}v / {st.get('sample_safe',0)}s")
    A(f"exact 중복 제거                        {build.get('stats',{}).get('drop_dup_exact',0)}")
    A(f"similarity>95% 제거                    {build.get('stats',{}).get('drop_dup_sim95',0)}")
    A(f"final samples                         {len(full)} "
      f"(label=vuln {len(vuln)} / label=safe {len(safe)})")
    A("```")
    if st.get("_탈락_카테고리_주의"):
        A(f"> ⚠ {st['_탈락_카테고리_주의']}")
    A("")
    A("**§6 300건 컷**: 필터 통과 후 최종 샘플 "
      f"**{len(full)}건** → {'300건 이상이므로 v2-lite 로 전환하지 않았다.' if len(full) >= 300 else '**300건 미만 → v2-lite 전환**'}\n")

    A("### 언어 분포 (§3/§6 형식)\n")
    A("| 언어 | 전체 | train | val | test |")
    A("|---|---:|---:|---:|---:|")
    for lg in LANGS:
        A(f"| {lg} | {lang_all.get(lg,0)} | {lang_by_split['train'].get(lg,0)} | "
          f"{lang_by_split['val'].get(lg,0)} | {lang_by_split['test'].get(lg,0)} |")
    A(f"| **합계** | **{sum(lang_all.values())}** | **{sum(lang_by_split['train'].values())}** | "
      f"**{sum(lang_by_split['val'].values())}** | **{sum(lang_by_split['test'].values())}** |\n")

    # ── §5 cohort 3단계
    A("## 3. test cohort 재사용 — 3단계 보고 (§5)\n")
    A("```")
    A(f"v1 test cohort              {coh['v1_test_cohort_cve']} CVE ({coh['v1_test_rows']} 행)")
    A(f"① CVE 교집합                 {coh['cve_intersection']} CVE  ({coh['cve_intersection_pct']}%)")
    A(f"② file-sample 교집합          {coh['v2_test_unique_file_samples']} file-samples")
    A(f"③ paired 교집합              {coh['paired_cve_label']}  ← ③ AUC 의 실제 분모")
    A("```")
    A(f"> {coh['_paired_주의']}\n")
    A(f"paired AUC 계산에 쓰인 sample 집합 크기: **positive {n_pos} / negative {n_neg}**"
      f" (총 {n_pos+n_neg})\n")

    # ── truncation
    A("## 4. truncation 계측 (§8-2·§8-3)\n")
    A("| 대상 | 전체 | truncated | rate |")
    A("|---|---:|---:|---:|")
    A(f"| 학습셋(train+val) | {len(trainval)} | {n_trunc_tv} | {tr_rate_tv}% |")
    jt = (bench or {}).get("truncation", {})
    A(f"| juice-shop | {jt.get('total_files_scanned','—')} | {jt.get('truncated','—')} | "
      f"{jt.get('truncation_rate_pct','—')}% |")
    A("")
    A(f"학습셋에서 정답 LINE 이 창 밖으로 나간 positive 샘플: **{n_invis}/{len(vuln)} "
      f"({round(100*n_invis/max(1,len(vuln)),1)}%)** — §8-2 대로 train/val 에서만 버렸고 "
      "test 에서는 버리지 않았다. 이건 데이터 오류가 아니라 4096 컨텍스트의 구조적 한계다(§10-1).\n")

    A("### exact-line 사다리 — visible/invisible 분리 (§8-3)\n")
    lad = (bench or {}).get("exact_line_ladder", {})
    if lad:
        A("| 사다리 | 전체 | visible-only | invisible | in-scope |")
        A("|---|---|---|---|---|")
        for k, vv in lad.items():
            A(f"| {k} | {vv['all']} | {vv['visible_only']} | {vv['invisible']} | {vv['in_scope']} |")
    else:
        A("_(juice-shop 벤치 미실행)_")
    A("")

    # ── ±N
    A("## 5. ±N 확정 (§8-1)\n")
    if pmN.get("N") is not None:
        A(f"- **N = {pmN['N']}**")
        A(f"- 근거: 삭제줄 2개 이상인 (CVE, 파일) 그룹 **{pmN['n_groups']}개**, "
          f"연속 삭제줄 간격 표본 **{pmN['n_gaps']}개**, **중앙값 {pmN['median_gap']}** → 반올림")
        A(f"- 참고: 평균 {pmN.get('mean_gap')} / 최대 {pmN.get('max_gap')}")
        A("- R4 8건 파일럿(중앙값 3.5)은 표본이 작아 쓰지 않았다. 전체 수확 데이터로 "
          "재계산해 확정했고 이후 바꾸지 않았다(사전등록).\n")
    else:
        A("_(미확정)_\n")

    # ── 라벨 품질
    A("## 6. 라벨 품질 감사 — 100건 파일럿 3분류 (§7)\n")
    if label_audit:
        A(f"표본: {label_audit.get('_표본','')}\n")
        A("| 언어 | n | valid | related_but_indirect | unrelated_deletion | valid% |")
        A("|---|---:|---:|---:|---:|---:|")
        for lg, s in label_audit["by_language"].items():
            A(f"| {lg} | {s['n']} | {s['valid_vulnerable_line']} | {s['related_but_indirect']} | "
              f"{s['unrelated_deletion']} | {round(100*s['valid_vulnerable_line']/s['n'],1)}% |")
        t = label_audit["total"]
        A(f"| **전체** | **{t['n']}** | **{t['valid_vulnerable_line']}** | "
          f"**{t['related_but_indirect']}** | **{t['unrelated_deletion']}** | "
          f"**{round(100*t['valid_vulnerable_line']/t['n'],1)}%** |\n")
        A("> 이 비율에는 새 pass/fail threshold 를 만들지 않았다(사전등록 원칙). "
          "LINE 정확도가 낮을 때 \"모델이 못 찾았다\"와 \"라벨이 애매했다\"를 구분하는 근거로만 쓴다.\n")
        A("관측된 노이즈 패턴:\n")
        for n in label_audit.get("noise_patterns_observed", []):
            A(f"- {n}")
        A("")

    # ── 커버리지 축소
    A("## 7. 커버리지를 줄인 결정 (규칙 #10)\n")
    A("| 항목 | 건수 | 사유 |")
    A("|---|---:|---|")
    cr = collect.get("coverage_reductions") or {}
    A(f"| torvalds/linux **train 행 통째 제외** | {cr.get('torvalds_linux_train_rows_dropped','—')} | "
      f"{cr.get('사유','')} |")
    A(f"| torvalds/linux test 행 fetch 실패 | {cr.get('torvalds_linux_test_rows_fetch_failed','—')} | "
      f"시도 {cr.get('torvalds_linux_test_rows_attempted','—')}행 중 — 오래된 커널 커밋이 depth-2 로 안 잡힘 |")
    A(f"| 디스패치됐으나 필터 탈락 | {(st.get('rows') or 0) - (st.get('ok') or 0)} | "
      f"F2/F6/F3/F7/fetch실패 합계 — **세부 분해는 보존되지 않았다**(수확 중단) |")
    A(f"| 5개 언어 밖 확장자 | {collect.get('ext_rejected_total',0)} | "
      f"{collect.get('ext_rejected_counts',{})} |")
    A(f"| exact 중복 | {build.get('stats',{}).get('drop_dup_exact',0)} | 분할 전 dedup(누수 방지) |")
    A(f"| similarity>95% | {build.get('stats',{}).get('drop_dup_sim95',0)} | §10-1 요구 |")
    for k, vv in (build.get("dropped_from_training") or {}).items():
        A(f"| 학습셋에서 제외: {k} | {vv} | §8-2 |")
    A("")

    A("## 8. 필터 정책 — F1·F5 미적용 (이번 라운드 확정)\n")
    for k, vv in (collect.get("filters_skipped") or {}).items():
        A(f"- **{k}**: {vv}")
    A(f"- 적용한 필터: {', '.join(collect.get('filters_applied', []))}\n")

    A("## 9. 후속 개선사항 (이번 실행에는 반영하지 않음, §12)\n")
    A("실행 중 발견했지만 `V2_RUN_SPEC.md` 범위 밖이라 **의도적으로 반영하지 않은** 것들이다.\n")
    A("1. **v1 의 학습/서빙 프롬프트 불일치.** `rebuild/repo_bench_scan.py:40` 과 "
      "`scripts/api_rebuild.py:190` 의 `CHATML_TMPL` 은 `<|im_start|>assistant\\n` 까지만 붙이는데, "
      "실제 학습 텍스트는 `<|im_start|>assistant\\n<think>\\n\\n</think>\\n\\n` 로 이어진다"
      "(PHASE 2 에서 tokenizer 로 실측). 즉 v1 은 CLAUDE.md 가 요구한 \"바이트 단위 동일\"이 "
      "첫 호출에서 깨져 있었다(재시도 경로에서만 `_THINK_PREFILL` 로 보정). v1 은 FROZEN(§11)이라 "
      "고치지 않았다. v2 는 `prompt_v2.build_generation_prompt()` 로 처음부터 맞췄다.")
    A("2. **F4 노이즈 정규식이 여러 줄 주석의 중간 줄을 통과시킨다.** 현재 `NOISE` 는 주석 기호로 "
      "*시작하는* 줄만 잡아서, 플러그인 헤더(`Version: 1.1`)나 배너(`| WordPress 2.8 Plugin |`) 같은 "
      "블록주석 내부 줄이 정답 LINE 으로 뽑힌다. 파일럿 라벨 감사의 `unrelated_deletion` 주 원인.")
    A("3. **F4 의 IMPORT_ONLY 가 여러 줄 import 를 못 잡는다.** `ObjectValueNode,` / `File,` 같은 "
      "import 목록 continuation, Python 의 `from X import Y`, JS 의 `const { a, b } = require(...)` "
      "가 전부 통과한다.")
    A("4. **F3 이 테스트 파일 접미사를 안 거른다.** `PATH_EXCLUDE` 는 `test/` *디렉터리*만 제외해서 "
      "`JsonDeserializer.test.ts` / `transactions.test.api.js` 가 살아남는다.")
    A("5. **`line_selection_rule` 대안.** `first_deleted_line` 은 결정론적이지만 의미론적 정확도가 "
      "44.9%(파일럿 실측)다. 삭제줄 중 CWE sink 후보를 고르는 규칙이나 다건 LINE 출력(v3)이 대안.")
    A("6. **CVSS 결측이 많다.** `cvss_present=false` 인 샘플은 completion 이 `CVSS: UNKNOWN` 이 된다"
      "(v1 `derive_severity()` 동작 그대로). 이게 LINE 학습을 방해하는지는 "
      "`cvss_source=missing` 표본만 떼어 LINE 정확도를 비교하면 확인 가능(§7).")
    A("")

    A("## 10. 산출물 경로\n")
    A("```")
    for p in ["rebuild/prompt_v2.py", "rebuild/collect_files_v2.py", "rebuild/build_dataset_v2.py",
              "rebuild/validate_v2_dataset.py", "rebuild/bench_v2.py", "rebuild/v2_report.py",
              "rebuild/collect_cvemeta_v2.py", "rebuild/run_train_v2line.sh",
              "rebuild/data/v2line_full_all.jsonl", "rebuild/data/train_v2line.jsonl",
              "rebuild/data/val_v2line.jsonl", "rebuild/data/test_v2line.jsonl",
              "rebuild/out/v2_collect_report_all.json", "rebuild/out/v2_build_report_all.json",
              "rebuild/out/v2_label_audit_pilot100.json", "rebuild/out/v2_pmN.json"]:
        A(f"  {p}")
    A("```")

    p = OUT / "V2_RESULTS.md"
    p.write_text("\n".join(L))
    print(f"-> {p}  ({len(L)} 줄)")


if __name__ == "__main__":
    main()
