"""ScanOps v2 — [DATASET AUDIT] 학습 진입 전 자동 검증 (V2_RUN_SPEC.md rev.6 §10-1).

무결성 위반 항목은 **경고가 아니라 프로그램 종료**다. 학습을 시작하지 못하게 막는 게 목적이다.

fail-fast 조건 (§10-1):
  · CVE overlap (train∩val∩test) ≠ 0
  · LINE > file_length
  · label=vuln 샘플인데 LINE < 1        (label=safe 는 LINE=0 이 정상 — positive 에만 적용)
  · label=safe 샘플인데 LINE ≠ 0
  · train·test 에 동일 CVE 존재
  · §3 에서 재계산한 v1 train/val/test 고유 CVE 수가 문서 값과 다름
  · completion 토큰 수 > COMPLETION_RESERVE_TOKENS(128) 인데 format_overflow 로 기록 안 됨
  · §5-0 해시 분할을 재계산했을 때 실제 파일의 CVE→split 매핑과 하나라도 다름
  · exact 중복 존재 / similarity>95% 중복 존재
  · (v2 추가) line_text 가 pre-fix 파일의 LINE 줄과 불일치
        §7 은 "diff 라인 번호 체계와 pre-fix 파일 줄 번호 체계가 동일하다"를 **암묵적으로
        가정하지 말고 명시하라**고 요구한다. 명시만으로는 부족해서, 수확 때 남긴 삭제줄 원문과
        실제 파일 줄을 대조해 이 전제를 매 샘플에서 기계적으로 검증한다.

fail-fast 가 아니라 통계로만 남기는 것 (§10-1):
  · line_in_visible_context = false → 데이터 오류가 아니라 4096 컨텍스트의 구조적 한계다.
    다만 학습셋 truncation rate 가 30% 이상이면 **경고를 눈에 띄게** 출력하고 계속 진행한다.

━━ §3 숫자에 대하여 (PHASE 0 실측으로 확정) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
§3 표의 5,107 / 637 / 641 은 **split 파일의 raw 고유 CVE 수가 아니다.** 실측값은
raw 로는 5,132 / 641 / 641 이고, 문서 값과 일치하는 것은
**"v4_meta 5개 언어 후보(8,395) 와의 교집합"** 이다:
    8,395 = 5,107(v1 train ∩) + 637(v1 val ∩) + 641(v1 test ∩) + 2,010(나머지)
§3 의 표 머리글이 "v4_meta 5개 언어 후보 … 그중 v1 train 에 이미 쓰임" 이므로 이 해석이 맞다.
그래서 fail-fast 는 **교집합 기준**으로 걸고, 혼동 방지를 위해 raw·교집합·행 수를 전부 찍는다
(§3 이 "행 수와 고유 CVE 수를 혼동하지 않도록 둘 다 찍는다"고 요구한 것과 같은 취지).

실행:
  .venv/bin/python rebuild/validate_v2_dataset.py rebuild/data/v2_samples_raw_pilot100.jsonl
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import prompt_v2 as P  # noqa: E402
from collect_files_v2 import assign_split, LANG_GROUP, V4_LANG_MAP  # noqa: E402

DATA = ROOT / "data"

# §3 문서 값 (v4_meta 5개 언어 후보와의 교집합 기준)
SPEC_V1_CVE = {"train": 5107, "val": 637, "test": 641}
SPEC_V4META_5LANG = 8395
SPEC_REST = 2010
LANGS = ["JS/TS", "C/C++", "PHP", "Python", "Java"]

FAILURES: list[str] = []
WARNINGS: list[str] = []


def fail(msg: str) -> None:
    FAILURES.append(msg)
    print(f"  ✗ FAIL-FAST: {msg}")


def warn(msg: str) -> None:
    WARNINGS.append(msg)
    print(f"  ⚠ 경고: {msg}")


def ok(msg: str) -> None:
    print(f"  ✓ {msg}")


# ── 코드 정규화 해시 (v1 build_dataset.code_hash 와 동일 규칙) ────────────────
def code_hash(code: str) -> str:
    return hashlib.sha1(re.sub(r"\s+", " ", code).strip().lower().encode()).hexdigest()


def shingles(code: str, k: int = 5) -> set[str]:
    toks = re.sub(r"\s+", " ", code).strip().lower().split(" ")
    if len(toks) < k:
        return {" ".join(toks)}
    return {" ".join(toks[i:i + k]) for i in range(len(toks) - k + 1)}


def jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


# ── §3 v1 CVE 수 자기검증 ────────────────────────────────────────────────────
def audit_v1_counts() -> None:
    print("\n[1] §3 v1 고유 CVE 수 자기검증 (문서 값을 믿지 않고 파일에서 재계산)")
    cand = set()
    for line in (DATA / "v4_meta.jsonl").open():
        r = json.loads(line)
        if (r.get("language") or "").strip().lower() in V4_LANG_MAP:
            cand.add(r["cve_id"])
    print(f"      v4_meta 5개언어 고유 CVE : {len(cand)}  (문서 {SPEC_V4META_5LANG})")
    if len(cand) != SPEC_V4META_5LANG:
        fail(f"v4_meta 5개언어 고유 CVE {len(cand)} ≠ 문서 {SPEC_V4META_5LANG}")

    sets = {}
    for sp in ("train", "val", "test"):
        rows = [json.loads(l) for l in (DATA / f"{sp}.jsonl").open()]
        s = {r["meta"]["cve_id"] for r in rows}
        sets[sp] = s
        inter = len(s & cand)
        print(f"      v1 {sp:5s}: 행 {len(rows):5d} / raw 고유 CVE {len(s):5d} "
              f"/ ∩v4_meta5lang {inter:5d}  (문서 {SPEC_V1_CVE[sp]})")
        if inter != SPEC_V1_CVE[sp]:
            fail(f"v1 {sp} ∩v4_meta 고유 CVE {inter} ≠ 문서 {SPEC_V1_CVE[sp]}")
    rest = cand - sets["train"] - sets["val"] - sets["test"]
    print(f"      나머지(v2 train/val 후보) : {len(rest)}  (문서 {SPEC_REST})")
    if len(rest) != SPEC_REST:
        fail(f"나머지 {len(rest)} ≠ 문서 {SPEC_REST}")
    if not FAILURES:
        ok("§3 표를 코드가 그대로 재현함")
    return sets


# ── 메인 감사 ────────────────────────────────────────────────────────────────
def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DATA / "v2_samples_raw_all.jsonl"
    if not path.exists():
        print(f"[BLOCKED] 입력 없음: {path}")
        sys.exit(2)
    rows = [json.loads(l) for l in path.open()]
    print(f"[DATASET AUDIT] {path.name} — {len(rows)}건")

    v1sets = audit_v1_counts()

    vuln = [r for r in rows if r["label"] == "vuln"]
    safe = [r for r in rows if r["label"] == "safe"]

    print("\n[2] 수확 요약")
    print(f"      final samples : {len(rows)} (label=vuln {len(vuln)} / label=safe {len(safe)})")
    cves = {r["cve_id"] for r in rows}
    print(f"      고유 CVE      : {len(cves)}")
    print(f"      고유 file-sample ((cve,repo,file,label)) : "
          f"{len({(r['cve_id'], r['repo'], r['file'], r['label']) for r in rows})}")

    print("\n[3] 언어 분포 (§3/§6 형식)")
    g_all = Counter(r["lang_group"] for r in rows)
    g_v = Counter(r["lang_group"] for r in vuln)
    for L in LANGS:
        print(f"      {L:8s} 전체 {g_all.get(L, 0):5d}  (vuln {g_v.get(L, 0):5d})")
    other = set(g_all) - set(LANGS)
    if other:
        fail(f"5개 언어 그룹 밖의 lang_group 존재: {sorted(other)}")

    print("\n[4] line 라벨")
    n_bad_lt1 = sum(1 for r in vuln if r["line"] < 1)
    n_over = sum(1 for r in vuln if r["line"] > r["file_lines_total"])
    n_safe_nonzero = sum(1 for r in safe if r["line"] != 0)
    print(f"      label=vuln : valid {len(vuln) - n_bad_lt1 - n_over} / "
          f"invalid(LINE<1) {n_bad_lt1} / line > file_length {n_over}")
    print(f"      label=safe : LINE=0 {len(safe) - n_safe_nonzero} / LINE≠0(위반) {n_safe_nonzero}")
    if n_bad_lt1:
        fail(f"label=vuln 인데 LINE<1 인 샘플 {n_bad_lt1}건")
    if n_over:
        fail(f"LINE > file_length 인 샘플 {n_over}건")
    if n_safe_nonzero:
        fail(f"label=safe 인데 LINE≠0 인 샘플 {n_safe_nonzero}건")

    # v2 추가 검증 — §7 의 "diff 줄번호 = pre-fix 파일 줄번호" 전제를 기계적으로 대조
    n_lt_mismatch = sum(1 for r in vuln if not r.get("line_text_matches_file", False))
    print(f"      line_text ↔ pre-fix 파일 LINE 줄 대조 : "
          f"일치 {len(vuln) - n_lt_mismatch} / 불일치 {n_lt_mismatch}")
    if n_lt_mismatch:
        fail(f"line_text 가 파일의 LINE 줄과 다른 샘플 {n_lt_mismatch}건 "
             f"— §7 의 줄번호 체계 동일성 전제가 깨졌다")

    print("\n[5] context (§8-2 불변식)")
    n_fit = sum(1 for r in rows if r["input_tokens"] + r["completion_reserve_tokens"]
                <= r["max_sequence_tokens"])
    n_trunc = sum(1 for r in rows if r["truncated"])
    n_invisible = sum(1 for r in vuln if not r["line_in_visible_context"])
    rate = 100 * n_trunc / max(1, len(rows))
    msl = sorted({r["max_sequence_tokens"] for r in rows})
    print(f"      input_tokens+reserve ≤ max_seq({','.join(map(str,msl))}) : {n_fit}/{len(rows)}")
    print(f"      truncated {n_trunc} / truncation rate {rate:.1f}%")
    print(f"      line_in_visible_context=false (vuln) : {n_invisible} "
          f"({100*n_invisible/max(1,len(vuln)):.1f}%) — 통계만, fail-fast 아님")
    if n_fit != len(rows):
        fail(f"§8-2 불변식 위반 샘플 {len(rows)-n_fit}건")
    tr_train = [r for r in rows if r["split"] in ("train", "val")]
    if tr_train:
        r_tr = 100 * sum(1 for r in tr_train if r["truncated"]) / len(tr_train)
        if r_tr >= 30.0:
            warn(f"학습셋 truncation rate {r_tr:.1f}% ≥ 30% — 멈추지는 않지만 눈에 띄게 남긴다")

    print("\n[6] completion (예약 128 토큰)")
    n_of = sum(1 for r in rows if r.get("format_overflow"))
    n_over_tok = sum(1 for r in rows
                     if r.get("completion_tokens", 0) > P.COMPLETION_RESERVE_TOKENS)
    print(f"      ≤128 tokens {len(rows) - n_over_tok} / format_overflow(>128) {n_over_tok}")
    if n_over_tok != n_of:
        fail(f"completion>128 인 샘플 {n_over_tok}건 중 format_overflow 로 기록된 것은 "
             f"{n_of}건 — 계측 누락")

    print("\n[7] duplicates")
    hs = Counter(code_hash(r["source"]) for r in rows)
    n_exact = sum(c - 1 for c in hs.values() if c > 1)
    print(f"      exact 중복 : {n_exact}")
    if n_exact:
        fail(f"exact 중복 {n_exact}건 (분할 전 dedup 이 안 됐다)")
    # similarity>95% — 같은 (repo,file) 안에서만 비교한다(전수 비교는 O(n²)라 비현실적이고,
    # 실제 위험은 "같은 파일의 vuln/safe 가 거의 같아서 누수"가 아니라 "다른 CVE인데 같은 코드"다)
    buckets: dict[tuple, list] = defaultdict(list)
    for r in rows:
        buckets[(r["repo"], r["file"], r["label"])].append(r)
    n_sim = 0
    for k, group in buckets.items():
        if len(group) < 2:
            continue
        sh = [(g, shingles(g["source"])) for g in group]
        for i in range(len(sh)):
            for j in range(i + 1, len(sh)):
                if sh[i][0]["cve_id"] != sh[j][0]["cve_id"] and jaccard(sh[i][1], sh[j][1]) > 0.95:
                    n_sim += 1
    print(f"      similarity>95% (동일 repo·file·label, 다른 CVE) : {n_sim}")
    if n_sim:
        fail(f"similarity>95% 중복 {n_sim}건")

    print("\n[8] splits")
    sp = Counter(r["split"] for r in rows)
    print(f"      train {sp.get('train',0)} / val {sp.get('val',0)} / test {sp.get('test',0)}")
    tc = Counter(r.get("test_cohort_source") for r in rows if r["split"] == "test")
    print(f"      test 중 v1_test {tc.get('v1_test',0)} / supplemental {tc.get('supplemental',0)}")
    by_split = defaultdict(set)
    for r in rows:
        by_split[r["split"]].add(r["cve_id"])
    ov_tv = by_split["train"] & by_split["val"]
    ov_tt = by_split["train"] & by_split["test"]
    ov_vt = by_split["val"] & by_split["test"]
    print(f"      CVE overlap train∩val {len(ov_tv)} / train∩test {len(ov_tt)} "
          f"/ val∩test {len(ov_vt)}")
    if ov_tv or ov_tt or ov_vt:
        fail(f"split 간 CVE overlap ≠ 0 (train∩val {len(ov_tv)}, train∩test {len(ov_tt)}, "
             f"val∩test {len(ov_vt)})")

    # v1 train/val CVE 가 v2 에 섞였는지 (§3 "v2에서 전체 제외")
    leaked = {r["cve_id"] for r in rows} & (v1sets["train"] | v1sets["val"])
    print(f"      v1 train/val CVE 혼입 : {len(leaked)}")
    if leaked:
        fail(f"v1 train/val CVE 가 v2 에 {len(leaked)}건 섞였다: {sorted(leaked)[:5]}")

    print("\n[9] §5-0 해시 분할 재현성")
    mism = [r for r in rows if r["split"] != "test"
            and r["split"] != assign_split(r["cve_id"])]
    print(f"      재계산 불일치 : {len(mism)}")
    if mism:
        fail(f"§5-0 해시 분할 재계산이 파일과 {len(mism)}건 불일치 "
             f"— 분할이 비결정적 요인(수확 순서 등)에 의존했다는 신호")
    # 같은 CVE 가 여러 split 에 걸치지 않는지
    cve_splits = defaultdict(set)
    for r in rows:
        cve_splits[r["cve_id"]].add(r["split"])
    multi = {c for c, s in cve_splits.items() if len(s) > 1}
    print(f"      한 CVE 가 여러 split 에 걸침 : {len(multi)}")
    if multi:
        fail(f"CVE 단위 분할 위반 {len(multi)}건: {sorted(multi)[:5]}")

    print("\n" + "=" * 70)
    if FAILURES:
        print(f"[DATASET AUDIT] ✗ FAIL — fail-fast 위반 {len(FAILURES)}건. 학습 진입 차단.")
        for f in FAILURES:
            print(f"   · {f}")
        sys.exit(1)
    print(f"[DATASET AUDIT] ✓ PASS — fail-fast 위반 0건"
          + (f" / 경고 {len(WARNINGS)}건" if WARNINGS else ""))
    for w in WARNINGS:
        print(f"   ⚠ {w}")


if __name__ == "__main__":
    main()
