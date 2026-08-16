"""
ScanOps 재구축 — 라벨 비대칭(44:56) & REASON 폴백 티어 분석 (읽기 전용)
====================================================================
build_dataset.py / rebuild/data/{train,val,test}.jsonl 을 절대 수정하지 않는다.
build_dataset.py에서 로직(LANG_MAP, 길이 상수, REASON 추출 정규식, code_hash)을
그대로 import해서 재사용하고, 원본 CVEfixes를 한 번 더 스트리밍해 아래 두 가지를 확인한다.

1) 라벨 비율이 정확히 반반이 아닌 이유
   - 언어 필터 → cve_id/cwe_id 필터까지는 build_dataset.py와 동일하게 적용.
   - build_dataset.py의 실제 per-code 루프는 "길이 필터 → (통과 시) dedup" 순서다.
     이 스크립트는 요청대로 순서를 뒤집어 "dedup → 길이 측정"으로 진행해,
     dedup까지 끝난(=중복만 제거된) 상태에서 vulnerable_code/fixed_code 각각의
     길이 분포를 본다. dedup은 build_dataset.py와 동일하게 vuln/safe를 구분하지
     않는 단일 seen_hashes 전역 집합, 그리고 각 행에서 vuln → safe 순서로 처리한다
     (먼저 등장한 코드가 이기는 규칙도 동일).
   - 그 다음, 이 pre-length-filter 풀에 대해 [40, 12000]자 길이 필터를 적용했을 때
     vuln/safe 각각 몇 건이 걸러지는지 센다. build_dataset.py의 per-code 루프를
     읽어보면 vulnerable_code/fixed_code는 한 쌍(pair)이 아니라 완전히 독립된
     별도 샘플로 처리된다 (하나가 길이 필터에 걸려도 다른 하나는 영향받지 않음) —
     이 스크립트도 동일하게 독립 처리한다.
   - 추가로, vuln 쪽과 safe 쪽 각각 "자기 카테고리 내에서만" 중복률이 얼마나
     되는지 별도로 계산한다 (전역 공유 세트가 아닌, vuln 전용/safe 전용 세트).
     동일 취약 패턴이 여러 CVE에서 반복돼 vuln 쪽 자체 중복률이 더 높은지 확인용.

2) REASON 3단계 폴백 비율
   - build_dataset.py의 extract_reason()과 동일한 CAUSE_PAT / _desc_text를
     import해서, 이 스크립트에서 "어느 티어가 발동했는지"까지 함께 반환하는
     얇은 래퍼(extract_reason_tiered)를 만든다.
   - 최종 산출물인 train/val/test.jsonl의 label=="vuln" 샘플들을 읽어(읽기 전용),
     meta.cve_id / meta.cwe_id로 원본 스트리밍에서 수집해둔
     cve_description(cve_id 기준) / cwe_description(cwe_id 기준) 룩업 테이블을
     찾아 extract_reason_tiered를 재실행하고, 그 결과가 실제 completion에 박힌
     REASON 텍스트와 일치하는지 sanity check까지 겸해 티어별 건수를 집계한다.

실행:
  .venv/bin/python rebuild/analyze_label_asymmetry.py
"""
from __future__ import annotations

import json
import re
import statistics
from collections import Counter
from pathlib import Path

from build_dataset import (
    LANG_MAP,
    MIN_CHARS,
    MAX_CHARS,
    CAUSE_PAT,
    _desc_text,
    code_hash,
)

DATA_DIR = Path(__file__).resolve().parent / "data"


# ── REASON 티어 판정 래퍼 (extract_reason과 동일 로직, 티어 정보만 추가) ──────────
def extract_reason_tiered(cve_description, cwe_description: str) -> tuple[str, int]:
    """return (reason_text, tier). tier: 1=cve_description 패턴매치, 2=cwe_description 폴백, 3=둘다없음"""
    text = re.sub(r"\s+", " ", _desc_text(cve_description)).strip()
    for sent in re.split(r"(?<=[.!?])\s+", text):
        if CAUSE_PAT.search(sent) and 30 <= len(sent) <= 400:
            return sent.strip(), 1
    cwe_desc = re.sub(r"\s+", " ", cwe_description or "").strip()
    if cwe_desc:
        return cwe_desc[:400], 2
    return "", 3


def fmt_int(n: int) -> str:
    return f"{n:,}"


def length_stats(values: list[int]) -> dict:
    if not values:
        return {"n": 0, "mean": 0, "median": 0, "p90": 0, "max": 0}
    s = sorted(values)
    p90_idx = min(len(s) - 1, int(round(0.90 * (len(s) - 1))))
    return {
        "n": len(s),
        "mean": round(statistics.mean(s), 1),
        "median": round(statistics.median(s), 1),
        "p90": s[p90_idx],
        "max": s[-1],
    }


def main() -> None:
    from datasets import load_dataset

    print("=" * 80)
    print("[읽기 전용 분석] build_dataset.py / 기존 train·val·test.jsonl은 수정하지 않음")
    print("=" * 80)

    print("\nCVEfixes 스트리밍 로드 중… (원본 약 13k 행, task1+task2 공용 1-pass)")
    ds = load_dataset("hitoshura25/cvefixes", split="train", streaming=True)

    # ── task1 집계 상태 ──────────────────────────────────────────────────────
    # (a) build_dataset.py와 동일한 "전역 공유 seen_hashes" — 순서만 dedup을
    #     길이필터보다 먼저 적용하도록 재배치. 이 풀의 길이가 "길이필터 직전" 분포.
    seen_hashes_global: set[str] = set()
    lengths_pre_length_filter: dict[str, list[int]] = {"vuln": [], "safe": []}
    dedup_drop_global = Counter()  # 전역 공유 세트 기준 dedup 드롭 (vuln/safe 구분해 카운트)
    length_filter_drop = Counter()  # 위 풀에 길이필터를 적용했을 때 vuln/safe 각각 드롭 건수
    length_filter_keep = Counter()

    # (b) vuln 전용 / safe 전용 독립 세트 — "자기 카테고리 내" 중복률 계산용
    seen_hashes_by_label = {"vuln": set(), "safe": set()}
    total_codes_by_label = Counter()   # 언어+cve/cwe 필터 통과한 코드 총량 (label별)
    unique_codes_by_label = Counter()  # 그 중 label 전용 세트 기준 유니크(=최초 등장) 건수

    # task2용 룩업 테이블
    cve_desc_by_cve: dict[str, object] = {}
    cwe_desc_by_cwe: dict[str, str] = {}

    stats = Counter()

    for row in ds:
        stats["rows_total"] += 1

        lang = LANG_MAP.get(str(row.get("language") or "").strip().lower())
        if lang is None:
            stats["drop_language"] += 1
            continue

        cve_id = (row.get("cve_id") or "").strip()
        cwe_id = (row.get("cwe_id") or "").strip()
        if not cve_id or not cwe_id.startswith("CWE-"):
            stats["drop_no_cwe"] += 1
            continue

        stats["rows_kept_for_analysis"] += 1

        # task2 룩업 테이블 채우기 (최초 등장 값 사용; cve_description/cwe_description은
        # 해당 CVE/CWE의 속성이라 행이 달라도 동일해야 정상)
        if cve_id not in cve_desc_by_cve:
            cve_desc_by_cve[cve_id] = row.get("cve_description")
        if cwe_id not in cwe_desc_by_cwe:
            cwe_desc_by_cwe[cwe_id] = row.get("cwe_description") or ""

        for code, label in ((row.get("vulnerable_code"), "vuln"), (row.get("fixed_code"), "safe")):
            code = (code or "").strip()
            if not code:
                continue

            # (b) label 전용 dedup — 전역 세트와 무관하게 독립 계산
            total_codes_by_label[label] += 1
            h = code_hash(code)
            if h not in seen_hashes_by_label[label]:
                seen_hashes_by_label[label].add(h)
                unique_codes_by_label[label] += 1

            # (a) 전역 공유 dedup을 길이필터보다 먼저 적용 (요청된 순서)
            if h in seen_hashes_global:
                dedup_drop_global[label] += 1
                continue
            seen_hashes_global.add(h)

            # 여기까지 살아남은 코드 = "길이 필터 적용 직전" 풀
            L = len(code)
            lengths_pre_length_filter[label].append(L)
            if MIN_CHARS <= L <= MAX_CHARS:
                length_filter_keep[label] += 1
            else:
                length_filter_drop[label] += 1

    # ── task1 결과 출력 ──────────────────────────────────────────────────────
    print("\n" + "=" * 80)
    print("[1] 라벨 비율 44:56 원인 분석")
    print("=" * 80)
    print(f"\n분석 대상 행 수 (언어필터+cve/cwe필터 통과): {fmt_int(stats['rows_kept_for_analysis'])} / 전체 {fmt_int(stats['rows_total'])}")

    print("\n--- (1-1) 언어필터→dedup까지 적용한 뒤, 길이필터 '직전' 문자 길이 분포 ---")
    print(f"{'구분':<8}{'n':>8}{'mean':>10}{'median':>10}{'p90':>10}{'max':>10}")
    for label in ("vuln", "safe"):
        st = length_stats(lengths_pre_length_filter[label])
        name = "vulnerable_code" if label == "vuln" else "fixed_code"
        print(f"{name:<16}{st['n']:>8}{st['mean']:>10}{st['median']:>10}{st['p90']:>10}{st['max']:>10}")

    print("\n--- (1-2) 위 풀에 길이 필터([40, 12000]자) 적용 시 드롭/유지 건수 (vuln/safe 독립 처리) ---")
    print(f"{'구분':<16}{'유지':>10}{'드롭':>10}{'드롭율':>10}")
    for label in ("vuln", "safe"):
        keep = length_filter_keep[label]
        drop = length_filter_drop[label]
        tot = keep + drop
        rate = f"{100*drop/tot:.2f}%" if tot else "N/A"
        name = "vulnerable_code" if label == "vuln" else "fixed_code"
        print(f"{name:<16}{keep:>10}{drop:>10}{rate:>10}")
    print(
        "\n※ build_dataset.py의 per-code 루프 확인 결과: vulnerable_code/fixed_code는 쌍(pair)으로 묶여 "
        "\n   같이 빠지는 구조가 아니라, 각각 독립된 별도 샘플로 처리된다 (한쪽이 길이 범위를 벗어나도 "
        "\n   다른 쪽 채택 여부에는 영향을 주지 않음)."
    )

    print("\n--- (1-3) 코드 정규화 해시 dedup: vuln 전용 vs safe 전용 (전역 공유 세트가 아닌 독립 계산) ---")
    print(f"{'구분':<16}{'총량':>10}{'유니크':>10}{'중복제거건':>12}{'중복제거율':>12}")
    for label in ("vuln", "safe"):
        tot = total_codes_by_label[label]
        uniq = unique_codes_by_label[label]
        dup = tot - uniq
        rate = f"{100*dup/tot:.2f}%" if tot else "N/A"
        name = "vulnerable_code" if label == "vuln" else "fixed_code"
        print(f"{name:<16}{tot:>10}{uniq:>10}{dup:>12}{rate:>12}")

    print("\n--- (참고) 전역 공유 seen_hashes(vuln→safe 순서, build_dataset.py와 동일 규칙) 기준 dedup 드롭 ---")
    print(f"  vuln 드롭(먼저 본 safe 코드와 해시충돌): {dedup_drop_global['vuln']}건")
    print(f"  safe 드롭(먼저 본 vuln 코드와 해시충돌): {dedup_drop_global['safe']}건")

    # ── task2: REASON 3단계 폴백 비율 ────────────────────────────────────────
    print("\n" + "=" * 80)
    print("[2] REASON 필드 3단계 폴백 사용 비율 (train+val+test 전체, label=='vuln')")
    print("=" * 80)

    reason_re = re.compile(r"^REASON:\s*(.*)$", re.MULTILINE)
    tier_counter = Counter()
    mismatch = 0
    total_vuln = 0
    missing_lookup = 0

    for split in ("train", "val", "test"):
        path = DATA_DIR / f"{split}.jsonl"
        with path.open() as f:
            for line in f:
                rec = json.loads(line)
                if rec["meta"]["label"] != "vuln":
                    continue
                total_vuln += 1
                cve_id = rec["meta"]["cve_id"]
                cwe_id = rec["meta"]["cwe_id"]

                if cve_id not in cve_desc_by_cve or cwe_id not in cwe_desc_by_cwe:
                    missing_lookup += 1
                    tier_counter["lookup_불가(스트리밍서 못찾음)"] += 1
                    continue

                recomputed_reason, tier = extract_reason_tiered(
                    cve_desc_by_cve[cve_id], cwe_desc_by_cwe[cwe_id]
                )
                if tier == 3:
                    recomputed_reason = f"Vulnerability classified as {cwe_id}."

                m = reason_re.search(rec["completion"])
                actual_reason = m.group(1).strip() if m else ""
                if actual_reason != recomputed_reason:
                    mismatch += 1

                tier_counter[tier] += 1

    print(f"\nvuln 샘플 총 {fmt_int(total_vuln)}건 (train+val+test) 중 REASON 티어 재계산:")
    print(f"{'티어':<45}{'건수':>10}{'비율':>10}")
    tier_labels = {
        1: "① cve_description 패턴 매치",
        2: "② cwe_description 폴백",
        3: "③ 'Vulnerability classified as {CWE}.' 정형문",
    }
    for t in (1, 2, 3):
        n = tier_counter.get(t, 0)
        pct = f"{100*n/total_vuln:.2f}%" if total_vuln else "N/A"
        print(f"{tier_labels[t]:<45}{n:>10}{pct:>10}")
    if missing_lookup:
        pct = f"{100*missing_lookup/total_vuln:.2f}%"
        print(f"{'(lookup 실패 — 원본 스트리밍서 cve/cwe 미발견)':<45}{missing_lookup:>10}{pct:>10}")

    print(f"\nsanity check: 재계산 REASON과 실제 파일 REASON 불일치 {mismatch}건 / {total_vuln - missing_lookup}건 비교")

    # ── 요약 해석 ────────────────────────────────────────────────────────────
    print("\n" + "=" * 80)
    print("요약 해석")
    print("=" * 80)
    print(
        """
[1] 라벨 비대칭(44:56) 해석
build_dataset.py는 vulnerable_code/fixed_code를 쌍으로 묶어 한쪽이 탈락하면 같이
버리는 구조가 아니라, 완전히 독립된 별도 샘플로 취급한다. 따라서 (1-2)의 길이 필터
드롭율이 vuln/safe 간에 차이가 나면 그 차이만큼 최종 라벨 비율이 50:50에서 벌어진다.
여기에 더해 (1-3)에서 vuln 쪽 자체 중복률이 safe 쪽보다 유의하게 높다면, 이는 동일한
취약 패턴(예: 같은 라이브러리의 반복된 취약 함수)이 여러 CVE에 걸쳐 재등장하는 반면
그 수정본(fixed_code)은 프로젝트별로 조금씩 달라 중복 판정을 덜 받는다는 뜻이고,
그 결과 vuln 쪽 최종 샘플 수가 상대적으로 더 깎여 safe > vuln 비율(44:56)로 기운다.
(참고)의 전역 공유 dedup 드롭 건수는 build_dataset.py의 실제 규칙(같은 정규화 해시가
vuln/safe를 가리지 않고 먼저 등장한 쪽을 채택)까지 반영한 수치로, 두 코드가 (드물게도)
정규화 후 동일한 텍스트가 되는 케이스—예: diff가 공백/주석 차이뿐인 fix—를 포착한다.

[2] REASON 폴백 티어 해석
①(cve_description에서 원인 서술 문장 추출)이 가장 많이 쓰였다면 NVD 설명 품질이
전반적으로 준수하다는 뜻이고, ③(정형 문장)의 비중이 낮다면 CWE 라벨은 있으나
설명이 빈약한 CVE가 드물다는 뜻이다. 반대로 ③ 비중이 크다면 학습 데이터의 REASON
텍스트가 다양성 없이 같은 문장("Vulnerability classified as {CWE-id}.")으로 뭉치는
CWE-id가 많아, 모델이 REASON 생성을 사실상 CWE-id 암기로 풀 위험이 있다는 신호다.
"""
    )


if __name__ == "__main__":
    main()
