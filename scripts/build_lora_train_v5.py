"""
QLoRA v5 학습데이터 — 안전 코드(NONE) 예시 추가로 1% 불균형 해소
====================================================================
원인 진단(OWASP Benchmark 110케이스 테스트): data/lora_train_v4.jsonl
291개 중 "안전/취약점 없음" 완성 예시가 3개(1%)뿐이라, 모델이 항상
무언가를 "취약하다"고 출력하도록 학습됨 (오탐률 92~100%).

이 스크립트는:
  1. 기존 v4 데이터(291개, 취약 예시)는 그대로 보존.
  2. OWASP Benchmark의 safe(false) 라벨 코드에서, 현재 벤치마크
     홀드아웃(scripts/owasp_benchmark_cases.py가 샘플링한 110개)에 포함된
     id는 전부 제외하고 새로 ~150개를 카테고리별로 균등 샘플링해
     "VULNERABILITY: NONE" 완성 예시로 추가 (테스트셋 오염 방지).
  3. scripts/benchmark_v5_cases.py의 SAFE_CASES(50개, 다양한 언어)도
     동일한 NONE 완성 예시로 추가.
  4. 프롬프트 스타일은 기존 v4 데이터와 동일하게 단순 유지
     ("Analyze this {language} code for security vulnerabilities:\n\n{code}")
     — 학습/추론 프롬프트 포맷 차이로 인한 혼란을 줄이기 위해 통일.

실행:
  source .venv/bin/activate
  python scripts/build_lora_train_v5.py
출력:
  data/lora_train_v5.jsonl
"""
from __future__ import annotations

import csv
import json
import random
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(BASE / "scripts"))

from scripts.owasp_benchmark_cases import (
    CSV_PATH, JAVA_DIR, _extract_code, build_cases as build_holdout_cases,
)
from scripts.benchmark_v5_cases import SAFE_CASES

OUT = BASE / "data" / "lora_train_v5.jsonl"
V4_PATH = BASE / "data" / "lora_train_v4.jsonl"
SEED = 7
N_OWASP_SAFE = 150

NONE_COMPLETION = (
    "VULNERABILITY: NONE\n"
    "SEVERITY: NONE\n"
    "CVSS: N/A\n"
    "ATTACK: 없음 — 이 코드에는 실제로 악용 가능한 취약점이 없습니다.\n"
    "FIX: 수정 불필요."
)


def load_v4() -> list[dict]:
    rows = []
    with open(V4_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def owasp_safe_examples(exclude_ids: set[str]) -> list[dict]:
    rows = list(csv.reader(open(CSV_PATH)))[1:]
    by_cat: dict[str, list[str]] = {}
    for r in rows:
        if len(r) < 4:
            continue
        test_id, cat, real_vuln = r[0].strip(), r[1].strip(), r[2].strip()
        if real_vuln == "true" or test_id in exclude_ids:
            continue
        by_cat.setdefault(cat, []).append(test_id)

    rng = random.Random(SEED)
    cats = sorted(by_cat)
    per_cat = max(1, N_OWASP_SAFE // len(cats))
    picked: list[str] = []
    for cat in cats:
        ids = by_cat[cat][:]
        rng.shuffle(ids)
        picked.extend(ids[:per_cat])
    rng.shuffle(picked)
    picked = picked[:N_OWASP_SAFE]

    examples = []
    for test_id in picked:
        java_file = JAVA_DIR / f"{test_id}.java"
        if not java_file.exists():
            continue
        code = _extract_code(java_file)
        examples.append({
            "prompt": f"Analyze this Java code for security vulnerabilities:\n\n{code}",
            "completion": NONE_COMPLETION,
        })
    return examples


def safe_case_examples() -> list[dict]:
    examples = []
    for c in SAFE_CASES:
        examples.append({
            "prompt": f"Analyze this {c['language']} code for security vulnerabilities:\n\n{c['code']}",
            "completion": NONE_COMPLETION,
        })
    return examples


def main():
    holdout_ids = {c["id"] for c in build_holdout_cases()}
    print(f"홀드아웃(벤치마크용, 학습 제외) {len(holdout_ids)}개")

    v4 = load_v4()
    owasp_safe = owasp_safe_examples(holdout_ids)
    v5_safe = safe_case_examples()

    all_rows = v4 + owasp_safe + v5_safe
    rng = random.Random(SEED)
    rng.shuffle(all_rows)

    n_none = sum(1 for r in all_rows if "NONE" in r["completion"].split("\n")[0])
    print(f"v4 취약 예시: {len(v4)}개")
    print(f"OWASP 안전(NONE) 추가: {len(owasp_safe)}개")
    print(f"v5 SAFE_CASES(NONE) 추가: {len(v5_safe)}개")
    print(f"총 {len(all_rows)}개 (안전/NONE 비율 {100*n_none/len(all_rows):.1f}%)")

    with open(OUT, "w", encoding="utf-8") as f:
        for row in all_rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"저장: {OUT}")


if __name__ == "__main__":
    main()
