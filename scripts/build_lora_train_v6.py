"""
QLoRA v6 학습데이터 — 학습/추론 프롬프트 정합 + 클래스 균형
====================================================================
v5 진단: 안전 예시를 40%로 늘렸지만, 학습데이터에 NONE으로 넣은
파라미터화 쿼리조차 추론 시 여전히 'SQL Injection'으로 오탐.

가설(핵심): 학습 프롬프트와 추론 프롬프트가 달랐다.
  - 학습(v4/v5): "Analyze this {lang} code...:\n\n{code}"  (단순)
  - 추론(production, build_ft_user_prompt):
    "Analyze this {lang} code...:\n\n```{hint}\n{code}\n```\n\n{OUTPUT_FORMAT}"
  → 모델은 OUTPUT_FORMAT(NONE 지시문 포함)을 학습 중 한 번도 못 봤으므로,
    추론 시 그 지시를 따를 이유가 없었다.

v6 수정:
  1. 학습 프롬프트를 production의 build_ft_user_prompt와 100% 동일하게 생성
     (코드펜스 + SAFE 탈출구가 포함된 OUTPUT_FORMAT).
  2. 안전(NONE) 예시 비율을 ~50%로 더 끌어올림 (취약 편향 상쇄 강화).
  3. 취약 예시 completion에 CVSS 라인 보강(OUTPUT_FORMAT과 정합).

실행:
  source .venv/bin/activate
  python scripts/build_lora_train_v6.py
출력:
  data/lora_train_v6.jsonl
"""
from __future__ import annotations

import csv
import json
import random
import re
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(BASE / "scripts"))

from scripts.owasp_benchmark_cases import (
    CSV_PATH, JAVA_DIR, _extract_code, build_cases as build_holdout_cases,
)
from scripts.benchmark_v5_cases import SAFE_CASES, VULN_CASES
from scripts.benchmark_qwen_rag import build_ft_user_prompt

OUT = BASE / "data" / "lora_train_v6.jsonl"
V4_PATH = BASE / "data" / "lora_train_v4.jsonl"
SEED = 11
N_OWASP_SAFE = 110   # v5(40% 안전)가 탐지율을 과교정시킴 → ~35%로 낮춰 균형

NONE_COMPLETION = (
    "VULNERABILITY: NONE\n"
    "SEVERITY: NONE\n"
    "CVSS: N/A\n"
    "ATTACK: 없음 — 이 코드에는 실제로 악용 가능한 취약점이 없습니다.\n"
    "FIX: 수정 불필요."
)


def _reformat_prompt(old_prompt: str) -> tuple[str, str]:
    """v4 데이터의 단순 프롬프트에서 language/code를 복원해
    build_ft_user_prompt 포맷으로 변환한다."""
    m = re.match(r"Analyze this (.+?) code for security vulnerabilities:\s*\n+(.*)",
                 old_prompt, re.DOTALL)
    if not m:
        # 포맷 불일치 시 통째로 Unknown 처리
        return "Unknown", old_prompt
    return m.group(1).strip(), m.group(2).strip()


def _ensure_cvss(completion: str) -> str:
    """취약 completion에 CVSS 라인이 없으면 SEVERITY 뒤에 추가(OUTPUT_FORMAT 정합)."""
    if "CVSS:" in completion.upper():
        return completion
    lines = completion.split("\n")
    out = []
    for ln in lines:
        out.append(ln)
        if ln.upper().startswith("SEVERITY:"):
            sev = ln.split(":", 1)[1].strip().upper()
            cvss = {"CRITICAL": "9.8", "HIGH": "7.5", "MEDIUM": "5.3", "LOW": "3.1"}.get(sev, "7.5")
            out.append(f"CVSS: {cvss}")
    return "\n".join(out)


def load_v4_vuln() -> list[dict]:
    rows = []
    with open(V4_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            comp = d["completion"]
            # v4의 안전/NONE 예시(3개)는 아래 통합 안전셋으로 대체하므로 제외
            if comp.split("\n")[0].upper().startswith(("VULNERABILITY: NONE", "VULNERABILITY: NO")):
                continue
            lang, code = _reformat_prompt(d["prompt"])
            rows.append({
                "prompt": build_ft_user_prompt(lang, code),
                "completion": _ensure_cvss(comp),
            })
    return rows


def owasp_safe_examples(exclude_ids: set[str], n: int) -> list[dict]:
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
    per_cat = max(1, n // len(cats))
    picked: list[str] = []
    for cat in cats:
        ids = by_cat[cat][:]
        rng.shuffle(ids)
        picked.extend(ids[:per_cat])
    rng.shuffle(picked)
    picked = picked[:n]

    out = []
    for test_id in picked:
        java_file = JAVA_DIR / f"{test_id}.java"
        if not java_file.exists():
            continue
        code = _extract_code(java_file)
        out.append({
            "prompt": build_ft_user_prompt("Java", code),
            "completion": NONE_COMPLETION,
        })
    return out


def safe_case_examples() -> list[dict]:
    return [
        {"prompt": build_ft_user_prompt(c["language"], c["code"]), "completion": NONE_COMPLETION}
        for c in SAFE_CASES
    ]


def main():
    holdout_ids = {c["id"] for c in build_holdout_cases()}
    print(f"홀드아웃(벤치마크용, 학습 제외) {len(holdout_ids)}개")

    vuln = load_v4_vuln()
    safe_owasp = owasp_safe_examples(holdout_ids, N_OWASP_SAFE)
    safe_synth = safe_case_examples()
    safe = safe_owasp + safe_synth

    all_rows = vuln + safe
    rng = random.Random(SEED)
    rng.shuffle(all_rows)

    n_none = len(safe)
    print(f"취약 예시(프롬프트 재포맷): {len(vuln)}개")
    print(f"안전(NONE): OWASP {len(safe_owasp)} + 합성 {len(safe_synth)} = {len(safe)}개")
    print(f"총 {len(all_rows)}개 (안전 비율 {100*n_none/len(all_rows):.1f}%)")

    with open(OUT, "w", encoding="utf-8") as f:
        for row in all_rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"저장: {OUT}")
    # 샘플 확인
    print("\n--- 안전 예시 프롬프트 샘플 ---")
    print(safe[0]["prompt"][:400])


if __name__ == "__main__":
    main()
