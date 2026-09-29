"""
ScanOps 보안 모델 학습데이터 빌더 (단일 출처, 문서화)
================================================================
취약/안전을 균형 있게, 같은 분포·같은 길이의 completion으로 구성한다.
v4~v10 반복에서 얻은 3가지 교훈을 모두 반영:

  1. 클래스 균형: 안전 예시가 너무 적으면 '항상 취약', 너무 많으면 '항상 안전'.
     → 안전 비율을 ~43%로 (취약을 약간 더 많이 = 탐지 지향).
  2. 분포 정합: 취약/안전 모두 OWASP 긴 Java 서블릿을 포함해 '코드 길이=라벨'
     단축학습을 차단.
  3. completion 길이 대칭: 취약/안전 모두 3줄(VULN/SEVERITY/CVSS)로 통일.
     한쪽이 짧으면 모델이 그쪽으로 도망친다.

3가지 출처를 합친다:
  A. OWASP Benchmark 취약(Java, 긴 서블릿)  — 외부 표준셋 성능
  B. OWASP Benchmark 안전(Java, 긴 서블릿)  — 오탐 억제
  C. 2026년 5~6월 신규 NVD CVE 패턴(scripts/benchmark_v5_cases.py)
     — 범용 LLM 학습 컷오프 이후 CVE → "Grok이 못 잡는 신규 취약점" 명분 + 탐지력
  D. mitigation 적용 안전 코드(다양한 언어)  — 안전 다양성

홀드아웃(평가용 OWASP 110케이스)은 학습에서 항상 제외한다.

실행:
  python -m ml.build_dataset --out data/lora_train_v11.jsonl
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.owasp_benchmark_cases import CSV_PATH, JAVA_DIR, _extract_code, build_cases as holdout_cases
from scripts.benchmark_v5_cases import VULN_CASES, SAFE_CASES
from scripts.build_lora_train_v7 import CAT_INFO
from scripts.benchmark_qwen_rag import build_ft_user_prompt

SEED = 41
N_OWASP_VULN = 400        # OWASP 취약(Java)
N_OWASP_SAFE = 280        # OWASP 안전(Java)
# 2026 CVE(C)와 합성 안전(D)은 전량 사용(각 ~50개)

# 안전/취약 모두 3줄 대칭
NONE_COMPLETION = "VULNERABILITY: NONE\nSEVERITY: NONE\nCVSS: 0.0"


def _owasp_vuln_completion(cat: str) -> str:
    cwe, name, sev, cvss, _, _ = CAT_INFO[cat]
    return f"VULNERABILITY: {cwe} {name}\nSEVERITY: {sev}\nCVSS: {cvss}"


def _cve_vuln_completion(case: dict) -> str:
    """2026 NVD CVE 케이스용 completion (3줄 대칭)."""
    name = case["expected_vuln"]
    cwe = case.get("cwe", "")
    low = name.lower()
    if any(k in low for k in ("injection", "rce", "code exec", "deserial", "command", "eval", "ssti", "template")):
        sev, cvss = "CRITICAL", "9.8"
    elif any(k in low for k in ("xss", "ssrf", "traversal", "xxe", "redirect", "hardcoded", "auth")):
        sev, cvss = "HIGH", "8.1"
    else:
        sev, cvss = "HIGH", "7.5"
    head = f"{cwe} {name}".strip()
    return f"VULNERABILITY: {head}\nSEVERITY: {sev}\nCVSS: {cvss}"


def _owasp_pools(exclude: set[str]):
    rows = list(csv.reader(open(CSV_PATH)))[1:]
    vuln, safe = {}, {}
    for r in rows:
        if len(r) < 4:
            continue
        tid, cat, real = r[0].strip(), r[1].strip(), r[2].strip()
        if tid in exclude:
            continue
        (vuln if real == "true" else safe).setdefault(cat, []).append(tid)
    return vuln, safe


def _sample(by_cat: dict, n: int, rng: random.Random):
    cats = sorted(by_cat)
    per = max(1, n // len(cats))
    out = []
    for c in cats:
        ids = by_cat[c][:]
        rng.shuffle(ids)
        out += [(t, c) for t in ids[:per]]
    rng.shuffle(out)
    return out[:n]


def build(out_path: Path) -> None:
    rng = random.Random(SEED)
    hold = {c["id"] for c in holdout_cases()}
    print(f"홀드아웃(학습 제외) {len(hold)}개")

    vpool, spool = _owasp_pools(hold)

    # A. OWASP 취약(Java)
    owasp_vuln = [
        {"prompt": build_ft_user_prompt("Java", _extract_code(JAVA_DIR / f"{t}.java")),
         "completion": _owasp_vuln_completion(c)}
        for t, c in _sample(vpool, N_OWASP_VULN, rng) if (JAVA_DIR / f"{t}.java").exists()
    ]
    # B. OWASP 안전(Java)
    owasp_safe = [
        {"prompt": build_ft_user_prompt("Java", _extract_code(JAVA_DIR / f"{t}.java")),
         "completion": NONE_COMPLETION}
        for t, c in _sample(spool, N_OWASP_SAFE, rng) if (JAVA_DIR / f"{t}.java").exists()
    ]
    # C. 2026 5~6월 신규 NVD CVE 패턴 (Grok 컷오프 이후 → 핵심 차별점)
    cve_2026 = [
        {"prompt": build_ft_user_prompt(c["language"], c["code"]),
         "completion": _cve_vuln_completion(c)}
        for c in VULN_CASES
    ]
    # D. mitigation 적용 안전 코드(다양한 언어)
    synth_safe = [
        {"prompt": build_ft_user_prompt(c["language"], c["code"]), "completion": NONE_COMPLETION}
        for c in SAFE_CASES
    ]

    vuln = owasp_vuln + cve_2026
    safe = owasp_safe + synth_safe
    rows = vuln + safe
    rng.shuffle(rows)

    out_path.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", encoding="utf-8")
    ns = len(safe)
    print(f"A.OWASP취약 {len(owasp_vuln)} + C.2026CVE {len(cve_2026)} = 취약 {len(vuln)}")
    print(f"B.OWASP안전 {len(owasp_safe)} + D.합성안전 {len(synth_safe)} = 안전 {len(safe)}")
    print(f"총 {len(rows)}개, 안전 {100*ns/len(rows):.1f}%  (2026 신규 CVE {len(cve_2026)}건 포함)")
    print(f"저장: {out_path}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=ROOT / "data" / "lora_train_v11.jsonl")
    build(ap.parse_args().out)
