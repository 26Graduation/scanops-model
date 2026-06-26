"""
QLoRA v7 학습데이터 — 스타일 단축학습(spurious shortcut) 차단
====================================================================
v6 진단: 취약 예시=짧은 합성 스니펫, 안전 예시=긴 OWASP Java 서블릿이라
모델이 보안 의미가 아니라 '코드 길이/스타일 = 라벨'을 학습 → OWASP
홀드아웃(전부 긴 Java)에 전부 NONE(recall 0%).

v7 수정(핵심): 취약/안전 예시를 같은 분포(OWASP 긴 Java 서블릿)로 균형 있게
구성해 스타일 단축경로를 제거한다.
  - OWASP 취약(true, 홀드아웃 제외): 카테고리별 CWE 완성예시로 변환
  - OWASP 안전(false, 홀드아웃 제외): NONE 완성예시
  - 합성 데이터(v4 취약 일부 + SAFE_CASES)는 언어 다양성용으로 소량 보조
프롬프트는 production build_ft_user_prompt와 100% 동일 포맷.

실행:
  source .venv/bin/activate
  python scripts/build_lora_train_v7.py
출력:
  data/lora_train_v8.jsonl
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
from scripts.benchmark_v5_cases import SAFE_CASES
from scripts.benchmark_qwen_rag import build_ft_user_prompt

OUT = BASE / "data" / "lora_train_v8.jsonl"
V4_PATH = BASE / "data" / "lora_train_v4.jsonl"
SEED = 17
N_OWASP_VULN = 400   # OWASP 취약(긴 Java) — 스타일 단축경로 차단의 핵심
N_OWASP_SAFE = 400   # OWASP 안전(긴 Java) — 균형
N_SYNTH_VULN = 80   # 합성 취약(짧은 스니펫, 언어 다양성 보조)

# 카테고리 → (CWE, 취약점명, 심각도, CVSS, 공격설명, 수정방법)
CAT_INFO = {
    "sqli": ("CWE-89", "SQL Injection", "CRITICAL", "9.8",
             "사용자 입력이 검증 없이 SQL 쿼리에 직접 연결되어 임의 쿼리 실행이 가능합니다.",
             "PreparedStatement와 파라미터 바인딩(setString 등)을 사용하세요."),
    "xss": ("CWE-79", "Cross-Site Scripting", "HIGH", "7.5",
            "사용자 입력이 이스케이프 없이 HTML 응답에 출력되어 악성 스크립트가 실행될 수 있습니다.",
            "출력 시 HTML 엔티티 인코딩(ESAPI.encoder().encodeForHTML)을 적용하세요."),
    "cmdi": ("CWE-78", "OS Command Injection", "CRITICAL", "9.8",
             "사용자 입력이 시스템 명령에 연결되어 임의 OS 명령 실행이 가능합니다.",
             "명령을 직접 조립하지 말고 화이트리스트 검증 또는 안전한 API를 사용하세요."),
    "pathtraver": ("CWE-22", "Path Traversal", "HIGH", "7.5",
                   "사용자 입력이 파일 경로에 사용되어 ../ 등으로 임의 파일 접근이 가능합니다.",
                   "경로를 정규화(canonicalize)한 뒤 허용 디렉터리 내인지 검증하세요."),
    "crypto": ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm", "MEDIUM", "5.9",
               "취약하거나 구식인 암호 알고리즘(DES 등)을 사용해 암호문이 복호화될 수 있습니다.",
               "AES-GCM 등 검증된 강력한 알고리즘과 안전한 모드를 사용하세요."),
    "hash": ("CWE-328", "Use of Weak Hash", "MEDIUM", "5.3",
             "MD5/SHA-1 등 충돌에 취약한 해시를 사용해 무결성이 보장되지 않습니다.",
             "SHA-256 이상, 비밀번호엔 bcrypt/Argon2 같은 강한 해시를 사용하세요."),
    "ldapi": ("CWE-90", "LDAP Injection", "HIGH", "7.5",
              "사용자 입력이 LDAP 필터에 직접 연결되어 인증 우회/정보 노출이 가능합니다.",
              "LDAP 특수문자를 이스케이프하거나 안전한 필터 빌더를 사용하세요."),
    "xpathi": ("CWE-643", "XPath Injection", "HIGH", "7.5",
               "사용자 입력이 XPath 쿼리에 직접 연결되어 임의 노드 조회가 가능합니다.",
               "XPath 변수 바인딩 또는 입력 이스케이프를 사용하세요."),
    "trustbound": ("CWE-501", "Trust Boundary Violation", "MEDIUM", "5.3",
                   "신뢰할 수 없는 사용자 입력이 세션 등 신뢰 영역에 그대로 저장됩니다.",
                   "신뢰 경계를 넘기 전 입력을 검증/정제하세요."),
    "securecookie": ("CWE-614", "Sensitive Cookie Without Secure Flag", "MEDIUM", "5.3",
                     "Secure 플래그 없이 쿠키를 설정해 평문 채널로 쿠키가 노출될 수 있습니다.",
                     "쿠키에 setSecure(true)와 setHttpOnly(true)를 설정하세요."),
    "weakrand": ("CWE-330", "Use of Insufficiently Random Values", "MEDIUM", "5.3",
                 "java.util.Random 등 예측 가능한 난수를 보안 용도로 사용합니다.",
                 "SecureRandom을 사용해 예측 불가능한 난수를 생성하세요."),
}


def _vuln_completion(cat: str) -> str:
    cwe, name, sev, cvss, attack, fix = CAT_INFO[cat]
    return (f"VULNERABILITY: {cwe} {name}\n"
            f"SEVERITY: {sev}\n"
            f"CVSS: {cvss}\n"
            f"ATTACK: {attack}\n"
            f"FIX: {fix}")


NONE_COMPLETION = (
    "VULNERABILITY: NONE\n"
    "SEVERITY: NONE\n"
    "CVSS: N/A\n"
    "ATTACK: 없음 — 이 코드에는 실제로 악용 가능한 취약점이 없습니다.\n"
    "FIX: 수정 불필요."
)


def _owasp_by_label(exclude_ids: set[str]) -> tuple[dict, dict]:
    rows = list(csv.reader(open(CSV_PATH)))[1:]
    vuln_by_cat: dict[str, list[str]] = {}
    safe_by_cat: dict[str, list[str]] = {}
    for r in rows:
        if len(r) < 4:
            continue
        tid, cat, real = r[0].strip(), r[1].strip(), r[2].strip()
        if tid in exclude_ids:
            continue
        (vuln_by_cat if real == "true" else safe_by_cat).setdefault(cat, []).append(tid)
    return vuln_by_cat, safe_by_cat


def _sample_balanced(by_cat: dict[str, list[str]], n: int, rng: random.Random) -> list[tuple[str, str]]:
    cats = sorted(by_cat)
    per = max(1, n // len(cats))
    picked: list[tuple[str, str]] = []
    for cat in cats:
        ids = by_cat[cat][:]
        rng.shuffle(ids)
        picked.extend((tid, cat) for tid in ids[:per])
    rng.shuffle(picked)
    return picked[:n]


def _owasp_examples(picked: list[tuple[str, str]], vulnerable: bool) -> list[dict]:
    out = []
    for tid, cat in picked:
        jf = JAVA_DIR / f"{tid}.java"
        if not jf.exists():
            continue
        code = _extract_code(jf)
        out.append({
            "prompt": build_ft_user_prompt("Java", code),
            "completion": _vuln_completion(cat) if vulnerable else NONE_COMPLETION,
        })
    return out


def _synth_vuln(n: int, rng: random.Random) -> list[dict]:
    rows = []
    with open(V4_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            if d["completion"].split("\n")[0].upper().startswith(("VULNERABILITY: NONE", "VULNERABILITY: NO")):
                continue
            m = re.match(r"Analyze this (.+?) code for security vulnerabilities:\s*\n+(.*)",
                         d["prompt"], re.DOTALL)
            if not m:
                continue
            lang, code = m.group(1).strip(), m.group(2).strip()
            comp = d["completion"]
            if "CVSS:" not in comp.upper():
                _cvss_map = {"CRITICAL": "9.8", "HIGH": "7.5", "MEDIUM": "5.3", "LOW": "3.1"}
                out = []
                for ln in comp.split("\n"):
                    out.append(ln)
                    if ln.upper().startswith("SEVERITY:"):
                        sev = ln.split(":", 1)[1].strip().upper()
                        out.append(f"CVSS: {_cvss_map.get(sev, '7.5')}")
                comp = "\n".join(out)
            rows.append({"prompt": build_ft_user_prompt(lang, code), "completion": comp})
    rng.shuffle(rows)
    return rows[:n]


def main():
    rng = random.Random(SEED)
    holdout_ids = {c["id"] for c in build_holdout_cases()}
    print(f"홀드아웃(학습 제외) {len(holdout_ids)}개")

    vuln_by_cat, safe_by_cat = _owasp_by_label(holdout_ids)
    owasp_vuln = _owasp_examples(_sample_balanced(vuln_by_cat, N_OWASP_VULN, rng), vulnerable=True)
    owasp_safe = _owasp_examples(_sample_balanced(safe_by_cat, N_OWASP_SAFE, rng), vulnerable=False)
    synth_vuln = _synth_vuln(N_SYNTH_VULN, rng)
    synth_safe = [{"prompt": build_ft_user_prompt(c["language"], c["code"]),
                   "completion": NONE_COMPLETION} for c in SAFE_CASES]

    vuln = owasp_vuln + synth_vuln
    safe = owasp_safe + synth_safe
    all_rows = vuln + safe
    rng.shuffle(all_rows)

    print(f"취약: OWASP {len(owasp_vuln)} + 합성 {len(synth_vuln)} = {len(vuln)}개")
    print(f"안전: OWASP {len(owasp_safe)} + 합성 {len(synth_safe)} = {len(safe)}개")
    print(f"총 {len(all_rows)}개 (안전 비율 {100*len(safe)/len(all_rows):.1f}%)")
    print("→ 취약/안전 모두 OWASP 긴 Java 서블릿 포함 → 스타일 단축경로 차단")

    with open(OUT, "w", encoding="utf-8") as f:
        for row in all_rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"저장: {OUT}")


if __name__ == "__main__":
    main()
