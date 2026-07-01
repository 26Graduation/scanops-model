"""
ScanOps V12 학습데이터 빌더 — OWASP 0% (과적합 원천 차단)
================================================================
V11과의 결정적 차이: **OWASP Benchmark 코드를 학습에서 100% 제외**한다.
V11은 OWASP 취약/안전 서블릿(A,B)을 학습에 넣고 OWASP로 평가해 "같은 시험지로
공부한" 데이터 누수가 있었다. V12는 OWASP를 순수 zero-shot 평가셋으로만 쓴다.

따라서 V12에서 OWASP·CVEfixes(평가용 2벤치마크) 성능이 높게 나오면, 그것은
학습으로 외운 게 아니라 (1) 진짜 일반화 + (2) 규칙기반 taint 그래프 덕분이며,
이것이 곧 "과적합이 아니다"라는 증거가 된다.

데이터 출처 (모두 OWASP-free, 다언어):
  A. v4 학습셋의 취약 코드 (Python/Node/Java/C/C++/PHP/Go/Ruby/Kotlin 등)
  B. v5 학습셋의 안전 코드 중 **OWASP 서블릿이 아닌 것만**
  C. 2026 신규 NVD CVE 코드 (scripts/benchmark_v5_cases.py: 취약 50 + 안전 50)
     — 범용 LLM 학습 컷오프 이후 → "Grok이 못 보는 신규 취약점" 명분

과적합 방지 장치:
  1. OWASP 서블릿 코드(HttpServletRequest/BenchmarkTest 흔적)는 무조건 배제.
  2. OWASP 홀드아웃 110케이스 코드 해시를 학습에서 제외.
  3. CVEfixes 평가셋 코드 해시도 (파일이 있으면) 제외.
  4. 코드 해시 dedup — 같은 코드 중복 금지.
  5. train/val 90:10 stratified 분리 → Colab에서 과적합(val loss 발산) 감시.
  6. completion 3줄 대칭(VULN/SEVERITY/CVSS) — "긴 코드=안전" 단축학습 차단.

실행:
  python -m ml.build_dataset_v12 --out data/lora_train_v12_clean.jsonl
산출: <out>(train) + <out 옆>_val.jsonl(검증)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.benchmark_v5_cases import VULN_CASES, SAFE_CASES
from scripts.benchmark_qwen_rag import build_ft_user_prompt
from scripts.v12_cases import expand as v12_pairs

SEED = 41
SAFE_RATIO_TARGET = 0.44          # 안전 비율 목표(취약 지향 약간)
NONE_COMPLETION = "VULNERABILITY: NONE\nSEVERITY: NONE\nCVSS: 0.0"

# ── 코드 정규화 & 해시 (dedup / 누수 차단) ────────────────────────────────────
def _norm_code(code: str) -> str:
    return re.sub(r"\s+", " ", code or "").strip().lower()

def _h(code: str) -> str:
    return hashlib.sha1(_norm_code(code).encode()).hexdigest()

def _is_owasp(code: str, lang: str = "") -> bool:
    """OWASP 서블릿/벤치마크 흔적이면 학습에서 배제."""
    blob = f"{code}\n{lang}"
    return any(k in blob for k in (
        "HttpServletRequest", "HttpServletResponse", "BenchmarkTest",
        "doPost", "doGet", "org.owasp",
    ))

# ── severity → CVSS 매핑 (3줄 대칭 보정용) ─────────────────────────────────────
_SEV_CVSS = {"CRITICAL": "9.8", "HIGH": "8.1", "MEDIUM": "5.5", "LOW": "3.5"}

def _cvss_for(name: str, sev: str) -> str:
    low = name.lower()
    if any(k in low for k in ("injection", "rce", "code exec", "deserial",
                              "command", "eval", "ssti", "template")):
        return "9.8"
    if any(k in low for k in ("xss", "ssrf", "traversal", "xxe",
                              "redirect", "hardcoded", "auth")):
        return "8.1"
    return _SEV_CVSS.get(sev.upper(), "7.5")

# ── 기존 jsonl에서 코드+라벨 수확 ─────────────────────────────────────────────
_LANG_RE = re.compile(r"Analyze this (.+?) code", re.I)
_FENCE_RE = re.compile(r"```[a-zA-Z+#./]*\n(.*?)```", re.S)
# OUTPUT_FORMAT/지시문 블록 시작 마커 — 코드 추출 시 잘라낸다
_TAIL_MARKERS = ("First decide", "Respond starting", "Supplementary CVE")

def _parse_prompt(prompt: str) -> tuple[str, str] | None:
    lm = _LANG_RE.search(prompt)
    if not lm:
        return None
    lang = lm.group(1).strip()
    # 1) 코드펜스가 있으면 그 안을 사용
    fm = _FENCE_RE.search(prompt)
    if fm:
        return lang, fm.group(1).strip()
    # 2) 펜스가 없으면 "...vulnerabilities:" 다음부터 지시문 전까지가 코드
    m = re.search(r"vulnerabilit(?:y|ies)[:\.]\s*\n+", prompt, re.I)
    if not m:
        return None
    code = prompt[m.end():]
    for mk in _TAIL_MARKERS:
        idx = code.find(mk)
        if idx != -1:
            code = code[:idx]
    code = code.strip()
    return (lang, code) if code else None

def _three_line_vuln(completion: str) -> str | None:
    """기존 completion(VULN/SEVERITY/...)을 3줄 대칭으로 정규화."""
    lines = completion.splitlines()
    vuln = next((l for l in lines if l.upper().startswith("VULNERABILITY:")), None)
    if not vuln or "NONE" in vuln.upper():
        return None
    name = vuln.split(":", 1)[1].strip()
    sev_line = next((l for l in lines if l.upper().startswith("SEVERITY:")), "")
    sev = sev_line.split(":", 1)[1].strip().upper() if ":" in sev_line else "HIGH"
    if sev not in _SEV_CVSS:
        sev = "HIGH"
    cvss = _cvss_for(name, sev)
    return f"VULNERABILITY: {name}\nSEVERITY: {sev}\nCVSS: {cvss}"

def harvest(path: Path, want_safe: bool):
    """jsonl에서 (lang, code, completion, is_safe) 수확. OWASP는 건너뜀."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        parsed = _parse_prompt(r.get("prompt", ""))
        if not parsed:
            continue
        lang, code = parsed
        if _is_owasp(code, lang):
            continue
        is_safe = "NONE" in r.get("completion", "")
        if want_safe and not is_safe:
            continue
        if (not want_safe) and is_safe:
            continue
        comp = NONE_COMPLETION if is_safe else _three_line_vuln(r["completion"])
        if comp is None:
            continue
        yield lang, code, comp, is_safe

# ── 평가셋(OWASP 홀드아웃 + CVEfixes) 코드 해시 → 학습 제외 ────────────────────
def _excluded_hashes() -> set[str]:
    ex: set[str] = set()
    # OWASP 홀드아웃 110
    try:
        from scripts.owasp_benchmark_cases import build_cases, JAVA_DIR, _extract_code
        for c in build_cases():
            jf = JAVA_DIR / f"{c['id']}.java"
            if jf.exists():
                ex.add(_h(_extract_code(jf)))
    except Exception as e:  # noqa: BLE001
        print(f"  (OWASP 홀드아웃 해시 스킵: {e})")
    # CVEfixes 평가셋 (있으면)
    cvf = ROOT / "data" / "cvefixes_benchmark.jsonl"
    if cvf.exists():
        for line in cvf.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    ex.add(_h(json.loads(line).get("code", "")))
                except Exception:  # noqa: BLE001
                    pass
    return ex

# ── 빌드 ──────────────────────────────────────────────────────────────────────
def build(out_path: Path) -> None:
    rng = random.Random(SEED)
    excluded = _excluded_hashes()
    print(f"평가셋 제외 해시 {len(excluded)}개")

    seen: set[str] = set()
    vuln: list[dict] = []
    safe: list[dict] = []

    def add(lang: str, code: str, comp: str, is_safe: bool):
        hh = _h(code)
        if hh in excluded or hh in seen or not code.strip():
            return
        seen.add(hh)
        row = {"prompt": build_ft_user_prompt(lang, code), "completion": comp}
        (safe if is_safe else vuln).append(row)

    # A. v4 취약 코드 (다언어) — v2/v3도 추가 다양성으로 합침(중복은 dedup)
    for v in ("v4", "v3", "v2"):
        for lang, code, comp, _ in harvest(ROOT / "data" / f"lora_train_{v}.jsonl", want_safe=False):
            add(lang, code, comp, False)
    # B. v5 안전 코드 (OWASP 제외)
    for lang, code, comp, _ in harvest(ROOT / "data" / "lora_train_v5.jsonl", want_safe=True):
        add(lang, code, comp, True)
    # C. 2026 신규 NVD CVE (취약 + 안전)
    for c in VULN_CASES:
        name = c["expected_vuln"]
        cwe = c.get("cwe", "")
        head = f"{cwe} {name}".strip()
        comp = f"VULNERABILITY: {head}\nSEVERITY: {'CRITICAL' if _cvss_for(name,'')=='9.8' else 'HIGH'}\nCVSS: {_cvss_for(name,'HIGH')}"
        add(c["language"], c["code"], comp, False)
    for c in SAFE_CASES:
        add(c["language"], c["code"], NONE_COMPLETION, True)
    # D. V12 paired 뱅크 (취약/안전 쌍, OWASP-free) — 판별력 강화
    for lang, code, name, cwe, is_safe in v12_pairs():
        if is_safe:
            add(lang, code, NONE_COMPLETION, True)
        else:
            head = f"{cwe} {name}".strip()
            comp = f"VULNERABILITY: {head}\nSEVERITY: {'CRITICAL' if _cvss_for(name,'')=='9.8' else 'HIGH'}\nCVSS: {_cvss_for(name,'HIGH')}"
            add(lang, code, comp, False)

    # 균형 맞추기: 안전 비율을 SAFE_RATIO_TARGET에 맞춰 취약을 캡
    rng.shuffle(vuln)
    rng.shuffle(safe)
    n_safe = len(safe)
    # safe / (safe + vuln) = ratio  →  vuln = safe*(1-ratio)/ratio
    max_vuln = int(round(n_safe * (1 - SAFE_RATIO_TARGET) / SAFE_RATIO_TARGET))
    vuln = vuln[:max_vuln]

    rows = vuln + safe
    rng.shuffle(rows)

    # train/val 90:10 stratified
    def split(items):
        k = max(1, int(len(items) * 0.10))
        return items[k:], items[:k]
    v_tr, v_va = split(vuln)
    s_tr, s_va = split(safe)
    train = v_tr + s_tr
    val = v_va + s_va
    rng.shuffle(train)
    rng.shuffle(val)

    out_path.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in train) + "\n", encoding="utf-8")
    val_path = out_path.with_name(out_path.stem + "_val.jsonl")
    val_path.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in val) + "\n", encoding="utf-8")

    total = len(rows)
    print("─" * 60)
    print(f"총 {total}개  (취약 {len(vuln)} / 안전 {len(safe)}, 안전 {100*len(safe)/total:.1f}%)")
    print(f"train {len(train)}  |  val {len(val)}")
    print(f"OWASP 서블릿 포함: 0 (설계상 배제)")
    print(f"저장: {out_path}")
    print(f"검증: {val_path}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=ROOT / "data" / "lora_train_v12_clean.jsonl")
    build(ap.parse_args().out)
