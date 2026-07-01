"""
ScanOps V13 학습데이터 빌더 — CVEfixes 대규모 확장 (자체 판별력 강화)
================================================================
V12의 근본 한계는 **학습셋이 264개로 너무 작다**는 것이었다(짧고 명확한 예시뿐).
3B는 "무조건 취약", 7B는 "무조건 안전"으로 무너졌고 둘 다 실제 CVE에서 동전 수준.
V13은 HuggingFace `hitoshura25/cvefixes`(실제 CVE 패치 커밋의 vuln/fixed 코드쌍)에서
**balanced 다언어 3,000~5,000개**를 뽑아 모델 자체 판별력을 끌어올린다.

★누수 차단(가장 중요) — CVE-id 기준 train/test 엄격 분리:
  1. data/cvefixes_benchmark.jsonl 의 141개 CVE-id를 **held-out 으로 예약** → 학습에서 제외.
     (CVE 단위 분리라 같은 CVE의 vuln/fixed 가 train·test 로 새는 것까지 막는다.)
  2. 벤치마크 코드 해시도 직접 제외(belt-and-suspenders).
  3. OWASP 홀드아웃 110케이스 코드 해시 제외(계속 유지).
  4. 코드 해시 dedup — 같은 코드 중복 금지.
  5. train/val 분리도 **CVE-id 단위 disjoint** → val loss 발산을 정직하게 감시.

포맷(메모리 결정 유지):
  - build_ft_user_prompt(language, code) — V12와 동일 user 프롬프트.
  - completion 3줄 대칭: vuln=VULNERABILITY/SEVERITY/CVSS, safe=NONE 3줄.
    각 CVE가 vulnerable_code→vuln, fixed_code→safe 를 내므로 자연히 50/50 균형.

실행:
  python -m ml.build_dataset_v13 --n 4000 --out data/lora_train_v13.jsonl
산출: <out>(train) + <out 옆>_val.jsonl(검증)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.benchmark_qwen_rag import build_ft_user_prompt

SEED = 41
NONE_COMPLETION = "VULNERABILITY: NONE\nSEVERITY: NONE\nCVSS: 0.0"

# 우리 시스템이 다루는 언어 → 표준 라벨 (benchmark 빌더와 동일)
LANG_MAP = {
    "python": "Python", "javascript": "Node.js / Express", "typescript": "TypeScript",
    "java": "Java", "go": "Go", "php": "PHP", "c#": "C#", "csharp": "C#",
    "ruby": "Ruby", "c": "C", "c++": "C++", "cpp": "C++",
}
MIN_LEN, MAX_LEN = 40, 1600   # 너무 짧으면 노이즈, 너무 길면 컨텍스트 초과

# ── 코드 정규화 & 해시 ────────────────────────────────────────────────────────
def _norm(c: str) -> str:
    return re.sub(r"\s+", " ", c or "").strip().lower()

def _h(c: str) -> str:
    return hashlib.sha1(_norm(c).encode()).hexdigest()

# OWASP Benchmark을 zero-shot 평가셋으로 유지하기 위해, 서블릿/벤치마크 흔적이 있는
# 코드는 학습에서 배제한다(v12와 동일 원칙 — "servlet=취약" 단축학습/오염 차단).
_OWASP_MARKERS = ("HttpServletRequest", "HttpServletResponse", "BenchmarkTest",
                  "org.owasp", "owasp.benchmark")

def _is_owasp(code: str) -> bool:
    return any(k in code for k in _OWASP_MARKERS)

# ── severity / CVSS 도출 (3줄 대칭) ───────────────────────────────────────────
def _sev_cvss(cvss3, severity: str) -> tuple[str, str]:
    """cvss3 점수 우선, 없으면 severity 문자열 → (SEVERITY, CVSS) 도출."""
    score = None
    try:
        if cvss3 is not None and str(cvss3).strip() not in ("", "nan", "None"):
            score = float(cvss3)
    except (TypeError, ValueError):
        score = None
    if score is not None:
        if score >= 9.0:   sev = "CRITICAL"
        elif score >= 7.0: sev = "HIGH"
        elif score >= 4.0: sev = "MEDIUM"
        else:              sev = "LOW"
        return sev, f"{score:.1f}"
    sev = (severity or "").strip().upper()
    bucket = {"CRITICAL": "9.5", "HIGH": "8.1", "MEDIUM": "5.5", "LOW": "3.5"}
    if sev not in bucket:
        sev = "HIGH"            # 미상이면 보수적으로 HIGH
    return sev, bucket[sev]

def _vuln_completion(cwe_id: str, cwe_name: str, cvss3, severity: str) -> str:
    name = (cwe_name or "").strip()
    if len(name) > 80:
        name = name[:80].rstrip()
    head = f"{(cwe_id or '').strip()} {name}".strip() or "Security Vulnerability"
    sev, cvss = _sev_cvss(cvss3, severity)
    return f"VULNERABILITY: {head}\nSEVERITY: {sev}\nCVSS: {cvss}"

# ── 제외 해시(누수 차단): 벤치마크 + OWASP 홀드아웃 ───────────────────────────
def _reserved() -> tuple[set[str], set[str]]:
    """반환: (예약 CVE-id 집합, 제외 코드해시 집합)."""
    cve_ids: set[str] = set()
    code_h: set[str] = set()
    # 1·2) CVEfixes 벤치마크 → CVE-id 예약 + 코드해시 제외
    bench = ROOT / "data" / "cvefixes_benchmark.jsonl"
    if bench.exists():
        for line in bench.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            if r.get("cve"):
                cve_ids.add(r["cve"])
            code_h.add(_h(r.get("code", "")))
    # 3) OWASP 홀드아웃 110 코드해시
    try:
        from scripts.owasp_benchmark_cases import build_cases, JAVA_DIR, _extract_code
        for c in build_cases():
            jf = JAVA_DIR / f"{c['id']}.java"
            if jf.exists():
                code_h.add(_h(_extract_code(jf)))
    except Exception as e:  # noqa: BLE001
        print(f"  (OWASP 홀드아웃 해시 스킵: {e})")
    return cve_ids, code_h

# ── 빌드 ──────────────────────────────────────────────────────────────────────
def build(n: int, out: Path, max_scan: int) -> None:
    from datasets import load_dataset

    rng = random.Random(SEED)
    reserved_cves, excluded_h = _reserved()
    print(f"held-out 예약 CVE {len(reserved_cves)}개 · 제외 코드해시 {len(excluded_h)}개")
    print("CVEfixes 스트리밍 로드 중…")
    ds = load_dataset("hitoshura25/cvefixes", split="train", streaming=True)

    seen: set[str] = set()
    # 후보를 (lang, label) 버킷에 모으되, CVE-id 를 함께 들고 다닌다(분리용)
    cand: dict[tuple[str, str], list[dict]] = defaultdict(list)
    scanned = leaked = 0
    for r in ds:
        scanned += 1
        if scanned > max_scan:
            break
        lang = LANG_MAP.get(str(r.get("language", "")).strip().lower())
        if not lang:
            continue
        cve = r.get("cve_id") or ""
        if cve in reserved_cves:          # ★ held-out CVE → 학습 금지
            leaked += 1
            continue
        v = (r.get("vulnerable_code") or "").strip()
        f = (r.get("fixed_code") or "").strip()
        if _norm(v) == _norm(f):
            continue
        vuln_comp = _vuln_completion(
            r.get("cwe_id") or "", r.get("cwe_name") or "",
            r.get("cvss3_base_score"), str(r.get("severity") or ""),
        )
        for code, label, comp in ((v, "vuln", vuln_comp), (f, "safe", NONE_COMPLETION)):
            if not (MIN_LEN <= len(code) <= MAX_LEN):
                continue
            if _is_owasp(code):          # ★ OWASP zero-shot 보존 — 서블릿 흔적 배제
                leaked += 1
                continue
            hh = _h(code)
            if hh in excluded_h or hh in seen:
                continue
            seen.add(hh)
            cand[(lang, label)].append({
                "cve": cve, "lang": lang, "label": label,
                "prompt": build_ft_user_prompt(lang, code), "completion": comp,
            })

    # ── 언어 균등 + vuln/safe 균형 샘플링 ────────────────────────────────────
    langs = sorted({l for (l, _) in cand})
    per = max(2, n // (2 * max(1, len(langs))))
    picked: list[dict] = []
    for lang in langs:
        for label in ("vuln", "safe"):
            items = cand.get((lang, label), [])
            rng.shuffle(items)
            picked.extend(items[:per])
    rng.shuffle(picked)
    picked = picked[:n]

    # ── train/val 분리: CVE-id 단위 disjoint (≈10% CVE를 val로) ──────────────
    cves = sorted({r["cve"] for r in picked if r["cve"]})
    rng.shuffle(cves)
    n_val_cve = max(1, int(len(cves) * 0.10))
    val_cves = set(cves[:n_val_cve])
    train = [r for r in picked if r["cve"] not in val_cves]
    val = [r for r in picked if r["cve"] in val_cves]

    def _strip(r: dict) -> dict:
        return {"prompt": r["prompt"], "completion": r["completion"]}

    rng.shuffle(train); rng.shuffle(val)
    out.write_text("\n".join(json.dumps(_strip(r), ensure_ascii=False) for r in train) + "\n", encoding="utf-8")
    val_path = out.with_name(out.stem + "_val.jsonl")
    val_path.write_text("\n".join(json.dumps(_strip(r), ensure_ascii=False) for r in val) + "\n", encoding="utf-8")

    # ── 리포트 ──────────────────────────────────────────────────────────────
    nv = sum(1 for r in picked if r["label"] == "vuln")
    print("─" * 60)
    print(f"스캔 {scanned}행 · held-out CVE로 거른 행 {leaked}")
    print(f"총 {len(picked)}개  (취약 {nv} / 안전 {len(picked)-nv}, 안전 {100*(len(picked)-nv)/max(1,len(picked)):.1f}%)")
    print("언어:", dict(Counter(r["lang"] for r in picked)))
    print(f"train {len(train)} | val {len(val)}  (CVE disjoint: val CVE {len(val_cves)}개)")
    # 누수 자가검증: train/val 코드해시 교집합은 0 이어야 한다
    th = {_h(json.loads(json.dumps(r))["prompt"]) for r in train}
    vh = {_h(r["prompt"]) for r in val}
    print(f"train∩val prompt 해시 교집합: {len(th & vh)} (0 이어야 정상)")
    print(f"저장: {out}\n검증: {val_path}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=4000, help="목표 학습 샘플 수(3000~5000)")
    ap.add_argument("--out", type=Path, default=ROOT / "data" / "lora_train_v13.jsonl")
    ap.add_argument("--max-scan", type=int, default=80000, help="스트리밍 스캔 행 상한")
    a = ap.parse_args()
    build(a.n, a.out, a.max_scan)
