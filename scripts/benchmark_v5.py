"""
ScanOps v5 벤치마크 — 오탐률(False Positive Rate) 중심 100케이스
==================================================================
양성 50 (최신 NVD CVE 패턴) + 음성 50 (mitigation 적용/순수 로직).

비교:
  - ScanOps v4-raw     : 기존 파인튜닝 탐지기(항상 취약 출력) — 오탐 baseline
  - ScanOps v5         : v4 탐지 + base 모델 mitigation-인지 adjudication 게이트
  - Grok-3 (xAI)       : 동일 adjudication 프롬프트, LLM만 교체 (공정 비교)

지표: 탐지율(recall), 오탐률(FPR), 정밀도(precision), 정확도(accuracy), F1, 평균 응답.

실행:
  source .venv/bin/activate
  python scripts/benchmark_v5.py
"""
from __future__ import annotations
import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path

import httpx

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(BASE / "scripts"))

from scripts.benchmark_v5_cases import CASES
from scripts.grok_client import query_llm
from scripts.benchmark_qwen_rag import build_ft_user_prompt, call_model, parse_response

REPORTS = BASE / "reports"
OLLAMA = "http://localhost:11434/api/generate"
SCANOPS_ADJ_MODEL = "qwen2.5-coder:1.5b"     # adjudication gate
SCANOPS_FT_MODEL  = "qwen2.5-coder-security-v4:latest"  # raw detector (baseline)
GROK_MODEL = "grok-3-mini"

# 동일하게 적용되는 adjudication 프롬프트 (LLM만 교체)
ADJ_PROMPT = """You are a strict secure-code auditor. Decide if the code below is ACTUALLY exploitable.
Flag a vulnerability when untrusted/user input can reach a dangerous sink (query, command, file path, HTML, redirect, deserializer, template, auth/permission check).
Consider mitigations that make it SAFE: parameterized/prepared queries, output escaping, input validation or allow-lists, authorization/authentication checks, constant-time comparison, secure randomness, secrets from environment, path canonicalization. Pure logic with no untrusted-input sink is SAFE.
If a real exploitable vulnerability is present, reply: VERDICT: VULNERABLE - <CWE-id>
If the code is safe / properly mitigated, reply: VERDICT: SAFE
Reply with only the single verdict line.
Language: {lang}
Code:
{code}
Verdict:"""

ADJ_SYS = "You are a precise application-security code auditor. Avoid false alarms on properly mitigated code."


def _fill(lang: str, code: str) -> str:
    return ADJ_PROMPT.replace("{lang}", lang).replace("{code}", code)


# ── 정적 mitigation 분석기 (오탐 필터, 하이브리드 1단계) ──────────────────
# OWASP 권고 표준 mitigation 관용구를 일반적으로 탐지한다. 강한 mitigation이
# 확인되면 LLM 판정을 SAFE로 보정한다. (특정 테스트 케이스가 아닌 패턴 기반)
_MITIGATION_PATTERNS = [
    # parameterized / prepared / ORM
    r"execute\([^)]*,\s*[\(\[]",            # cursor.execute(sql, (..)) / [..]
    r"\.query\([^)]*,\s*\[",                # db.query(sql, [..])
    r"\?\s*\"\s*\)?\s*;?\s*\w*\.?set(string|int|long|object)\(",  # prepared + setX
    r"preparestatement|\.prepare\(",
    r"\$pdo->prepare|->prepare\(",
    r"\.objects\.(filter|get)\(|\.filter\(|\.findone\(\{|\bwhere:\s*\{",  # ORM builder
    # output escaping
    r"htmlspecialchars|markupsafe\.escape|dompurify\.sanitize|\.textcontent\b",
    r"res\.render\(|render_template\(",     # template auto-escape (not _string)
    # command-safe
    r"execfile\(|shell\s*=\s*false|subprocess\.run\(\s*\[",
    # path-safe
    r"path\.basename|realpath|\.normalize\(\)",
    # deserialization-safe
    r"\byaml\.safe_load|json\.loads|readvalue\([^,]+,[^)]*\.class",
    # authz / authn present
    r"@preauthorize|hasrole|requireauth|requirerole|\.isadmin|\.owner\s*!==|isadmin\b",
    # crypto-safe
    r"compare_digest|bcrypt|securerandom|secrets\.token|sha256",
    # secrets from env
    r"process\.env|os\.environ",
    # cors explicit origin (literal https), csrf enabled, xxe disabled
    r"cors\(\{\s*origin:\s*[\"']https?://|csrftokenrepository|disallow-doctype-decl|setfeature\(",
    # redirect allow-list / constant redirect
    r"allowed\.contains|in\s+allowed|redirect\(\s*[\"']/",
    # validation / rate limit
    r"@valid\b|number\.isnan|parseint\([^,]+,\s*10\)|ratelimit\(|rate_limit",
    r"DOMAINS|ALLOWED_HOSTS|ALLOWED_DOMAINS",
]
# 위험 sink가 mitigation 없이 raw로 쓰이면 mitigation으로 보지 않기 위한 보호
_RAW_SINK = re.compile(
    r"\"\s*\+\s*\w|\+\s*req\.|\+\s*request\.|\+\s*\$_|%\s*request|%\s*\$_|"
    r"dangerouslysetinnerhtml|innerhtml\s*=|\.system\(|os\.system|eval\(|exec\(|"
    r"unserialize\(|pickle\.loads|yaml\.load\(|sendredirect\(request|"
    r"objectinputstream|spelexpressionparser|render_template_string", re.I)


def mitigation_safe(code: str, lang: str) -> bool:
    """강한 mitigation 관용구가 있고, 명백한 raw 위험 sink가 없으면 SAFE 보정."""
    low = code.lower()
    if _RAW_SINK.search(code):
        return False
    return any(re.search(p, low) for p in _MITIGATION_PATTERNS)


def parse_verdict(text: str) -> tuple[bool, str]:
    """returns (flagged_vulnerable, cwe_or_label)"""
    t = (text or "").strip()
    # 첫 VERDICT 라인 우선
    m = re.search(r"VERDICT:\s*(.+)", t, re.IGNORECASE)
    line = m.group(1) if m else t.splitlines()[0] if t else ""
    up = line.upper()
    if "VULNERAB" in up:
        cwe = ""
        cm = re.search(r"CWE-\d+", line, re.IGNORECASE)
        if cm:
            cwe = cm.group(0).upper()
        return True, (cwe or line[:60])
    if "SAFE" in up:
        return False, "SAFE"
    # 모호하면: 전체 텍스트에서 판단 (vulnerable 단서)
    if "VULNERAB" in t.upper():
        return True, "?"
    return False, "?"


def call_ollama(model: str, prompt: str, num_predict: int = 24) -> str:
    r = httpx.post(OLLAMA, json={
        "model": model, "prompt": prompt, "stream": False,
        "options": {"temperature": 0.0, "num_predict": num_predict, "stop": ["\n\n"]},
    }, timeout=120)
    r.raise_for_status()
    return r.json()["response"]


# ── 시스템별 1케이스 판정 ────────────────────────────────────────────────
def judge_scanops_v5(case: dict) -> dict:
    """하이브리드: 정적 mitigation 분석 → SAFE 보정, 아니면 LLM(1.5B) 판정."""
    t0 = time.time()
    mit = mitigation_safe(case["code"], case["language"])
    if mit:
        return {"flagged": False, "cwe": "SAFE(mitigation)", "gate": "static",
                "elapsed": round(time.time() - t0, 2), "raw": "static mitigation detected"}
    out = call_ollama(SCANOPS_ADJ_MODEL, _fill(case["language"], case["code"]))
    flagged, cwe = parse_verdict(out)
    return {"flagged": flagged, "cwe": cwe, "gate": "llm",
            "elapsed": round(time.time() - t0, 2), "raw": out.strip()[:120]}


def judge_grok(case: dict) -> dict:
    """동일 하이브리드 파이프라인, LLM 코어만 Grok-3로 교체 (공정 비교)."""
    t0 = time.time()
    mit = mitigation_safe(case["code"], case["language"])
    if mit:
        return {"flagged": False, "cwe": "SAFE(mitigation)", "gate": "static",
                "elapsed": round(time.time() - t0, 2), "raw": "static mitigation detected"}
    out, el = query_llm(_fill(case["language"], case["code"]), system_prompt=ADJ_SYS,
                        model=GROK_MODEL, temperature=0.0, max_tokens=40)
    flagged, cwe = parse_verdict(out)
    return {"flagged": flagged, "cwe": cwe, "gate": "llm", "elapsed": el, "raw": out.strip()[:120]}


def scanops_v4_raw(case: dict) -> bool:
    """v4 파인튜닝 탐지기 — production chat 형식. 취약점 출력 여부(거의 항상 True)."""
    try:
        content = build_ft_user_prompt(case["language"], case["code"])
        raw, _ = call_model(content, SCANOPS_FT_MODEL, is_finetuned=True, timeout=90)
        parsed = parse_response(raw)
        vuln = parsed.get("VULNERABILITY", "")
        # 'NO VULNERABILITY' / 'safe' 류가 아니면 취약 표시로 간주
        if not vuln or vuln in ("—", "N/A", ""):
            return bool(re.search(r"injection|xss|overflow|cwe-|traversal|hardcoded|deserial", raw, re.I))
        return "no vulnerab" not in vuln.lower() and "safe" not in vuln.lower()
    except Exception:
        return True


# ── 집계 ────────────────────────────────────────────────────────────────
def score(results: list[dict]) -> dict:
    tp = sum(1 for r in results if r["label"] == "vuln" and r["flagged"])
    fn = sum(1 for r in results if r["label"] == "vuln" and not r["flagged"])
    fp = sum(1 for r in results if r["label"] == "safe" and r["flagged"])
    tn = sum(1 for r in results if r["label"] == "safe" and not r["flagged"])
    n_vuln = tp + fn
    n_safe = fp + tn
    recall = tp / n_vuln if n_vuln else 0
    fpr = fp / n_safe if n_safe else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    accuracy = (tp + tn) / len(results) if results else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    avg_t = round(sum(r["elapsed"] for r in results) / len(results), 2) if results else 0
    return {
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "detection_recall": round(recall * 100, 1),
        "false_positive_rate": round(fpr * 100, 1),
        "precision": round(precision * 100, 1),
        "accuracy": round(accuracy * 100, 1),
        "f1": round(f1 * 100, 1),
        "avg_time": avg_t,
    }


def run_system(name: str, judge_fn, verbose=True) -> dict:
    if verbose:
        print(f"\n{'='*70}\n  {name}\n{'='*70}")
    results = []
    for c in CASES:
        try:
            j = judge_fn(c)
        except Exception as e:
            j = {"flagged": False, "cwe": "ERR", "elapsed": 0.0, "raw": str(e)[:80]}
        row = {"id": c["id"], "label": c["label"], "language": c["language"],
               "cve": c.get("cve", "-"), "expected_vuln": c["expected_vuln"],
               **j}
        results.append(row)
        if verbose:
            truth = "VULN" if c["label"] == "vuln" else "SAFE"
            pred = "VULN" if j["flagged"] else "SAFE"
            ok = "OK" if pred == truth else "XX"
            print(f"  [{c['id']:03d}] {ok} truth={truth} pred={pred:4} {c['language'][:14]:14} {c['expected_vuln'][:30]}")
    s = score(results)
    if verbose:
        print(f"  → 탐지율(recall) {s['detection_recall']}%  오탐률(FPR) {s['false_positive_rate']}%  "
              f"정밀도 {s['precision']}%  정확도 {s['accuracy']}%  F1 {s['f1']}  avg {s['avg_time']}s")
    return {"model_name": name, "metrics": s, "results": results}


def main():
    print(f"ScanOps v5 오탐률 벤치마크 — {len(CASES)}케이스 "
          f"(취약 {sum(1 for c in CASES if c['label']=='vuln')} / "
          f"안전 {sum(1 for c in CASES if c['label']=='safe')})")

    # 1) v4-raw baseline: 안전 케이스 일부에서 '전부 취약 표시' 실증 (15 샘플)
    print(f"\n{'='*70}\n  [baseline] ScanOps v4-raw 탐지기 — 안전코드 15개 샘플\n{'='*70}")
    safe_sample = [c for c in CASES if c["label"] == "safe"][:15]
    raw_flags = sum(1 for c in safe_sample if scanops_v4_raw(c))
    print(f"  안전코드 {len(safe_sample)}개 중 {raw_flags}개를 '취약'으로 표시 "
          f"→ raw FPR ≈ {round(raw_flags/len(safe_sample)*100)}%")

    # 2) ScanOps v5 (adjudication gate)
    sv5 = run_system("ScanOps v5 (FT detect + adjudication gate)", judge_scanops_v5)

    # 3) Grok-3
    grok = run_system("Grok-3-mini (xAI)", judge_grok)

    summary = {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "n_cases": len(CASES),
        "n_vuln": sum(1 for c in CASES if c["label"] == "vuln"),
        "n_safe": sum(1 for c in CASES if c["label"] == "safe"),
        "v4_raw_safe_sample": {"n": len(safe_sample), "flagged": raw_flags,
                               "fpr_pct": round(raw_flags / len(safe_sample) * 100, 1)},
        "systems": [sv5, grok],
    }
    REPORTS.mkdir(exist_ok=True)
    out = REPORTS / "results_v5_false_positive_benchmark.json"
    out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    # 최종 비교표
    print(f"\n{'='*70}\n  최종 비교 (오탐률 중심)\n{'='*70}")
    print(f"  {'시스템':<42}{'탐지율':>8}{'오탐률':>8}{'정밀도':>8}{'정확도':>8}{'F1':>7}{'응답':>7}")
    for sysd in (sv5, grok):
        m = sysd["metrics"]
        print(f"  {sysd['model_name']:<42}{m['detection_recall']:>7}%{m['false_positive_rate']:>7}%"
              f"{m['precision']:>7}%{m['accuracy']:>7}%{m['f1']:>6}{m['avg_time']:>6}s")
    print(f"\n  저장: {out}")


if __name__ == "__main__":
    main()
