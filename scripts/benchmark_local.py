"""
로컬 보안 벤치마크 — Grok 없이 완전 무료
세 가지 모드 비교:
  1. gemma:2b (Ollama 베이스라인)
  2. LoRA fine-tuned 모델 (HuggingFace, gemma-2-2b-it 기반)
  3. RAG + gemma:2b (ChromaDB CVE 컨텍스트)

실행:
  python scripts/benchmark_local.py --mode baseline
  python scripts/benchmark_local.py --mode lora
  python scripts/benchmark_local.py --mode rag
  python scripts/benchmark_local.py --mode all
"""

import argparse
import json
import re
import time
import urllib.request
from datetime import datetime
from pathlib import Path

BASE    = Path(__file__).resolve().parent.parent
REPORTS = BASE / "reports"
LORA    = BASE / "models" / "gemma2-security-lora"

OLLAMA_URL = "http://localhost:11434/api/generate"

# ── 테스트 케이스 (20개 공통) ──────────────────────────────────────────────────
CASES = [
    {"id":  1, "language": "React / Next.js",       "expected_vuln": "XSS",
     "code": 'return <div dangerouslySetInnerHTML={{__html: userInput}} />;'},
    {"id":  2, "language": "React / Next.js",       "expected_vuln": "XSS",
     "code": 'return <a href={`javascript:${userAction}`}>Click</a>;'},
    {"id":  3, "language": "React / Next.js",       "expected_vuln": "Code Injection via eval",
     "code": "eval(searchParams.get('callback'));"},
    {"id":  4, "language": "React / Next.js",       "expected_vuln": "XSS via event handler",
     "code": '<img src={user.avatar} onError={user.fallback} />'},
    {"id":  5, "language": "Node.js / Express",     "expected_vuln": "SQL Injection",
     "code": 'db.query("SELECT * FROM users WHERE id=" + req.params.id);'},
    {"id":  6, "language": "Node.js / Express",     "expected_vuln": "Command Injection",
     "code": "exec(req.body.command);"},
    {"id":  7, "language": "Node.js / Express",     "expected_vuln": "Insecure CORS",
     "code": "res.setHeader('Access-Control-Allow-Origin', '*');"},
    {"id":  8, "language": "Node.js / Express",     "expected_vuln": "Hardcoded Secret",
     "code": "jwt.verify(token, 'hardcoded_secret_key');"},
    {"id":  9, "language": "Java Spring Boot",      "expected_vuln": "SQL Injection",
     "code": 'String query = "SELECT * FROM " + tableName;\nstmt.execute(query);'},
    {"id": 10, "language": "Java Spring Boot",      "expected_vuln": "Command Injection",
     "code": "Runtime.getRuntime().exec(userInput);"},
    {"id": 11, "language": "Java Spring Boot",      "expected_vuln": "Overly Permissive Endpoint",
     "code": '@RequestMapping(value="/**")\npublic ResponseEntity<?> handle(HttpServletRequest req) { ... }'},
    {"id": 12, "language": "Java Spring Boot",      "expected_vuln": "Timing Attack",
     "code": "if (password.equals(inputPassword)) { grantAccess(); }"},
    {"id": 13, "language": "Python",                "expected_vuln": "Insecure Deserialization",
     "code": "import pickle\nobj = pickle.loads(user_data)"},
    {"id": 14, "language": "Python",                "expected_vuln": "Command Injection",
     "code": "import subprocess\nsubprocess.call(user_input, shell=True)"},
    {"id": 15, "language": "Python",                "expected_vuln": "Arbitrary Code Execution via YAML",
     "code": "import yaml\ndata = yaml.load(user_input)  # not safe_load"},
    {"id": 16, "language": "Python",                "expected_vuln": "Command Injection",
     "code": 'import os\nos.system(f"ping {host}")'},
    {"id": 17, "language": "C",                     "expected_vuln": "Format String Attack",
     "code": "printf(user_input);  // user-controlled format string"},
    {"id": 18, "language": "C",                     "expected_vuln": "Buffer Overflow",
     "code": "char buf[64];\nstrcpy(buf, argv[1]);  // no bounds check"},
    {"id": 19, "language": "GitHub Actions YAML",   "expected_vuln": "Script Injection via untrusted input",
     "code": "- run: echo ${{ github.event.issue.title }}"},
    {"id": 20, "language": "GitHub Actions YAML",   "expected_vuln": "Supply Chain Attack (unpinned action)",
     "code": "- uses: actions/checkout@main  # unpinned version"},
]

PROMPT_TMPL = """\
You are a security code reviewer.
Analyze this {language} code for security vulnerabilities.

Code:
{code}

Respond in this exact format:
VULNERABILITY: [vulnerability name]
SEVERITY: [CRITICAL/HIGH/MEDIUM/LOW]
ATTACK: [attack scenario in one sentence]
FIX: [fixed code only, no explanation]"""

_CWE_ALIASES = {
    "xss":                  ["cwe-79", "cwe-80", "cross-site"],
    "sql injection":        ["cwe-89", "sql"],
    "command injection":    ["cwe-78", "cwe-77", "command", "injection"],
    "hardcoded secret":     ["cwe-798", "cwe-259", "hard-coded", "hardcoded"],
    "insecure cors":        ["cwe-942", "cwe-346", "cors"],
    "timing attack":        ["cwe-208", "timing"],
    "overly permissive":    ["cwe-284", "permissive", "authorization"],
    "insecure deserialization": ["cwe-502", "deserialization", "deserializ"],
    "arbitrary code execution via yaml": ["cwe-502", "yaml"],
    "supply chain":         ["cwe-829", "unpinned"],
    "buffer overflow":      ["cwe-120", "cwe-121", "overflow"],
    "format string":        ["cwe-134", "format string"],
    "script injection":     ["cwe-78", "injection"],
    "code injection":       ["cwe-94", "cwe-95", "eval"],
}


def _detected(parsed: dict, expected: str) -> bool:
    vuln = parsed.get("VULNERABILITY", "").lower()
    if any(w in vuln for w in expected.lower().split()):
        return True
    for key, aliases in _CWE_ALIASES.items():
        if any(k in expected.lower() for k in key.split()):
            if any(a in vuln for a in aliases):
                return True
    return False


def _parse(text: str) -> dict:
    fields: dict[str, str] = {}
    for key in ("VULNERABILITY", "SEVERITY", "ATTACK", "FIX"):
        m = re.search(
            rf"^\*{{0,2}}{key.lower()}\*{{0,2}}:[ \t]*(.+)",
            text, re.MULTILINE | re.IGNORECASE,
        )
        fields[key] = m.group(1).strip().strip("*").strip() if m else "—"
    m_fix = re.search(r"^\*{0,2}fix\*{0,2}:[ \t]*([\s\S]+)", text, re.MULTILINE | re.IGNORECASE)
    if m_fix:
        raw = m_fix.group(1).strip()
        raw = re.sub(r"^```[^\n]*\n", "", raw).rstrip("`").strip()
        fields["FIX"] = raw
    return fields


# ── Ollama 호출 ────────────────────────────────────────────────────────────────

def _ollama(prompt: str, model: str) -> tuple[str, float]:
    payload = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode()
    req = urllib.request.Request(
        OLLAMA_URL, data=payload,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=120) as resp:
        body = json.loads(resp.read())
    return body["response"], round(time.perf_counter() - t0, 2)


# ── LoRA 추론 ──────────────────────────────────────────────────────────────────

_lora_model     = None
_lora_tokenizer = None


def _load_lora():
    global _lora_model, _lora_tokenizer
    if _lora_model is not None:
        return _lora_model, _lora_tokenizer
    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer

    if not LORA.exists():
        raise FileNotFoundError(
            f"LoRA 어댑터 없음: {LORA}\n"
            "  먼저 실행: python scripts/lora_finetune.py"
        )

    # 저장된 adapter_config.json에서 base model 확인
    cfg_path = LORA / "adapter_config.json"
    base_id  = "google/gemma-2-2b-it"
    if cfg_path.exists():
        with open(cfg_path) as f:
            cfg = json.load(f)
        base_id = cfg.get("base_model_name_or_path", base_id)

    print(f"LoRA 로딩: base={base_id}, adapter={LORA}")
    device = "mps" if torch.backends.mps.is_available() else "cpu"
    dtype  = torch.float16 if device == "mps" else torch.float32

    tokenizer = AutoTokenizer.from_pretrained(LORA)
    base = AutoModelForCausalLM.from_pretrained(base_id, torch_dtype=dtype, low_cpu_mem_usage=True)
    model = PeftModel.from_pretrained(base, str(LORA))
    model = model.to(device)
    model.eval()

    _lora_model, _lora_tokenizer = model, tokenizer
    return model, tokenizer


def _lora_infer(language: str, code: str) -> tuple[str, float]:
    import torch
    model, tokenizer = _load_lora()
    device = next(model.parameters()).device

    prompt = PROMPT_TMPL.format(language=language, code=code)
    # Gemma-2 IT format
    if "gemma" in getattr(tokenizer, "name_or_path", "").lower():
        text = f"<start_of_turn>user\n{prompt}<end_of_turn>\n<start_of_turn>model\n"
    else:
        text = prompt + "\n"

    inputs = tokenizer(text, return_tensors="pt").to(device)
    t0 = time.perf_counter()
    with torch.no_grad():
        out = model.generate(
            **inputs,
            max_new_tokens=256,
            do_sample=False,
            temperature=1.0,
            pad_token_id=tokenizer.eos_token_id,
        )
    elapsed = round(time.perf_counter() - t0, 2)
    new_tokens = out[0][inputs["input_ids"].shape[1]:]
    response   = tokenizer.decode(new_tokens, skip_special_tokens=True)
    return response, elapsed


# ── 모드별 실행 ───────────────────────────────────────────────────────────────

def run_baseline(ollama_model: str = "gemma:2b") -> list[dict]:
    print(f"\n[BASELINE] Ollama {ollama_model}")
    print("─" * 55)
    results = []
    for c in CASES:
        prompt = PROMPT_TMPL.format(language=c["language"], code=c["code"])
        try:
            raw, elapsed = _ollama(prompt, ollama_model)
        except Exception as e:
            print(f"  [{c['id']:02d}] 오류: {e}")
            results.append({**c, "response": "", "parsed": {}, "elapsed": 0.0, "detected": False})
            continue
        parsed = _parse(raw)
        ok     = _detected(parsed, c["expected_vuln"])
        results.append({**c, "response": raw, "parsed": parsed, "elapsed": elapsed, "detected": ok})
        print(f"  [{c['id']:02d}] {'✓' if ok else '✗'} {parsed.get('VULNERABILITY','?')[:50]}  {elapsed}s")
    return results


def run_lora() -> list[dict]:
    print("\n[LoRA] gemma-2-2b-it + 보안 파인튜닝")
    print("─" * 55)
    results = []
    for c in CASES:
        try:
            raw, elapsed = _lora_infer(c["language"], c["code"])
        except Exception as e:
            print(f"  [{c['id']:02d}] 오류: {e}")
            results.append({**c, "response": "", "parsed": {}, "elapsed": 0.0, "detected": False})
            continue
        parsed = _parse(raw)
        ok     = _detected(parsed, c["expected_vuln"])
        results.append({**c, "response": raw, "parsed": parsed, "elapsed": elapsed, "detected": ok})
        print(f"  [{c['id']:02d}] {'✓' if ok else '✗'} {parsed.get('VULNERABILITY','?')[:50]}  {elapsed}s")
    return results


def run_rag(ollama_model: str = "gemma:2b") -> list[dict]:
    print(f"\n[RAG] Ollama {ollama_model} + ChromaDB CVE")
    print("─" * 55)
    try:
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from rag_local import analyze_with_context
    except ImportError as e:
        print(f"RAG 로드 실패: {e}")
        return []

    results = []
    for c in CASES:
        try:
            res = analyze_with_context(
                language=c["language"], code=c["code"], model=ollama_model
            )
        except Exception as e:
            print(f"  [{c['id']:02d}] 오류: {e}")
            results.append({**c, "parsed": {}, "elapsed": 0.0, "detected": False, "cve_references": []})
            continue
        parsed = {
            "VULNERABILITY": res["vulnerability"],
            "SEVERITY":      res["severity"],
            "ATTACK":        res["attack"],
            "FIX":           res["fix"],
        }
        ok = _detected(parsed, c["expected_vuln"])
        results.append({
            **c,
            "parsed": parsed,
            "elapsed": res["elapsed"],
            "detected": ok,
            "cve_references": res.get("cve_references", []),
        })
        n_cve = len(res.get("cve_references", []))
        print(f"  [{c['id']:02d}] {'✓' if ok else '✗'} {res['vulnerability'][:50]}  {res['elapsed']}s  CVE:{n_cve}")
    return results


# ── HTML 보고서 ───────────────────────────────────────────────────────────────

SEVERITY_COLOR = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#16a34a"}
LANG_COLOR = {
    "React / Next.js":     "#06b6d4",
    "Node.js / Express":   "#22c55e",
    "Java Spring Boot":    "#f97316",
    "Python":              "#a855f7",
    "C":                   "#64748b",
    "GitHub Actions YAML": "#ec4899",
}

BASELINE_35 = {"model": "Gemma 2B (기존)", "detect_pct": 35.0, "avg_time": 4.27}


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_report(all_runs: dict[str, list[dict]]) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    def summary(results: list[dict]) -> tuple[int, int, float]:
        n  = len(results)
        ok = sum(1 for r in results if r.get("detected"))
        t  = [r["elapsed"] for r in results if r.get("elapsed", 0) > 0]
        return n, ok, round(sum(t) / len(t), 2) if t else 0.0

    cards = ""
    for label, results in all_runs.items():
        n, ok, avg = summary(results)
        pct  = round(ok / n * 100, 1) if n else 0
        delta = pct - BASELINE_35["detect_pct"]
        ds   = "+" if delta >= 0 else ""
        dc   = "#22c55e" if delta >= 0 else "#ef4444"
        cards += f"""
        <div class="run-card">
          <div class="run-label">{_esc(label)}</div>
          <div class="run-pct" style="color:{dc};">{pct}%</div>
          <div class="run-sub">{ok}/{n} 탐지 · 평균 {avg}s</div>
          <div class="run-delta" style="color:{dc};">{ds}{delta:.1f}%p vs 기존</div>
        </div>"""

    detail_sections = ""
    for label, results in all_runs.items():
        rows = ""
        for r in results:
            ok  = r.get("detected", False)
            sev = r.get("parsed", {}).get("SEVERITY", "").upper()
            sc  = SEVERITY_COLOR.get(sev, "#94a3b8")
            tc  = "#22c55e" if ok else "#ef4444"
            ec  = "#22c55e" if r.get("elapsed", 0) < 3 else ("#eab308" if r.get("elapsed", 0) < 8 else "#ef4444")
            vuln = _esc(r.get("parsed", {}).get("VULNERABILITY", "—"))
            rows += f"""
            <tr>
              <td>#{r['id']}</td>
              <td>{_esc(r['language'])}</td>
              <td>{_esc(r['expected_vuln'])}</td>
              <td>{vuln}</td>
              <td><span class="sev" style="background:{sc};">{sev or '—'}</span></td>
              <td style="color:{tc};font-weight:700;">{'✓' if ok else '✗'}</td>
              <td style="color:{ec};">{r.get('elapsed',0)}s</td>
            </tr>"""
        detail_sections += f"""
        <h2 style="margin:24px 0 8px;font-size:1rem;color:#334155;">{_esc(label)}</h2>
        <table><thead><tr>
          <th>#</th><th>언어</th><th>예상 취약점</th><th>탐지 결과</th>
          <th>심각도</th><th>탐지</th><th>시간</th>
        </tr></thead><tbody>{rows}</tbody></table>"""

    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>ScanOps Local Benchmark</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#f0f4f8;color:#1e293b;padding:24px}}
h1{{font-size:1.5rem;font-weight:700;margin-bottom:4px}}
.sub{{color:#64748b;font-size:.85rem;margin-bottom:20px}}
.runs{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}}
.run-card{{background:#fff;border-radius:12px;padding:18px 22px;flex:1;min-width:160px;
           box-shadow:0 1px 4px rgba(0,0,0,.08);text-align:center}}
.run-label{{font-size:.72rem;font-weight:600;color:#64748b;text-transform:uppercase;margin-bottom:6px}}
.run-pct{{font-size:2rem;font-weight:800}}
.run-sub{{font-size:.75rem;color:#94a3b8;margin-top:3px}}
.run-delta{{font-size:.82rem;font-weight:700;margin-top:4px}}
.baseline-note{{background:#fff;border-radius:10px;padding:12px 18px;margin-bottom:20px;
                box-shadow:0 1px 4px rgba(0,0,0,.08);font-size:.85rem;color:#475569}}
table{{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;
       overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.08);font-size:.82rem}}
th{{background:#f1f5f9;padding:10px 12px;text-align:left;font-weight:600;color:#475569;font-size:.75rem}}
td{{padding:9px 12px;border-bottom:1px solid #f1f5f9;vertical-align:top}}
.sev{{display:inline-block;color:#fff;font-size:.72rem;font-weight:700;
      padding:2px 8px;border-radius:999px}}
</style>
</head>
<body>
<h1>ScanOps — Local Benchmark (Grok-free)</h1>
<p class="sub">생성일: {now} · 완전 로컬 실행 · Gemma-2 LoRA + ChromaDB RAG</p>
<div class="baseline-note">베이스라인: {BASELINE_35['model']} {BASELINE_35['detect_pct']}% / {BASELINE_35['avg_time']}s</div>
<div class="runs">{cards}</div>
{detail_sections}
</body>
</html>"""


# ── 메인 ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="로컬 보안 벤치마크 (Grok 없이)")
    parser.add_argument("--mode",  default="baseline",
                        choices=["baseline", "lora", "rag", "all"],
                        help="실행 모드")
    parser.add_argument("--model", default="gemma:2b",
                        help="Ollama 모델명 (baseline/rag 모드)")
    args = parser.parse_args()

    REPORTS.mkdir(exist_ok=True)
    all_runs: dict[str, list[dict]] = {}

    if args.mode in ("baseline", "all"):
        all_runs[f"Gemma:2b Ollama (베이스라인)"] = run_baseline(args.model)

    if args.mode in ("rag", "all"):
        all_runs[f"RAG + {args.model}"] = run_rag(args.model)

    if args.mode in ("lora", "all"):
        all_runs["Gemma-2 2B LoRA (파인튜닝)"] = run_lora()

    # 결과 요약
    print("\n" + "═" * 55)
    print("최종 결과")
    print("═" * 55)
    for label, results in all_runs.items():
        n  = len(results)
        ok = sum(1 for r in results if r.get("detected"))
        t  = [r["elapsed"] for r in results if r.get("elapsed", 0) > 0]
        avg = round(sum(t) / len(t), 2) if t else 0
        pct = round(ok / n * 100, 1) if n else 0
        print(f"  {label:35s} {ok}/{n} = {pct}%  avg {avg}s")
    print(f"  {'베이스라인 (기존 gemma:2b)':35s} 7/20 = 35.0%  avg 4.27s")

    # HTML 저장
    if all_runs:
        html  = build_report(all_runs)
        stamp = datetime.now().strftime("%Y%m%d_%H%M")
        out   = REPORTS / f"benchmark_local_{stamp}.html"
        out.write_text(html, encoding="utf-8")
        print(f"\nHTML 저장: {out}")

        # JSON도 저장 (분석용)
        json_out = REPORTS / f"benchmark_local_{stamp}.json"
        with open(json_out, "w", encoding="utf-8") as f:
            # parsed dict의 non-serializable 필드 제거
            clean = {
                k: [{kk: vv for kk, vv in r.items() if kk != "response"} for r in v]
                for k, v in all_runs.items()
            }
            json.dump(clean, f, ensure_ascii=False, indent=2)
        print(f"JSON 저장: {json_out}")


if __name__ == "__main__":
    main()
