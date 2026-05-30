"""
ScanOps CLI — 터미널에서 코드 취약점 분석

사용법:
  # 코드 직접 입력
  python scripts/analyze.py --lang react --code 'return <div dangerouslySetInnerHTML={{__html: userInput}} />;'

  # 파일 분석
  python scripts/analyze.py --file src/components/UserProfile.jsx

  # stdin 파이프
  cat MyController.java | python scripts/analyze.py --lang java

  # 디렉토리 전체 스캔 (취약 파일만 출력)
  python scripts/analyze.py --dir ./src --lang react --only-vuln
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "scripts"))

from scripts.benchmark_qwen_rag import (
    build_ft_user_prompt,
    build_base_rag_prompt,
    call_model,
    search_cves,
    parse_response,
    detected as _detected,
)
from scripts.benchmark_core import CASES  # accepted 키워드 참고용

MODEL_FT   = "qwen2.5-coder-security-v2:latest"
MODEL_BASE = "qwen2.5-coder:1.5b"

# 언어별 확장자 매핑
EXT_TO_LANG = {
    ".jsx": "React / Next.js", ".tsx": "React / Next.js",
    ".js":  "Node.js / Express", ".ts": "Node.js / Express",
    ".java": "Java Spring Boot",
    ".py":  "Python",
    ".c":   "C", ".h": "C", ".cpp": "C++",
    ".yml": "GitHub Actions YAML", ".yaml": "GitHub Actions YAML",
    ".go":  "Go", ".rs": "Rust", ".rb": "Ruby", ".php": "PHP",
}

LANG_ALIASES = {
    "react": "React / Next.js", "nextjs": "React / Next.js", "tsx": "React / Next.js",
    "node": "Node.js / Express", "express": "Node.js / Express", "js": "Node.js / Express",
    "javascript": "Node.js / Express",
    "java": "Java Spring Boot", "spring": "Java Spring Boot",
    "python": "Python", "py": "Python",
    "c": "C", "cpp": "C++",
    "yaml": "GitHub Actions YAML", "yml": "GitHub Actions YAML",
    "go": "Go", "rust": "Rust", "ruby": "Ruby", "php": "PHP",
}

# 분석 대상 확장자 (디렉토리 스캔 시)
SCAN_EXTENSIONS = set(EXT_TO_LANG.keys())

SEVERITY_COLOR = {
    "CRITICAL": "\033[91m", "HIGH": "\033[93m",
    "MEDIUM":   "\033[94m", "LOW":  "\033[92m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"
GREEN = "\033[92m"
RED   = "\033[91m"
CYAN  = "\033[96m"
GRAY  = "\033[90m"


def resolve_language(lang_hint: str | None, file_path: Path | None) -> str:
    if lang_hint:
        return LANG_ALIASES.get(lang_hint.lower(), lang_hint)
    if file_path:
        return EXT_TO_LANG.get(file_path.suffix.lower(), "Unknown")
    return "Unknown"


def analyze_code(language: str, code: str, use_rag: bool = True, verbose: bool = True) -> dict:
    """어댑티브 2단계 분석: QLoRA → base+RAG 폴백."""
    t0 = time.time()

    # ── Stage 1: QLoRA 파인튜닝 모델 ─────────────────────────────────────────
    content_ft = build_ft_user_prompt(language, code)
    try:
        resp_ft, t_ft = call_model(content_ft, MODEL_FT, is_finetuned=True, timeout=60)
    except Exception as e:
        resp_ft, t_ft = "", 0.0
        if verbose:
            print(f"  {GRAY}[Stage 1 오류: {e}]{RESET}")

    parsed_ft = parse_response(resp_ft)
    vuln_ft   = parsed_ft.get("VULNERABILITY", "")
    ok_ft     = bool(vuln_ft and vuln_ft not in ("—", "N/A", ""))
    # raw fallback
    if not ok_ft and resp_ft:
        raw_l = resp_ft.lower()
        for kw in ["vulnerability", "cwe-", "injection", "overflow", "xss", "sql",
                   "command", "deserialization", "cors", "hardcoded", "timing", "supply chain"]:
            if kw in raw_l:
                ok_ft = True
                if not vuln_ft or vuln_ft in ("—",):
                    parsed_ft["VULNERABILITY"] = resp_ft[:120].split("\n")[0].strip()
                break

    stage = 1
    final_parsed = parsed_ft
    cves: list[dict] = []

    if ok_ft:
        if use_rag:
            cve_q = f"{language} {vuln_ft} {code[:120]}"
            cves  = search_cves(cve_q)
    else:
        # ── Stage 2: base + RAG 폴백 ─────────────────────────────────────────
        stage = 2
        cve_q = f"{language} security vulnerability {code[:120]}"
        cves  = search_cves(cve_q) if use_rag else []
        content_b = build_base_rag_prompt(language, code, cves)
        try:
            resp_b, _ = call_model(content_b, MODEL_BASE, is_finetuned=False, timeout=60)
            final_parsed = parse_response(resp_b)
        except Exception as e:
            if verbose:
                print(f"  {GRAY}[Stage 2 오류: {e}]{RESET}")

    elapsed = round(time.time() - t0, 2)
    vuln   = final_parsed.get("VULNERABILITY", "—")
    sev    = final_parsed.get("SEVERITY",      "—")
    attack = final_parsed.get("ATTACK",        "—")
    fix    = final_parsed.get("FIX",           "—")

    return {
        "language": language,
        "stage":    stage,
        "elapsed":  elapsed,
        "detected": vuln not in ("—", "N/A", "", None),
        "vulnerability": vuln,
        "severity":  sev,
        "attack":    attack,
        "fix":       fix,
        "cve_references": cves,
    }


def print_result(result: dict, file_path: Path | None = None) -> None:
    vuln  = result["vulnerability"]
    sev   = result["severity"]
    ok    = result["detected"]
    stage = result["stage"]
    cves  = result["cve_references"]

    sep = "─" * 60

    if file_path:
        print(f"\n{BOLD}📄 {file_path}{RESET}")
    print(sep)

    if ok:
        sev_col = SEVERITY_COLOR.get(sev.upper(), "")
        print(f"  {RED}⚠  취약점 탐지됨{RESET}  {GRAY}[Stage {stage} | {result['elapsed']}s]{RESET}")
        print(f"  {BOLD}취약점: {sev_col}{vuln}{RESET}")
        print(f"  심각도: {sev_col}{sev}{RESET}")
        print(f"  공격: {result['attack']}")
        if result["fix"] and result["fix"] != "—":
            print(f"\n  {GREEN}수정 코드:{RESET}")
            for line in result["fix"].split("\n")[:15]:
                print(f"    {GRAY}{line}{RESET}")
        if cves:
            print(f"\n  {CYAN}관련 CVE ({len(cves)}건):{RESET}")
            for c in cves[:3]:
                print(f"    - {c['cve_id']} ({c['severity']}, CVSS {c['base_score']}, {c['cwe_id']})")
                if c.get("description"):
                    print(f"      {GRAY}{c['description'][:100]}...{RESET}")
    else:
        print(f"  {GREEN}✓ 취약점 미탐지  {GRAY}[{result['elapsed']}s]{RESET}")

    print(sep)


def scan_file(path: Path, lang_hint: str | None, use_rag: bool) -> dict | None:
    language = resolve_language(lang_hint, path)
    if language == "Unknown":
        return None
    code = path.read_text(encoding="utf-8", errors="ignore")
    if not code.strip():
        return None
    # 파일이 너무 크면 분할 분석 (2000자씩)
    chunks = [code[i:i+2000] for i in range(0, min(len(code), 6000), 2000)]
    all_results = []
    for chunk in chunks:
        r = analyze_code(language, chunk, use_rag=use_rag, verbose=False)
        r["file"] = str(path)
        all_results.append(r)
        if r["detected"]:
            break  # 취약점 발견 시 추가 청크 스킵
    return all_results[0] if all_results else None


def cmd_analyze(args) -> None:
    # 코드 소스 결정
    if args.code:
        code = args.code
        file_path = None
    elif args.file:
        file_path = Path(args.file)
        code = file_path.read_text(encoding="utf-8", errors="ignore")
    elif not sys.stdin.isatty():
        code = sys.stdin.read()
        file_path = None
    else:
        print("코드를 --code, --file, 또는 stdin으로 입력하세요.")
        sys.exit(1)

    language = resolve_language(args.lang, file_path)
    if language == "Unknown" and not args.lang:
        language = "Python"  # 기본값

    print(f"\n{BOLD}ScanOps 취약점 분석{RESET}  언어: {CYAN}{language}{RESET}")
    print(f"{GRAY}모델: {MODEL_FT} (어댑티브 2단계){RESET}\n")

    result = analyze_code(language, code, use_rag=not args.no_rag)
    print_result(result, file_path)

    if args.json:
        out = args.json if args.json != True else "result.json"
        Path(out).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\nJSON 저장: {out}")


def cmd_dir(args) -> None:
    src = Path(args.dir)
    if not src.exists():
        print(f"디렉토리 없음: {src}")
        sys.exit(1)

    files = [f for f in src.rglob("*") if f.suffix.lower() in SCAN_EXTENSIONS
             and "node_modules" not in f.parts
             and ".git" not in f.parts
             and "dist" not in f.parts
             and "build" not in f.parts]

    print(f"\n{BOLD}ScanOps 디렉토리 스캔{RESET}  {CYAN}{src}{RESET}")
    print(f"대상 파일 {len(files)}개 분석 중...\n")

    found_vulns = []
    for i, fp in enumerate(files, 1):
        lang_hint = args.lang if args.lang else None
        print(f"  [{i:03d}/{len(files):03d}] {fp.relative_to(src)}", end=" ", flush=True)
        r = scan_file(fp, lang_hint, use_rag=not args.no_rag)
        if r is None:
            print(f"{GRAY}스킵{RESET}")
            continue
        if r["detected"]:
            sev_col = SEVERITY_COLOR.get(r["severity"].upper(), "")
            print(f"{RED}⚠ {sev_col}{r['severity']}{RESET} — {r['vulnerability'][:50]}")
            found_vulns.append(r)
        else:
            print(f"{GREEN}✓ 안전{RESET}")

    print(f"\n{'─'*60}")
    print(f"결과: {len(files)}개 파일 중 {RED}{len(found_vulns)}개 취약점 발견{RESET}")

    if found_vulns and not args.only_summary:
        print(f"\n{BOLD}취약점 상세:{RESET}")
        for r in found_vulns:
            sev_col = SEVERITY_COLOR.get(r["severity"].upper(), "")
            print(f"  {RED}⚠{RESET}  {r['file']}")
            print(f"     {sev_col}{r['severity']}{RESET}  {r['vulnerability']}")

    if args.json:
        out = args.json if isinstance(args.json, str) else "scan_results.json"
        Path(out).write_text(json.dumps(found_vulns, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\nJSON 저장: {out}")


def main():
    parser = argparse.ArgumentParser(
        prog="scanops",
        description="ScanOps 취약점 분석 CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  # React 코드 직접 분석
  python scripts/analyze.py --lang react --code 'return <div dangerouslySetInnerHTML={{__html: x}} />;'

  # Java 파일 분석
  python scripts/analyze.py --file UserController.java

  # stdin 파이프
  cat MyComponent.tsx | python scripts/analyze.py --lang react

  # 디렉토리 전체 스캔
  python scripts/analyze.py --dir ./src

  # JSON 결과 저장
  python scripts/analyze.py --file app.py --json result.json
        """,
    )
    sub = parser.add_subparsers(dest="cmd")

    # 기본: 단일 코드 분석
    parser.add_argument("--code",   help="분석할 코드 (직접 입력)")
    parser.add_argument("--file",   help="분석할 파일 경로")
    parser.add_argument("--lang",   help="언어 (react, java, python, node, c, yaml 등)")
    parser.add_argument("--no-rag", action="store_true", help="RAG CVE 검색 비활성화")
    parser.add_argument("--json",   nargs="?", const="result.json", help="결과를 JSON으로 저장")

    # 서브커맨드: 디렉토리 스캔
    p_dir = sub.add_parser("dir", help="디렉토리 전체 스캔")
    p_dir.add_argument("dir",         help="스캔할 디렉토리")
    p_dir.add_argument("--lang",      help="언어 강제 지정 (생략 시 확장자 자동 감지)")
    p_dir.add_argument("--no-rag",    action="store_true")
    p_dir.add_argument("--only-vuln", action="store_true", help="취약 파일만 출력")
    p_dir.add_argument("--only-summary", action="store_true", help="요약만 출력")
    p_dir.add_argument("--json",      nargs="?", const="scan_results.json")

    args = parser.parse_args()

    if args.cmd == "dir":
        cmd_dir(args)
    else:
        cmd_analyze(args)


if __name__ == "__main__":
    main()
