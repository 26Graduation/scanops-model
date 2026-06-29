"""
ScanOps Model API Server (FastAPI)
백엔드(Spring Boot)에서 HTTP로 호출할 수 있는 분석 엔드포인트

실행:
  cd /Users/kimsehan/Desktop/scanops/scanops-model
  source .venv/bin/activate
  uvicorn scripts.api_server:app --host 0.0.0.0 --port 8100 --reload

엔드포인트:
  POST /analyze        — 코드 단건 분석
  POST /analyze/batch  — 파일 목록 일괄 분석 (GitHub repo용)
  POST /analyze/pr     — PR diff 보안 스캔 (GitHub Action용)
  GET  /health         — 서버 상태 확인
"""

from __future__ import annotations

import os
import re
import sys
import time
from pathlib import Path
from typing import Optional

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "scripts"))

from fastapi import FastAPI, HTTPException, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, Field

from scripts.benchmark_qwen_rag import (
    build_ft_user_prompt,
    build_base_rag_prompt,
    call_model,
    search_cves,
    parse_response,
)
from scripts.grok_client import query_llm as grok_query
from scanops.core.code_graph import (
    CodeFile,
    build_code_graph,
    evidence_from_neo4j,
    evidence_for_finding,
    kg_risk_score,
    should_suppress_finding,
    sync_to_neo4j,
)

app = FastAPI(
    title="ScanOps Model API",
    description="QLoRA v2 + Qdrant RAG 어댑티브 취약점 분석 API",
    version="4.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── API Key 인증 ───────────────────────────────────────────────────────────────

_API_KEY_HEADER = APIKeyHeader(name="X-Scanops-Key", auto_error=False)
_CONFIGURED_KEY = os.environ.get("SCANOPS_API_KEY", "")


def _require_api_key(key: Optional[str] = Security(_API_KEY_HEADER)) -> None:
    if _CONFIGURED_KEY and key != _CONFIGURED_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing X-Scanops-Key")


# ── 파일 확장자 → 언어 매핑 ───────────────────────────────────────────────────

_EXT_LANG: dict[str, str] = {
    ".java": "Java Spring Boot",
    ".kt": "Kotlin",
    ".jsx": "React / Next.js",
    ".tsx": "React / Next.js",
    ".js": "Node.js / Express",
    ".ts": "Node.js / Express",
    ".py": "Python",
    ".go": "Go",
    ".rs": "Rust",
    ".c": "C",
    ".cpp": "C++",
    ".h": "C",
    ".php": "PHP",
    ".rb": "Ruby",
    ".yml": "GitHub Actions YAML",
    ".yaml": "GitHub Actions YAML",
}


def _detect_language(filename: str) -> Optional[str]:
    ext = Path(filename).suffix.lower()
    return _EXT_LANG.get(ext)

MODEL_FT   = os.getenv("OLLAMA_MODEL", "qwen2.5-coder-security-v11:latest")
MODEL_BASE = os.getenv("OLLAMA_BASE_MODEL", "qwen2.5-coder:3b")


# ── 요청/응답 모델 ─────────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    language: str
    code: str
    file_path: Optional[str] = None
    use_rag: bool = True


class CveReference(BaseModel):
    cve_id: str
    severity: str
    base_score: float
    cwe_id: str
    description: str


class GraphEvidence(BaseModel):
    category: str
    verdict: str
    filename: str
    variable: str
    sink: str
    source: str
    path: list[str]
    summary: str
    confidence: float


class AnalyzeResponse(BaseModel):
    language: str
    file_path: Optional[str]
    detected: bool
    stage: int                  # 1=QLoRA, 2=base+RAG fallback
    vulnerability: str
    severity: str
    cvss_score: Optional[float] = None   # CVSS base score (v4 모델부터 지원)
    attack: str
    fix: str
    cve_references: list[CveReference]
    kg_risk_score: Optional[float] = None
    graph_evidence: list[GraphEvidence] = Field(default_factory=list)
    suppressed_by_graph: bool = False
    elapsed: float


class BatchRequest(BaseModel):
    files: list[AnalyzeRequest]
    stop_on_first: bool = False  # 첫 취약점 발견 시 중단


class BatchResponse(BaseModel):
    total: int
    detected_count: int
    results: list[AnalyzeResponse]
    elapsed: float


# PR diff 스캔용 모델
class PrFile(BaseModel):
    filename: str
    content: str       # 파일 전체 내용
    patch: Optional[str] = None   # git diff patch (라인 번호 매핑용)


class PrScanRequest(BaseModel):
    repo: str          # "owner/repo"
    pr_number: int
    files: list[PrFile]


class PrFinding(BaseModel):
    filename: str
    detected: bool
    vulnerability: str
    severity: str
    cvss_score: Optional[float]
    attack: str
    fix: str
    cve_references: list[CveReference]
    kg_risk_score: Optional[float] = None
    graph_evidence: list[GraphEvidence] = Field(default_factory=list)
    suppressed_by_graph: bool = False
    diff_line: Optional[int] = None   # patch 첫 번째 추가 라인 번호


class PrScanResponse(BaseModel):
    repo: str
    pr_number: int
    total_files: int
    vulnerable_count: int
    findings: list[PrFinding]
    elapsed: float


# ── 한국어 번역 ────────────────────────────────────────────────────────────────

def _is_korean(text: str) -> bool:
    """한글 자모 포함 여부로 한국어 판별"""
    return any('가' <= ch <= '힣' or 'ᄀ' <= ch <= 'ᇿ' for ch in text)


def _translate_ko(text: str) -> str:
    """영어 텍스트를 Grok API로 한국어 번역. 실패 시 원문 반환.

    마크다운 코드 블록(```...```)은 번역하지 않고 그대로 유지.
    설명 텍스트 부분만 번역 후 재조합.
    """
    if not text or text in ("—", "N/A") or _is_korean(text):
        return text

    import re as _re

    # 코드 블록 분리: [설명, 코드블록, 설명, ...] 순서로 분할
    parts = _re.split(r"(```[\s\S]*?```)", text)

    translated_parts = []
    for part in parts:
        if part.startswith("```"):
            # 코드 블록은 번역 없이 유지
            translated_parts.append(part)
            continue

        if not part.strip() or _is_korean(part):
            translated_parts.append(part)
            continue

        # 코드 블록 없는 순수 텍스트: 인라인 코드 시그널 체크
        code_signals = sum(1 for ch in part if ch in "{}();=")
        if code_signals >= 6:
            # 인라인 코드가 많은 경우 번역 생략
            translated_parts.append(part)
            continue

        try:
            translated, _ = grok_query(
                prompt=(
                    "다음 보안 취약점 설명을 자연스러운 한국어로 번역하세요. "
                    "번역문만 출력하고 다른 설명은 쓰지 마세요.\n\n" + part
                ),
                system_prompt="You are a Korean security translator. Output only the Korean translation.",
                model="grok-3-mini",
                temperature=0.0,
                max_tokens=300,
            )
            translated_parts.append(translated.strip() if translated.strip() else part)
        except Exception:
            translated_parts.append(part)  # API 실패 시 원문 유지

    return "".join(translated_parts)


# ── 핵심 분석 로직 ─────────────────────────────────────────────────────────────

def _raw_ok(response: str) -> bool:
    if not response:
        return False
    keywords = [
        "injection", "overflow", "xss", "cross-site", "sql",
        "command", "deserialization", "cors", "hardcoded", "timing",
        "supply chain", "unpinned", "format string", "cwe-",
        "vulnerability", "attack", "severity",
        # 한국어 응답 키워드
        "취약점", "인젝션", "공격", "위험", "보안",
    ]
    r = response.lower()
    return any(k in r for k in keywords)


_VULN_GARBAGE = (
    "vulnerability:",    # 값 안에 키가 재등장 → 메타텍스트 포착
    "last line",         # "on the second last line"
    "at end of",         # "at end of block"
    "at the end",
    "on line ",
    "in the code",
    "in the function",
    "the vulnerability is",
    "this vulnerability",
)

def _is_valid_vuln(text: str) -> bool:
    """파싱된 VULNERABILITY 값이 실제 취약점 이름인지 검증."""
    if not text or text in ("—", "N/A", ""):
        return False
    t = text.lower()
    if any(p in t for p in _VULN_GARBAGE):
        return False
    # 문장이 3개 이상이면 설명 텍스트 → 거부
    if text.count(". ") >= 2:
        return False
    return True


def _no_vuln(text: Optional[str]) -> bool:
    """VULNERABILITY 값이 '취약점 없음(NONE)'을 의미하는지 판정.
    QLoRA v5부터는 안전한 코드에 대해 모델이 'VULNERABILITY: NONE'을
    출력하도록 학습됐으므로, 이를 명시적으로 미탐지로 처리해야 한다."""
    if text in ("—", "N/A", "", None):
        return True
    return isinstance(text, str) and text.strip().upper() == "NONE"


def _graph_files_from_requests(files: list[AnalyzeRequest | PrFile]) -> list[CodeFile]:
    rows = []
    for file in files:
        filename = getattr(file, "file_path", None) or getattr(file, "filename", None) or "<stdin>"
        language = getattr(file, "language", None) or _detect_language(filename) or "Unknown"
        content = getattr(file, "code", None) or getattr(file, "content", "")
        rows.append(CodeFile(filename=filename, language=language, content=content))
    return rows


def _enrich_with_graph(
    response: AnalyzeResponse,
    graph,
    vulnerability: str,
    filename: Optional[str],
    analysis_id: str,
) -> AnalyzeResponse:
    evidence = evidence_from_neo4j(analysis_id, filename, vulnerability)
    if not evidence:
        evidence = evidence_for_finding(graph, filename, vulnerability)
    response.graph_evidence = [GraphEvidence(**e.to_dict()) for e in evidence]
    response.kg_risk_score = kg_risk_score(response.cvss_score, evidence)
    response.suppressed_by_graph = should_suppress_finding(vulnerability, evidence)
    if response.suppressed_by_graph:
        response.detected = False
        response.severity = "INFO"
        response.kg_risk_score = 0.0
        response.attack = "지식 그래프 분석 결과 사용자 입력 흐름이 아닌 정적 import로 확인되어 오탐으로 판단했습니다."
        response.fix = "수정 불필요: 해당 값은 코드베이스 내 정적 asset import에서 유래합니다."
    return response


def _enrich_pr_finding_with_graph(finding: PrFinding, graph, analysis_id: str) -> PrFinding:
    evidence = evidence_from_neo4j(analysis_id, finding.filename, finding.vulnerability)
    if not evidence:
        evidence = evidence_for_finding(graph, finding.filename, finding.vulnerability)
    finding.graph_evidence = [GraphEvidence(**e.to_dict()) for e in evidence]
    finding.kg_risk_score = kg_risk_score(finding.cvss_score, evidence)
    finding.suppressed_by_graph = should_suppress_finding(finding.vulnerability, evidence)
    if finding.suppressed_by_graph:
        finding.detected = False
        finding.severity = "INFO"
        finding.kg_risk_score = 0.0
        finding.attack = "지식 그래프 분석 결과 사용자 입력 흐름이 아닌 정적 import로 확인되어 오탐으로 판단했습니다."
        finding.fix = "수정 불필요: 해당 값은 코드베이스 내 정적 asset import에서 유래합니다."
    return finding


def _sync_graph_for_demo(graph, analysis_id: str) -> None:
    try:
        sync_to_neo4j(graph, analysis_id=analysis_id)
    except Exception:
        pass


def run_adaptive(req: AnalyzeRequest, graph=None, analysis_id: str = "latest") -> AnalyzeResponse:
    t0 = time.time()
    cves: list[dict] = []

    # Stage 1: QLoRA 파인튜닝 모델
    try:
        content_ft = build_ft_user_prompt(req.language, req.code)
        resp_ft, _ = call_model(content_ft, MODEL_FT, is_finetuned=True, timeout=60)
        parsed_ft  = parse_response(resp_ft)
    except Exception:
        resp_ft, parsed_ft = "", {"VULNERABILITY": "—", "SEVERITY": "—", "ATTACK": "—", "FIX": "—"}

    vuln_ft = parsed_ft.get("VULNERABILITY", "—")
    sev_ft  = parsed_ft.get("SEVERITY",      "—")
    # Stage 1 성공 조건: VULNERABILITY 유효성 + SEVERITY 둘 다 있어야 완전한 응답으로 처리
    ok_ft   = (_is_valid_vuln(vuln_ft) and
               sev_ft not in ("—", "N/A", "", None))
    stage   = 1
    final   = parsed_ft

    if ok_ft:
        # Stage 1 완전 성공 — VULNERABILITY: NONE(안전 판정)이면 RAG도 건너뜀
        if req.use_rag and not _no_vuln(vuln_ft):
            cve_q = f"{req.language} {vuln_ft} {req.code[:120]}"
            cves  = search_cves(cve_q)
    else:
        # Stage 2: base + RAG 폴백
        # Stage 1이 VULNERABILITY를 식별했다면 더 정확한 CVE 쿼리에 활용
        stage = 2
        hint  = vuln_ft if not _no_vuln(vuln_ft) else "security vulnerability"
        cve_q = f"{req.language} {hint} {req.code[:120]}"
        cves  = search_cves(cve_q) if req.use_rag else []
        try:
            content_b = build_base_rag_prompt(req.language, req.code, cves)
            resp_b, _ = call_model(content_b, MODEL_BASE, is_finetuned=False, timeout=60)
            final = parse_response(resp_b)
        except Exception:
            pass

    vuln = final.get("VULNERABILITY", "—")
    sev  = final.get("SEVERITY",      "—")

    # CVSS 추출: "9.8", "CVSS 7.5", "base score: 8.1" 등 다양한 형식 처리
    _cvss_raw = final.get("CVSS", "—")
    cvss_score: Optional[float] = None
    if _cvss_raw not in ("—", "N/A", "", None):
        _m = re.search(r"(\d+(?:\.\d+)?)", _cvss_raw)
        if _m:
            try:
                _v = float(_m.group(1))
                cvss_score = _v if 0.0 <= _v <= 10.0 else None
            except ValueError:
                pass

    response = AnalyzeResponse(
        language    = req.language,
        file_path   = req.file_path,
        detected    = not _no_vuln(vuln),
        stage       = stage,
        vulnerability = vuln,
        severity    = sev,
        cvss_score  = cvss_score,
        attack      = _translate_ko(final.get("ATTACK", "—")),
        fix         = _translate_ko(final.get("FIX",    "—")),
        cve_references = [
            CveReference(
                cve_id      = c.get("cve_id", "N/A"),
                severity    = c.get("severity", "N/A"),
                base_score  = c.get("base_score", 0),
                cwe_id      = c.get("cwe_id", "N/A"),
                description = c.get("description", "")[:200],
            )
            for c in cves
        ],
        elapsed = round(time.time() - t0, 2),
    )
    if graph is not None:
        response = _enrich_with_graph(response, graph, vuln, req.file_path, analysis_id)
    return response


# ── 엔드포인트 ────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "model": MODEL_FT, "version": "4.0.0"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    if not req.code.strip():
        raise HTTPException(status_code=400, detail="code is empty")
    if not req.language.strip():
        raise HTTPException(status_code=400, detail="language is required")
    graph = build_code_graph(_graph_files_from_requests([req]))
    analysis_id = f"single:{req.file_path or '<stdin>'}"
    _sync_graph_for_demo(graph, analysis_id=analysis_id)
    return run_adaptive(req, graph=graph, analysis_id=analysis_id)


@app.post("/analyze/batch", response_model=BatchResponse)
def analyze_batch(req: BatchRequest):
    t0 = time.time()
    results: list[AnalyzeResponse] = []
    graph = build_code_graph(_graph_files_from_requests(req.files))
    analysis_id = "batch"
    _sync_graph_for_demo(graph, analysis_id=analysis_id)

    for file_req in req.files:
        if not file_req.code.strip():
            continue
        r = run_adaptive(file_req, graph=graph, analysis_id=analysis_id)
        results.append(r)
        if req.stop_on_first and r.detected:
            break

    detected_count = sum(1 for r in results if r.detected)
    return BatchResponse(
        total          = len(results),
        detected_count = detected_count,
        results        = results,
        elapsed        = round(time.time() - t0, 2),
    )


# 실제 취약점 이름에 등장하는 키워드 — 이 중 하나도 없고 CWE도 없으면 헛것으로 간주
_VALID_VULN_TERMS = (
    "xss", "cross-site", "cross site", "csrf", "ssrf", "sql", "injection",
    "command", "code execution", "rce", "remote code", "eval", "deserial",
    "xxe", "xml external", "path traversal", "directory traversal", "lfi", "rfi",
    "cors", "open redirect", "prototype pollution", "idor", "broken access",
    "authentication", "authorization", "hardcoded", "secret", "credential",
    "sensitive", "insecure", "ssti", "template injection", "ldap", "nosql",
    "race condition", "buffer overflow", "integer overflow", "format string",
    "weak", "crypto", "random", "jwt", "session", "clickjacking", "dom",
    "untrusted", "validation", "sanitiz", "redos", "denial of service", "dos",
)


def _is_valid_vuln_name(name: str) -> bool:
    """LLM이 토해낸 헛것(예: 'AI Assistant', 'On the first line')을 거른다.
    CWE-ID가 있거나 알려진 취약점 용어를 포함해야 진짜로 본다.
    """
    if not name:
        return False
    low = name.lower()
    if re.search(r"cwe[-\s]?\d+", low):
        return True
    if any(term in low for term in _VALID_VULN_TERMS):
        return True
    # 문장형 잡설(소문자로 시작하는 산문, 너무 긴 이름)은 거름
    return False


def _vuln_category(name: str) -> str:
    """취약점 이름을 카테고리로 정규화 (LLM 결과 ↔ 규칙 결과 중복 판정용)."""
    low = (name or "").lower()
    if "ssrf" in low or "request forgery" in low:        return "ssrf"
    if "xss" in low or "cross-site script" in low or "cross site script" in low:
        return "xss"
    if "eval" in low or "code injection" in low or "code execution" in low or "rce" in low:
        return "code-injection"
    if "command injection" in low:                       return "command-injection"
    if "sql" in low:                                     return "sql-injection"
    if "path traversal" in low or "directory traversal" in low: return "path-traversal"
    if "deserial" in low:                                return "deserialization"
    if "xxe" in low or "xml external" in low:            return "xxe"
    if "prototype pollution" in low:                     return "prototype-pollution"
    if "csrf" in low:                                    return "csrf"
    if "cors" in low:                                    return "cors"
    if "open redirect" in low:                           return "open-redirect"
    # 그 외에는 이름 앞부분으로 구분
    return low[:24]


def _parse_all_blocks(raw: str) -> list[dict]:
    """LLM 응답에서 모든 취약점 블록을 파싱한다.
    --- 구분자 또는 VULNERABILITY: 키워드 재등장 기준으로 분리.
    중복 취약점(이름+심각도 동일)은 제거한다.
    """
    # --- 구분자로 먼저 시도
    if re.search(r"\n---+", raw):
        parts = re.split(r"\n---+\n?", raw)
    else:
        # VULNERABILITY: 재등장 기준으로 분리
        parts = re.split(r"(?=\nVULNERABILITY\s*:)", raw)

    seen: set[tuple] = set()
    results = []
    for block in parts:
        block = block.strip()
        if not block:
            continue
        parsed = parse_response(block)
        vuln = parsed.get("VULNERABILITY", "—")
        sev  = parsed.get("SEVERITY", "—")
        if not vuln or vuln in ("—", "N/A", ""):
            continue
        # 파싱 오류 필터: "SOLUTION:", ";" 포함된 이름은 제거
        if "solution:" in vuln.lower() or ";" in vuln:
            continue
        # 헛것 필터: 알려진 취약점 용어/CWE 없는 이름은 LLM 환각으로 보고 제거
        if not _is_valid_vuln_name(vuln):
            continue
        key = (vuln.lower()[:40], sev.lower())
        if key in seen:
            continue
        seen.add(key)
        results.append(parsed)
    return results


_VULN_KEYWORDS = {
    "ssrf":              ["fetch(", "axios.get", "http.get", "request.get", "url(", "open("],
    "xss":               ["innerhtml", "dangerouslysetinnerhtml", "__html", "document.write", "outerhtml"],
    "sql injection":     ["select ", "insert ", "update ", "delete ", "executequery", "createquery"],
    "command injection": ["exec(", "spawn(", "os.system", "subprocess", "shell=true"],
    "path traversal":    ["readfile", "writefile", "../", "path.join", "fs.open"],
    "hardcoded":         ["password", "secret", "api_key", "apikey", "token"],
    "cors":              ["access-control-allow-origin", "cors(", "allowedorigins"],
    "deserialization":   ["objectinputstream", "readobject", "pickle.loads", "unserialize"],
    "xxe":               ["documentbuilder", "xmlreader", "saxparser"],
}


def _find_diff_lines(patch: str, vuln_name: str) -> list[int]:
    """patch에서 취약점 키워드와 매칭되는 모든 추가 라인 번호를 반환한다."""
    if not patch:
        return []

    keywords: list[str] = []
    vuln_lower = vuln_name.lower()
    for key, kws in _VULN_KEYWORDS.items():
        if key in vuln_lower:
            keywords.extend(kws)

    matched: list[int] = []
    current_line = 0
    for patch_line in patch.split("\n"):
        hunk = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)", patch_line)
        if hunk:
            current_line = int(hunk.group(1)) - 1
            continue
        if patch_line.startswith("-"):
            continue
        current_line += 1
        if patch_line.startswith("+"):
            line_lower = patch_line[1:].lower()
            if keywords and any(kw in line_lower for kw in keywords):
                matched.append(current_line)

    if matched:
        return matched

    # 키워드 매칭 실패 시 첫 번째 추가 라인 fallback
    m = re.search(r"@@ -\d+(?:,\d+)? \+(\d+)", patch)
    return [int(m.group(1))] if m else []


# 고신호 위험 싱크 — LLM이 놓쳐도 무조건 탐지하는 결정적 규칙
# (정규식, 취약점명, 심각도, CVSS, 공격 시나리오, 수정 방법)
_SINK_RULES: list[tuple] = [
    (re.compile(r"\beval\s*\("),
     "Code Injection (CWE-95)", "CRITICAL", 9.8,
     "공격자가 입력값을 통해 임의 JavaScript 코드를 실행시킬 수 있습니다.",
     "eval() 사용을 제거하고 신뢰할 수 없는 입력을 절대 실행하지 마세요."),
    (re.compile(r"dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\("),
     "Cross-Site Scripting (XSS, CWE-79)", "HIGH", 7.5,
     "공격자가 악성 스크립트를 주입해 다른 사용자의 세션·쿠키를 탈취할 수 있습니다.",
     "DOMPurify로 HTML을 새니타이즈하거나 textContent를 사용하세요."),
    (re.compile(r"\bfetch\s*\(\s*[a-zA-Z_$][\w$.\[\]]*\s*\)|axios\.(?:get|post|request)\s*\(\s*[a-zA-Z_$]"),
     "Server-Side Request Forgery (SSRF, CWE-918)", "HIGH", 8.1,
     "공격자가 임의 URL로 요청을 유도해 내부 자원에 접근하거나 정보를 탈취할 수 있습니다.",
     "허용된 도메인 화이트리스트로 URL을 검증한 뒤 요청하세요."),
]


def _rule_based_findings(patch: str) -> list[dict]:
    """patch의 추가 라인에서 고신호 위험 싱크를 결정적으로 탐지한다.
    LLM이 놓친 eval/XSS/SSRF를 보장 탐지하기 위한 안전망.
    같은 취약점 카테고리는 라인별로 모아 1건으로 반환한다.
    """
    if not patch:
        return []

    # 카테고리명 → {정보, 라인목록}
    hits: dict[str, dict] = {}
    current_line = 0
    for patch_line in patch.split("\n"):
        hunk = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)", patch_line)
        if hunk:
            current_line = int(hunk.group(1)) - 1
            continue
        if patch_line.startswith("-"):
            continue
        current_line += 1
        if not patch_line.startswith("+"):
            continue
        added = patch_line[1:]
        # 주석 줄은 건너뜀 (//, #, * 로 시작)
        stripped = added.strip()
        if stripped.startswith(("//", "#", "*", "/*")):
            continue
        for rx, vuln, sev, cvss, attack, fix in _SINK_RULES:
            if rx.search(added):
                slot = hits.setdefault(vuln, {
                    "vulnerability": vuln, "severity": sev, "cvss": cvss,
                    "attack": attack, "fix": fix, "lines": [],
                })
                slot["lines"].append(current_line)
    return list(hits.values())


@app.post("/analyze/pr", response_model=PrScanResponse)
def analyze_pr(req: PrScanRequest, _: None = Security(_require_api_key)):
    """GitHub PR diff 보안 스캔 — GitHub Action에서 호출"""
    t0 = time.time()
    findings: list[PrFinding] = []
    graph = build_code_graph(_graph_files_from_requests(req.files))
    analysis_id = f"pr:{req.repo}#{req.pr_number}"
    _sync_graph_for_demo(graph, analysis_id=analysis_id)

    for pr_file in req.files:
        language = _detect_language(pr_file.filename)
        if not language:
            continue
        content = pr_file.content.strip()
        if not content or len(content) > 12_000:
            continue

        # Stage1(QLoRA) + Stage2(base+RAG) 로 raw 응답 수집 후 전체 블록 파싱
        cves = search_cves(f"{language} security vulnerability {content[:120]}")
        # Stage 1
        try:
            prompt_ft = build_ft_user_prompt(language, content)
            raw_ft, _ = call_model(prompt_ft, MODEL_FT, is_finetuned=True, timeout=60)
        except Exception:
            raw_ft = ""
        # Stage 2
        try:
            prompt_b = build_base_rag_prompt(language, content, cves)
            raw_b, _ = call_model(prompt_b, MODEL_BASE, is_finetuned=False, timeout=90)
        except Exception:
            raw_b = ""

        # 두 응답 합쳐서 전체 취약점 블록 파싱 (중복 제거)
        combined = raw_ft + "\n---\n" + raw_b
        all_blocks = _parse_all_blocks(combined)

        # 이 파일에서 이미 잡은 취약점 카테고리 (LLM + 규칙 중복 방지)
        covered: set[str] = set()
        file_findings: list[PrFinding] = []

        for parsed in all_blocks:
            vuln = parsed.get("VULNERABILITY", "—")
            sev  = parsed.get("SEVERITY", "—")
            if not vuln or vuln in ("—", "N/A", ""):
                continue

            _cvss_raw = parsed.get("CVSS", "")
            cvss_score: Optional[float] = None
            _m = re.search(r"(\d+(?:\.\d+)?)", _cvss_raw or "")
            if _m:
                try:
                    v = float(_m.group(1))
                    cvss_score = v if 0.0 <= v <= 10.0 else None
                except ValueError:
                    pass

            # 이 취약점 타입에 맞는 모든 라인 찾기
            diff_lines = _find_diff_lines(pr_file.patch, vuln)
            if not diff_lines:
                diff_lines = [None]

            covered.add(_vuln_category(vuln))

            # CVE 보강
            cve_q = f"{language} {vuln} {content[:80]}"
            file_cves = search_cves(cve_q, top_k=3)
            cve_refs = [
                CveReference(
                    cve_id=c.get("cve_id", "N/A"), severity=c.get("severity", "N/A"),
                    base_score=c.get("base_score", 0), cwe_id=c.get("cwe_id", "N/A"),
                    description=c.get("description", "")[:200],
                ) for c in file_cves
            ]

            for diff_line in diff_lines:
                finding = PrFinding(
                    filename=pr_file.filename,
                    detected=True,
                    vulnerability=vuln,
                    severity=sev,
                    cvss_score=cvss_score,
                    attack=_translate_ko(parsed.get("ATTACK", "—")),
                    fix=_translate_ko(parsed.get("FIX", "—")),
                    cve_references=cve_refs,
                    diff_line=diff_line,
                )
                file_findings.append(_enrich_pr_finding_with_graph(finding, graph, analysis_id))

        # 결정적 안전망: LLM이 놓친 고신호 위험 싱크 보장 탐지
        for rule in _rule_based_findings(pr_file.patch):
            if _vuln_category(rule["vulnerability"]) in covered:
                continue  # LLM이 이미 잡은 카테고리는 건너뜀
            covered.add(_vuln_category(rule["vulnerability"]))
            r_cves = search_cves(f"{language} {rule['vulnerability']}", top_k=3)
            r_refs = [
                CveReference(
                    cve_id=c.get("cve_id", "N/A"), severity=c.get("severity", "N/A"),
                    base_score=c.get("base_score", 0), cwe_id=c.get("cwe_id", "N/A"),
                    description=c.get("description", "")[:200],
                ) for c in r_cves
            ]
            for diff_line in (rule["lines"] or [None]):
                finding = PrFinding(
                    filename=pr_file.filename, detected=True,
                    vulnerability=rule["vulnerability"], severity=rule["severity"],
                    cvss_score=rule["cvss"], attack=rule["attack"], fix=rule["fix"],
                    cve_references=r_refs, diff_line=diff_line,
                )
                file_findings.append(_enrich_pr_finding_with_graph(finding, graph, analysis_id))

        if file_findings:
            findings.extend(file_findings)
        else:
            findings.append(PrFinding(
                filename=pr_file.filename, detected=False,
                vulnerability="—", severity="—", cvss_score=None,
                attack="—", fix="—", cve_references=[], diff_line=None,
            ))

    vulnerable_count = sum(1 for f in findings if f.detected)
    return PrScanResponse(
        repo=req.repo,
        pr_number=req.pr_number,
        total_files=len(findings),
        vulnerable_count=vulnerable_count,
        findings=findings,
        elapsed=round(time.time() - t0, 2),
    )
