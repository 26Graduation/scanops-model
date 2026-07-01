"""ScanOps V13 API — 파인튜닝 모델 + 코드그래프 (LLM ∨ graph), RAG 미사용
================================================================
백엔드(scanops-backend `ScanopsModelClient`)가 기대하는 기존 계약(api_server.py 스키마)을
**그대로 유지**하면서, 내부 분석만 v13+코드그래프 앙상블(RAG 없음)로 제공한다.
→ 백엔드 코드 무수정으로 교체 가능.

엔드포인트: GET /health · POST /analyze · POST /analyze/batch · POST /analyze/pr
실행:  uvicorn scripts.api_v13:app --host 0.0.0.0 --port 8100
환경변수: SCANOPS_V13_MODEL, OLLAMA_URL, SCANOPS_API_KEY(선택, 헤더 X-Scanops-Key)
"""
from __future__ import annotations

import os
import re
import sys
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi import FastAPI, HTTPException, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, Field

from scanops.core.ensemble import predict_single, V13_MODEL

app = FastAPI(title="ScanOps V13 API (LLM + Graph, no RAG)", version="13.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_API_KEY = os.getenv("SCANOPS_API_KEY", "")
_API_KEY_HEADER = APIKeyHeader(name="X-Scanops-Key", auto_error=False)


def _auth(key: Optional[str] = Security(_API_KEY_HEADER)) -> None:
    if _API_KEY and key != _API_KEY:
        raise HTTPException(status_code=401, detail="invalid or missing X-Scanops-Key")


# ── 백엔드 계약 스키마 (api_server.py와 동일 필드) ────────────────────────────
class AnalyzeRequest(BaseModel):
    language: str
    code: str
    file_path: Optional[str] = None
    use_rag: bool = True                 # 받되 무시 (V13은 RAG 미사용)


class CveReference(BaseModel):
    cve_id: str
    severity: str
    base_score: float
    cwe_id: str
    description: str


class AnalyzeResponse(BaseModel):
    language: str
    file_path: Optional[str] = None
    detected: bool
    stage: int = 1                       # 항상 1 (2-stage adaptive 없음)
    vulnerability: str
    severity: str
    cvss_score: Optional[float] = None
    attack: str = ""
    fix: str = ""
    cve_references: list[CveReference] = Field(default_factory=list)
    suppressed_by_graph: bool = False
    votes: dict = Field(default_factory=dict)   # {llm, graph} (근거·디버깅용 추가필드)
    elapsed: float = 0.0


class BatchRequest(BaseModel):
    files: list[AnalyzeRequest]
    stop_on_first: bool = False


class BatchResponse(BaseModel):
    total: int
    detected_count: int
    results: list[AnalyzeResponse]
    elapsed: float


class PrFile(BaseModel):
    filename: str
    content: str
    patch: Optional[str] = None


class PrScanRequest(BaseModel):
    repo: str
    pr_number: int
    files: list[PrFile]


class PrFinding(BaseModel):
    filename: str
    detected: bool
    vulnerability: str
    severity: str
    cvss_score: Optional[float] = None
    attack: str = ""
    fix: str = ""
    cve_references: list[CveReference] = Field(default_factory=list)
    diff_line: Optional[int] = None


class PrScanResponse(BaseModel):
    repo: str
    pr_number: int
    total_files: int
    vulnerable_count: int
    findings: list[PrFinding]
    elapsed: float


# ── 공통 헬퍼 ──────────────────────────────────────────────────────────────────
def _to_float(cvss: Optional[str]) -> Optional[float]:
    try:
        f = float(cvss)
        return f if f > 0 else None
    except (TypeError, ValueError):
        return None


# ── CWE별 공격 시나리오 / 수정 가이드 (attack·fix 채움, 추가 모델호출 없음) ──────
_GUIDE: dict[str, tuple[str, str]] = {
    "89":  ("공격자가 입력 파라미터에 SQL 구문을 삽입해 인증 우회·데이터 유출·변조를 시도할 수 있다.",
            "PreparedStatement 등 파라미터화 쿼리(placeholder 바인딩)를 사용하고, 사용자 입력을 쿼리 문자열에 직접 연결하지 않는다."),
    "78":  ("사용자 입력이 셸 명령에 그대로 전달돼 임의 명령 실행(RCE)이 가능하다.",
            "셸을 거치지 않는 API(ProcessBuilder 인자 분리·execFile)를 쓰고, 입력을 화이트리스트로 검증하거나 shlex.quote/escapeshellarg로 이스케이프한다."),
    "79":  ("사용자 입력이 이스케이프 없이 HTML/JS로 출력돼 피해자 브라우저에서 스크립트가 실행된다(세션 탈취·피싱).",
            "출력 컨텍스트에 맞게 인코딩(HTML escape)하고 프레임워크 자동 이스케이프·CSP를 적용한다. innerHTML 대신 textContent를 쓴다."),
    "22":  ("경로에 ../ 등을 삽입해 의도치 않은 파일을 읽거나 쓸 수 있다(경로 조작).",
            "정규화(getCanonicalPath/realpath) 후 허용 디렉터리 접두어를 검증하고, 파일명은 화이트리스트/basename으로 제한한다."),
    "918": ("서버가 사용자가 지정한 URL로 요청을 보내 내부망·메타데이터 서비스에 접근당할 수 있다(SSRF).",
            "대상 호스트를 화이트리스트로 제한하고, 내부 IP/사설 대역·리다이렉트를 차단한다."),
    "502": ("신뢰할 수 없는 직렬화 데이터를 역직렬화해 임의 객체 생성·코드 실행이 가능하다.",
            "역직렬화 대상 클래스를 화이트리스트로 제한하거나 JSON 등 안전한 포맷을 쓰고, 서명·무결성 검증을 적용한다."),
    "94":  ("사용자 입력이 코드로 평가(eval 등)돼 임의 코드가 실행된다.",
            "동적 코드 평가(eval/exec)를 제거하고, 필요한 로직은 안전한 파서·매핑 테이블로 대체한다."),
    "74":  ("사용자 입력이 정화 없이 실행/질의 컨텍스트에 주입돼 인젝션이 발생한다.",
            "입력을 컨텍스트에 맞게 검증·이스케이프하고, 파라미터화·안전 API로 sink를 대체한다."),
    "327": ("취약하거나 구식인 암호 알고리즘을 사용해 기밀성이 보장되지 않는다.",
            "AES-GCM 등 검증된 최신 알고리즘·모드를 사용하고 DES/ECB 등 취약 알고리즘을 제거한다."),
    "328": ("MD5/SHA1 등 충돌에 취약한 해시를 사용한다.",
            "비밀번호는 bcrypt/argon2, 무결성은 SHA-256 이상을 사용한다."),
    "330": ("예측 가능한 난수를 보안 용도에 사용해 토큰·세션이 추측될 수 있다.",
            "암호학적 난수생성기(SecureRandom/secrets)를 사용한다."),
    "798": ("자격증명·키가 소스코드에 하드코딩돼 유출 시 즉시 악용된다.",
            "비밀값을 환경변수·시크릿 매니저로 분리하고 저장소에서 제거·회전한다."),
    "611": ("외부 엔티티를 처리하는 XML 파서로 파일 유출·SSRF가 가능하다(XXE).",
            "XML 파서의 DTD·외부 엔티티 처리를 비활성화한다."),
    "601": ("검증되지 않은 리다이렉트 대상으로 피싱 사이트로 유도될 수 있다.",
            "리다이렉트 대상을 화이트리스트/상대경로로 제한한다."),
    "90":  ("입력이 LDAP 필터에 삽입돼 인증 우회·정보 노출이 가능하다.",
            "LDAP 특수문자를 이스케이프(ESAPI.encodeForLDAP)하거나 안전한 바인딩을 쓴다."),
}
_KW = [("sql", "89"), ("command", "78"), ("cmd", "78"), ("xss", "79"), ("cross-site", "79"),
       ("traversal", "22"), ("path", "22"), ("ssrf", "918"), ("deserial", "502"),
       ("eval", "94"), ("code inj", "94"), ("crypto", "327"), ("cipher", "327"),
       ("hash", "328"), ("random", "330"), ("hardcod", "798"), ("secret", "798"),
       ("credential", "798"), ("xxe", "611"), ("redirect", "601"), ("ldap", "90"),
       ("inject", "74")]
_GENERIC = ("사용자 입력이 검증 없이 위험 지점에 도달해 악용될 수 있다.",
            "신뢰 경계에서 입력을 검증·이스케이프하고 안전한 API로 대체하며, 최소권한 원칙을 적용한다.")


def _guidance(vulnerability: Optional[str], graph_category: Optional[str]) -> tuple[str, str]:
    text = f"{graph_category or ''} {vulnerability or ''}"
    m = re.search(r"CWE-(\d+)", text)
    if m and m.group(1) in _GUIDE:
        return _GUIDE[m.group(1)]
    low = text.lower()
    for kw, cwe in _KW:
        if kw in low:
            return _GUIDE[cwe]
    return _GENERIC


def _detect_language(filename: str) -> str:
    ext = (filename.rsplit(".", 1)[-1] if "." in filename else "").lower()
    return {"py": "Python", "java": "Java", "js": "Node.js / Express",
            "ts": "TypeScript", "php": "PHP", "go": "Go", "rb": "Ruby",
            "cs": "C#", "c": "C", "cpp": "C++", "cc": "C++"}.get(ext, "Python")


def _first_diff_line(patch: Optional[str]) -> Optional[int]:
    """git patch에서 첫 추가 라인의 새 파일 기준 줄번호."""
    if not patch:
        return None
    m = re.search(r"@@ -\d+(?:,\d+)? \+(\d+)", patch)
    return int(m.group(1)) if m else None


def _analyze_one(language: str, code: str, file_path: Optional[str] = None) -> AnalyzeResponse:
    t0 = time.time()
    r = predict_single(code, language)
    attack, fix = ("", "")
    if r["vulnerable"]:
        attack, fix = _guidance(r.get("vulnerability"), (r.get("graph") or {}).get("category"))
    return AnalyzeResponse(
        language=language, file_path=file_path,
        detected=r["vulnerable"], stage=1,
        vulnerability=r.get("vulnerability") or "NONE",
        severity=r.get("severity") or "NONE",
        cvss_score=_to_float(r.get("cvss")),
        attack=attack, fix=fix, cve_references=[],
        suppressed_by_graph=False,
        votes=r.get("votes", {}),
        elapsed=round(time.time() - t0, 2),
    )


# ── 엔드포인트 ─────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "version": "13.0.0",
            "system": {"model": V13_MODEL, "rule": "LLM OR graph(taint)", "rag": False}}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest, _=Security(_auth)):
    if not req.code.strip():
        raise HTTPException(status_code=400, detail="empty code")
    try:
        return _analyze_one(req.language, req.code, req.file_path)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"model backend error: {e}")


@app.post("/analyze/batch", response_model=BatchResponse)
def analyze_batch(req: BatchRequest, _=Security(_auth)):
    t0 = time.time()
    results: list[AnalyzeResponse] = []
    for f in req.files:
        if not f.code.strip():
            continue
        res = _analyze_one(f.language, f.code, f.file_path)
        results.append(res)
        if req.stop_on_first and res.detected:
            break
    return BatchResponse(total=len(results),
                         detected_count=sum(1 for r in results if r.detected),
                         results=results, elapsed=round(time.time() - t0, 2))


@app.post("/analyze/pr", response_model=PrScanResponse)
def analyze_pr(req: PrScanRequest, _=Security(_auth)):
    t0 = time.time()
    findings: list[PrFinding] = []
    for f in req.files:
        if not f.content.strip():
            continue
        lang = _detect_language(f.filename)
        r = predict_single(f.content, lang)
        attack, fix = ("", "")
        if r["vulnerable"]:
            attack, fix = _guidance(r.get("vulnerability"), (r.get("graph") or {}).get("category"))
        findings.append(PrFinding(
            filename=f.filename, detected=r["vulnerable"],
            vulnerability=r.get("vulnerability") or "NONE",
            severity=r.get("severity") or "NONE",
            cvss_score=_to_float(r.get("cvss")),
            attack=attack, fix=fix, cve_references=[],
            diff_line=_first_diff_line(f.patch),
        ))
    return PrScanResponse(
        repo=req.repo, pr_number=req.pr_number,
        total_files=len(req.files),
        vulnerable_count=sum(1 for f in findings if f.detected),
        findings=findings, elapsed=round(time.time() - t0, 2))
