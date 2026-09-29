"""핵심 스캔 로직 — 파일/코드 스니펫을 받아 취약점을 반환한다.

웹 백엔드에서도 재사용할 수 있도록 CLI와 독립적인 순수 함수로 구현.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

import requests

from .embedder import embed_query
from .rag import OLLAMA_URL, LLM_MODEL, build_prompt, call_llm, search_cves

SUPPORTED_EXTENSIONS = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript/React",
    ".jsx": "JavaScript/React",
    ".java": "Java",
    ".c": "C",
    ".cpp": "C++",
    ".go": "Go",
    ".rb": "Ruby",
    ".php": "PHP",
    ".rs": "Rust",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".sh": "Shell",
    ".tf": "Terraform",
    ".kt": "Kotlin",
    ".swift": "Swift",
}

_SCAN_PROMPT_TEMPLATE = """\
You are a senior security engineer. Analyze the following {language} code for security vulnerabilities.

Code:
{code}

Respond with AT LEAST 3 vulnerabilities in this EXACT format (repeat the block for each finding):

VULNERABILITY: [name with CWE ID]
CVE: [CVE-YYYY-NNNNN or N/A]
CWE: [CWE-NNN]
CVSS: [0.0-10.0] ([CRITICAL|HIGH|MEDIUM|LOW])
LOCATION: [file:line or description]
ATTACK: [one-sentence attack scenario]
FIX:
[fixed code snippet or remediation steps]
---"""

# 파인튜닝 모델용 — 간단한 지시형, VULN_TYPE: 트리거 제거
_SCAN_PROMPT_FINETUNED = """\
Analyze this {language} code and list the security vulnerabilities:

{code}

For each vulnerability:
VULNERABILITY: <CWE-ID and name>
SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW>
ATTACK: <attack scenario>
FIX:
<fix>
---"""

_FINETUNED_MODEL_PREFIXES = ("qwen2.5-coder-security", "gemma2-security")


@dataclass
class Vulnerability:
    name: str
    cve_id: str = "N/A"
    cwe_id: str = "N/A"
    cvss_score: float | None = None
    severity: str = "UNKNOWN"
    location: str = "N/A"
    attack: str = ""
    fix: str = ""
    cve_references: list[dict] = field(default_factory=list)


@dataclass
class ScanResult:
    file_path: str
    language: str
    model: str
    elapsed: float
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    raw_output: str = ""

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == "HIGH")

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "language": self.language,
            "model": self.model,
            "elapsed_sec": round(self.elapsed, 2),
            "summary": {
                "total": len(self.vulnerabilities),
                "critical": self.critical_count,
                "high": self.high_count,
            },
            "vulnerabilities": [
                {
                    "name": v.name,
                    "cve_id": v.cve_id,
                    "cwe_id": v.cwe_id,
                    "cvss_score": v.cvss_score,
                    "severity": v.severity,
                    "location": v.location,
                    "attack": v.attack,
                    "fix": v.fix,
                    "cve_references": v.cve_references,
                }
                for v in self.vulnerabilities
            ],
        }


def _detect_language(path: Path) -> str:
    return SUPPORTED_EXTENSIONS.get(path.suffix.lower(), "Unknown")


_FIELD_LABELS = ("VULNERABILITY", "VULN_TYPE", "CVE", "CWE", "CVSS", "LOCATION", "ATTACK", "ATCK", "FIX", "SEVERITY")


def _normalize_raw(raw: str) -> str:
    """모델 출력의 마크다운 볼드를 제거해 'FIELD: value' 형태로 정규화.

    처리하는 형식:
      **FIELD:** value        (필드명만 볼드)
      **FIELD: value**        (줄 전체 볼드)
      **FIELD:** **value**    (각각 볼드)
    """
    # 코드 블록(```...```) 은 보존 — 잠깐 치환 후 복원
    code_blocks: list[str] = []
    def _save_code(m: re.Match) -> str:
        code_blocks.append(m.group(0))
        return f"\x00CODE{len(code_blocks)-1}\x00"
    raw = re.sub(r"```[\s\S]*?```", _save_code, raw)

    # **LABEL: ...** 또는 **LABEL:** 패턴 → LABEL: ...
    labels_pat = "|".join(_FIELD_LABELS)
    # Case 1: **LABEL: value** — 줄 전체 볼드
    raw = re.sub(
        rf"\*\*({labels_pat})\s*:\s*([^\*\n]*)\*\*",
        r"\1: \2",
        raw,
        flags=re.IGNORECASE,
    )
    # Case 2: **LABEL:** value — 필드명만 볼드
    raw = re.sub(
        rf"\*\*({labels_pat})\s*:\*\*\s*",
        r"\1: ",
        raw,
        flags=re.IGNORECASE,
    )
    # Case 3: **LABEL:** — 닫는 ** 없이 끝나는 경우
    raw = re.sub(
        rf"\*\*({labels_pat})\*\*\s*:",
        r"\1:",
        raw,
        flags=re.IGNORECASE,
    )
    # 남은 ** 제거 (라인 시작/끝)
    raw = re.sub(r"^\s*\*\*|\*\*\s*$", "", raw, flags=re.MULTILINE)

    # 코드 블록 복원
    for i, block in enumerate(code_blocks):
        raw = raw.replace(f"\x00CODE{i}\x00", block)

    return raw


def _parse_vulnerabilities(raw: str) -> list[Vulnerability]:
    """LLM 출력에서 구조화된 취약점 목록을 파싱한다.

    다양한 모델 출력 형식(마크다운 볼드, --- 구분자 없음, 번호 매기기 등)을 허용.
    """
    raw = _normalize_raw(raw)
    vulns: list[Vulnerability] = []

    # VULN_TYPE: → VULNERABILITY: 로 정규화 (파인튜닝 모델 출력 호환)
    raw = re.sub(r"(?i)VULN_TYPE\s*:", "VULNERABILITY:", raw)
    # ATCK: → ATTACK: 로 정규화
    raw = re.sub(r"(?i)\bATCK\s*:", "ATTACK:", raw)

    # 블록 분리: --- 구분자 → VULNERABILITY: 키워드 순으로 시도
    if re.search(r"\n---+", raw):
        blocks = re.split(r"\n---+\n?", raw)
    else:
        # VULNERABILITY: 가 새 줄 시작에 나오면 분리 (번호 1. 2. 포함)
        blocks = re.split(r"(?=(?:^|\n)\s*(?:\d+\.\s*)?VULNERABILITY\s*:)", raw, flags=re.IGNORECASE)

    for block in blocks:
        block = block.strip()
        if not re.search(r"VULNERABILITY\s*:", block, re.IGNORECASE):
            continue

        def _extract(key: str, text: str) -> str:
            """FIELD: value 한 줄 추출. 마크다운 잔재를 정리."""
            m = re.search(
                rf"^\s*(?:\d+\.\s*)?{key}\s*:\s*(.+)$",
                text,
                re.MULTILINE | re.IGNORECASE,
            )
            if not m:
                return "N/A"
            val = re.sub(r"\*+|_+", "", m.group(1)).strip()
            return val if val else "N/A"

        name    = _extract("VULNERABILITY", block)
        cve     = _extract("CVE", block)
        cwe_raw = _extract("CWE", block)
        cvss_raw= _extract("CVSS", block)
        location= _extract("LOCATION", block)
        # ATTACK 또는 ATCK (파인튜닝 모델이 줄여서 출력하는 경우)
        attack  = _extract("ATTACK", block)
        if attack == "N/A":
            attack = _extract("ATCK", block)
        # 파인튜닝 모델용: SEVERITY 필드 직접 파싱
        severity_raw = _extract("SEVERITY", block)

        # "None" 문자열 → "N/A" 정규화
        cve = "N/A" if cve.lower() in ("none", "n/a", "") else cve

        # name에 CWE가 포함된 경우 추출 (파인튜닝 모델 "CWE-79 NULL Pointer..." 형식)
        if cwe_raw in ("N/A", ""):
            cwe_in_name = re.search(r"CWE-\d+", name, re.IGNORECASE)
            if cwe_in_name:
                cwe_raw = cwe_in_name.group(0)

        # CWE: "CWE-89" 추출 또는 이름 그대로
        cwe = "N/A"
        cwe_m = re.search(r"CWE-\d+", cwe_raw, re.IGNORECASE)
        if cwe_m:
            cwe = cwe_m.group(0).upper()
        elif cwe_raw not in ("N/A", ""):
            cwe = cwe_raw

        # CVSS + severity
        cvss_score: float | None = None
        severity = "UNKNOWN"
        cm = re.search(r"([\d.]+)[^A-Z]*(CRITICAL|HIGH|MEDIUM|LOW)", cvss_raw, re.IGNORECASE)
        if cm:
            try:
                cvss_score = float(cm.group(1))
            except ValueError:
                pass
            severity = cm.group(2).upper()
        else:
            # SEVERITY 필드 또는 CVSS 텍스트에서 severity 추출
            for src in (cvss_raw, severity_raw):
                sev_m = re.search(r"\b(CRITICAL|HIGH|MEDIUM|LOW)\b", src, re.IGNORECASE)
                if sev_m:
                    severity = sev_m.group(1).upper()
                    break
            if severity == "UNKNOWN":
                if re.search(r"sql.inject|command.inject|rce|deseri|code.exec|buffer.overflow|format.string", name, re.IGNORECASE):
                    severity = "HIGH"
                elif re.search(r"xss|csrf|path.trav|xxe|ssrf|cors", name, re.IGNORECASE):
                    severity = "MEDIUM"

        # FIX: 다음 줄부터 다음 VULNERABILITY: 또는 --- 또는 끝까지
        fix_match = re.search(
            r"FIX\s*:\s*\n?([\s\S]+?)(?=\n\s*(?:\d+\.\s*)?VULNERABILITY\s*:|\n---|\Z)",
            block,
            re.IGNORECASE,
        )
        fix = fix_match.group(1).strip() if fix_match else ""
        # FIX 안의 남은 ** 제거
        fix = re.sub(r"\*\*", "", fix)

        vulns.append(Vulnerability(
            name=name,
            cve_id=cve,
            cwe_id=cwe,
            cvss_score=cvss_score,
            severity=severity,
            location=location,
            attack=attack,
            fix=fix,
        ))
    return vulns


def _parse_finetuned(raw: str) -> list[Vulnerability]:
    """파인튜닝 모델 출력 파서.

    다음 completion 포맷을 처리:
      VULNERABILITY: CWE-XX Name   (또는 첫 줄이 CWE-XX Name)
      SEVERITY: HIGH
      ATTACK: ...
      FIX:
      ...
    ---  ← 구분자 (선택적)
    """
    # 템플릿 placeholder 줄 제거 (<...> 로 싸인 라인)
    cleaned = re.sub(r"^<[^>]+>\s*$", "", raw, flags=re.MULTILINE)
    cleaned = cleaned.strip()
    if not cleaned:
        return []

    # VULNERABILITY: 또는 첫 줄로 이름 추출
    vuln_m = re.search(r"VULNERABILITY\s*:\s*(.+)", cleaned, re.IGNORECASE)
    if vuln_m:
        first_line = vuln_m.group(1).strip()
    else:
        first_line = cleaned.splitlines()[0].strip()

    # 플레이스홀더면 빈 것으로 처리
    if re.fullmatch(r"[\[<][^\]>]*[\]>]", first_line):
        first_line = "Unknown Vulnerability"

    cwe_m = re.search(r"CWE-(\d+)", first_line)
    cwe = f"CWE-{cwe_m.group(1)}" if cwe_m else "N/A"

    sev_m = re.search(r"SEVERITY\s*:\s*(CRITICAL|HIGH|MEDIUM|LOW)", cleaned, re.IGNORECASE)
    severity = sev_m.group(1).upper() if sev_m else "UNKNOWN"

    attack_m = re.search(r"ATTACK\s*:\s*(.+)", cleaned, re.IGNORECASE)
    attack = attack_m.group(1).strip() if attack_m else ""

    fix_m = re.search(r"FIX\s*:\s*\n?([\s\S]+?)(?:\n---|\Z)", cleaned, re.IGNORECASE)
    fix = fix_m.group(1).strip() if fix_m else ""

    if first_line == "Unknown Vulnerability" and not attack and not fix:
        return []

    return [Vulnerability(
        name=first_line,
        cve_id="N/A",
        cwe_id=cwe,
        severity=severity,
        attack=attack,
        fix=fix,
    )]


def _enrich_with_cves(vulns: list[Vulnerability], use_rag: bool = True) -> None:
    """각 취약점에 Qdrant에서 관련 CVE 레퍼런스를 붙인다."""
    if not use_rag:
        return
    for v in vulns:
        query = f"{v.cwe_id} {v.name} vulnerability"
        try:
            refs = search_cves(query, top_k=3)
            v.cve_references = refs
            # CVE ID가 N/A인 경우 가장 유사한 CVE로 보완 (None 레코드 제외)
            if v.cve_id == "N/A" and refs:
                ref_id = refs[0].get("cve_id")
                if ref_id:
                    v.cve_id = ref_id
        except Exception:
            pass


def scan_code(
    code: str,
    language: str = "Unknown",
    file_path: str = "<stdin>",
    use_rag: bool = True,
    model: str = LLM_MODEL,
) -> ScanResult:
    """코드 스니펫을 스캔하고 취약점 목록을 반환한다."""
    is_finetuned = any(model.startswith(p) for p in _FINETUNED_MODEL_PREFIXES)
    tmpl = _SCAN_PROMPT_FINETUNED if is_finetuned else _SCAN_PROMPT_TEMPLATE
    prompt = tmpl.format(language=language, code=code)
    t0 = time.time()
    raw = call_llm(prompt, model=model)
    elapsed = time.time() - t0

    if is_finetuned:
        vulns = _parse_finetuned(raw)
        if not vulns:
            vulns = _parse_vulnerabilities(raw)
    else:
        vulns = _parse_vulnerabilities(raw)
    _enrich_with_cves(vulns, use_rag=use_rag)

    return ScanResult(
        file_path=file_path,
        language=language,
        model=model,
        elapsed=elapsed,
        vulnerabilities=vulns,
        raw_output=raw,
    )


def scan_file(
    path: str | Path,
    use_rag: bool = True,
    model: str = LLM_MODEL,
) -> ScanResult:
    """파일을 읽어 스캔한다."""
    p = Path(path)
    language = _detect_language(p)
    code = p.read_text(encoding="utf-8", errors="replace")
    return scan_code(code, language=language, file_path=str(p), use_rag=use_rag, model=model)


def scan_directory(
    directory: str | Path,
    use_rag: bool = True,
    model: str = LLM_MODEL,
    max_files: int = 50,
) -> list[ScanResult]:
    """디렉터리 내 지원 확장자 파일을 재귀적으로 스캔한다."""
    d = Path(directory)
    results: list[ScanResult] = []
    files = [
        f for f in sorted(d.rglob("*"))
        if f.is_file() and f.suffix.lower() in SUPPORTED_EXTENSIONS
        and ".venv" not in f.parts
        and "node_modules" not in f.parts
    ][:max_files]
    for f in files:
        results.append(scan_file(f, use_rag=use_rag, model=model))
    return results
