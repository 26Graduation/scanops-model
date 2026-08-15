"""백엔드 language 문자열 → (확장자, Joern frontend) 매핑.

출처(실측):
  - scanops-backend GithubScanService.java:51-68  EXT_TO_LANG
  - scanops-model scripts/api_rebuild.py:201-206  _EXT_LANG
  - rebuild/data/cleanvul_v2_*.jsonl  meta.language  (Java/Python/JavaScript/C/C++)
두 소스의 문자열이 서로 다르므로(백엔드 ".java"→"Java Spring Boot",
api_rebuild ".java"→"Java") 합집합을 키로 둔다. 매칭은 소문자 정규화 후 완전일치,
실패 시 부분일치 폴백.
"""
from __future__ import annotations

# language 문자열(소문자) → (파일 확장자, joern importCode language 인자)
LANG_MAP: dict[str, tuple[str, str]] = {
    # Java
    "java": (".java", "JAVASRC"),
    "java spring boot": (".java", "JAVASRC"),
    # Python
    "python": (".py", "PYTHONSRC"),
    # JavaScript / TypeScript — jssrc2cpg 가 둘 다 처리
    "javascript": (".js", "JSSRC"),
    "node.js / express": (".js", "JSSRC"),
    "nodejs": (".js", "JSSRC"),
    "typescript": (".ts", "JSSRC"),
    "react / next.js": (".jsx", "JSSRC"),
    # C / C++
    "c": (".c", "NEWC"),
    "c++": (".cpp", "NEWC"),
    "cpp": (".cpp", "NEWC"),
    # 아래는 Joern 프론트엔드는 존재하나 이번 라운드에서 미검증(§9 기재)
    "php": (".php", "PHP"),
    "go": (".go", "GOLANG"),
    "ruby": (".rb", "RUBYSRC"),
    "c#": (".cs", "CSHARPSRC"),
    "kotlin": (".kt", "KOTLIN"),
}

# 이번 라운드에서 실제로 검증된 언어 (Phase 2 벤치 대상)
VERIFIED = {"JAVASRC", "PYTHONSRC", "JSSRC"}


def resolve(language: str) -> tuple[str, str] | None:
    """language 문자열 → (ext, joern_lang). 매핑 없으면 None."""
    if not language:
        return None
    key = language.strip().lower()
    if key in LANG_MAP:
        return LANG_MAP[key]
    # 부분일치 폴백 — 긴 키부터 (예 "Java Spring Boot 3.2")
    for k in sorted(LANG_MAP, key=len, reverse=True):
        if k in key:
            return LANG_MAP[k]
    return None


def ensure_ext(path: str, ext: str) -> str:
    """Joern은 확장자로 언어를 인식한다. 없으면 강제로 붙인다."""
    return path if path.endswith(ext) else path + ext
