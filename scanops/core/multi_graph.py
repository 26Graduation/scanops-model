"""
다언어 정적 taint 분석 (Python/PHP/Go/C#/Ruby/Node/TS) — V12
================================================================
java_graph.py(Java 전용)·code_graph.py(JS/TS 멀티파일)에 더해, 단일 스니펫을
언어별 generic source→sink→sanitizer 규칙으로 판정한다.

설계 원칙 (java_graph와 동일):
  **확신할 때만 vuln/safe, 애매하면 unknown(LLM 위임).**
  → false-safe(취약을 안전으로)를 0에 가깝게 유지하는 게 최우선.

⚠️ 과적합 방지 규약: 여기 규칙은 **언어 시맨틱(일반 지식) 기반**으로만 작성한다.
   평가 벤치마크(OWASP·CVEfixes)의 개별 테스트 케이스를 보고 규칙을 맞추지 않는다.
   (V11에서 OWASP decoy에 맞춰 규칙을 손튜닝한 것이 분석기 과적합이었음.)

판정 계약: analyze(code, language) -> {verdict: vuln|safe|unknown, category, reason}
"""
from __future__ import annotations

import re

# ── 카테고리 표시용 ──────────────────────────────────────────────────────────
_CWE = {
    "sqli": "CWE-89 SQL Injection", "cmdi": "CWE-78 OS Command Injection",
    "xss": "CWE-79 Cross-Site Scripting", "pathtraver": "CWE-22 Path Traversal",
    "ssrf": "CWE-918 Server-Side Request Forgery", "deser": "CWE-502 Insecure Deserialization",
    "codei": "CWE-94 Code Injection", "crypto": "CWE-327 Weak Cryptography",
    "hash": "CWE-328 Weak Hash", "weakrand": "CWE-330 Insecure Randomness",
    "secret": "CWE-798 Hardcoded Credentials",
}

def _v(cat, reason): return {"verdict": "vuln", "category": _CWE.get(cat, cat), "reason": reason}
def _s(cat, reason, strong=False):
    # strong=True: sink+sanitizer가 같은 자리에 명시된 고신뢰 safe(하이브리드 veto 가능).
    # strong=False: '원시형만/source 없음' 같은 약한 safe → 실제 CVE에선 veto 금물.
    return {"verdict": "safe", "category": _CWE.get(cat, cat), "reason": reason, "strong": strong}
def _u(reason, cat="?"): return {"verdict": "unknown", "category": _CWE.get(cat, cat), "reason": reason}

# ── 언어별 사용자입력 source 패턴 ────────────────────────────────────────────
SOURCES = {
    "python": [r"request\.(args|form|values|data|json|get_json|cookies|headers|files)",
               r"\bos\.environ\b.*\[", r"sys\.argv", r"\binput\("],
    "php":    [r"\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b", r"php://input", r"file_get_contents\(\s*['\"]php://input"],
    "go":     [r"r\.URL\.Query\(\)", r"r\.FormValue\(", r"r\.PostFormValue\(", r"mux\.Vars\(", r"c\.Param\(", r"c\.Query\("],
    "csharp": [r"Request\[", r"Request\.(Query|Form|Params|QueryString|Headers)", r"\bRequest\.InputStream"],
    "ruby":   [r"\bparams\[", r"request\.(params|query_parameters|GET|POST|body)", r"cookies\["],
    "node":   [r"req\.(query|params|body|cookies|headers)", r"request\.(query|params|body)",
               r"location\.(hash|search|href)", r"document\.URL", r"process\.argv"],
}
# Node/JS = TypeScript/React 포함
SOURCES["typescript"] = SOURCES["node"]
SOURCES["javascript"] = SOURCES["node"]

# ── 카테고리별 위험 sink 패턴 (언어 공통/언어별 혼합) ─────────────────────────
SINKS = {
    "cmdi": {
        "python": [r"\bos\.system\(", r"subprocess\.(call|run|Popen|check_output)\([^[]*shell\s*=\s*True", r"\bos\.popen\("],
        "php":    [r"\b(system|exec|shell_exec|passthru|popen|proc_open)\("],
        "go":     [r"exec\.Command\(\s*\"(sh|bash|cmd|cmd\.exe)\""],
        "csharp": [r"Process\.Start\(\s*\"(cmd|cmd\.exe|/bin/sh|bash)"],
        "ruby":   [r"\bsystem\(\s*[\"'][^\"']*#\{", r"`[^`]*#\{", r"\b(exec|eval|%x)\("],
        "node":   [r"\b(exec|execSync)\(", r"child_process"],
    },
    "sqli": {
        "python": [r"\.execute\(\s*f[\"']", r"\.execute\([\"'][^\"']*[\"']\s*[%+]", r"\.execute\([\"'].*\+\s*\w"],
        "php":    [r"->query\(", r"mysqli_query\(", r"->exec\("],
        "go":     [r"\.Query\(", r"\.Exec\(", r"\.QueryRow\("],
        "csharp": [r"new\s+SqlCommand\(", r"\.ExecuteReader\(", r"\.ExecuteNonQuery\("],
        "ruby":   [r"\.where\(\s*[\"'][^\"']*#\{", r"\.find_by_sql\(", r"\.execute\("],
        "node":   [r"\.query\(\s*`[^`]*\$\{", r"\.query\([\"'][^\"']*[\"']\s*\+", r"\$where"],
    },
    "pathtraver": {
        "python": [r"\bopen\(", r"send_file\(", r"send_from_directory\("],
        "php":    [r"\b(readfile|file_get_contents|fopen|include|require)\("],
        "go":     [r"os\.(ReadFile|Open)\(", r"ioutil\.ReadFile\(", r"http\.ServeFile\("],
        "csharp": [r"File\.(ReadAllText|ReadAllBytes|Open|OpenRead)\("],
        "ruby":   [r"File\.(read|open|new)\(", r"send_file\b"],
        "node":   [r"fs\.(readFile|readFileSync|createReadStream)\(", r"res\.sendFile\("],
    },
    "ssrf": {
        "python": [r"requests\.(get|post|put|head)\(", r"urllib\.request\.urlopen\(", r"httpx\.(get|post)\("],
        "php":    [r"\b(file_get_contents|curl_exec|fopen)\(", r"curl_setopt\(.*CURLOPT_URL"],
        "go":     [r"http\.(Get|Post|Head)\(", r"http\.NewRequest\("],
        "csharp": [r"(HttpClient|WebClient)[^;]*\.(GetAsync|DownloadString|GetStringAsync)\("],
        "ruby":   [r"\b(Net::HTTP|open-uri|URI\.open|HTTParty)\b", r"\bopen\(\s*params"],
        "node":   [r"\b(fetch|axios\.get|axios\.post|http\.get|https\.get|request)\("],
    },
    "deser": {
        "python": [r"pickle\.loads?\(", r"yaml\.load\((?![^)]*Loader)", r"\bmarshal\.loads?\("],
        "php":    [r"\bunserialize\("],
        "go":     [r"gob\.NewDecoder\("],
        "csharp": [r"BinaryFormatter\(\)", r"\.Deserialize\("],
        "ruby":   [r"Marshal\.load\(", r"YAML\.load\((?![^)]*safe)"],
        "node":   [r"node-serialize", r"unserialize\("],
    },
    "codei": {
        "python": [r"\beval\(", r"\bexec\(", r"compile\("],
        "php":    [r"\beval\(", r"assert\(\s*\$", r"create_function\("],
        "go":     [],
        "csharp": [r"CSharpScript\.Eval", r"DataTable\(\)\.Compute\("],
        "ruby":   [r"\beval\(", r"instance_eval\(", r"\bsend\(\s*params"],
        "node":   [r"\beval\(", r"new\s+Function\(", r"vm\.runInNewContext\("],
    },
    "xss": {
        "python": [r"render_template_string\(", r"\bMarkup\(", r"HttpResponse\(\s*[\"'].*<"],
        "php":    [r"\becho\b", r"\bprint\b"],
        "go":     [r"fmt\.Fprintf\(\s*w\b", r"w\.Write\(\s*\[\]byte"],
        "csharp": [r"Response\.Write\(", r"\.InnerHtml\s*="],
        "ruby":   [r"\.html_safe\b", r"raw\("],
        "node":   [r"\.innerHTML\s*=", r"dangerouslySetInnerHTML", r"res\.send\(\s*[\"'`].*<", r"document\.write\("],
    },
}

# ── 카테고리별 sanitizer/안전 패턴 (있으면 confident safe) ────────────────────
SANITIZERS = {
    "sqli": [r"\.setString\(|\.setInt\(|\.setLong\(", r"prepare\(", r"execute\([^)]*,\s*[\(\[]",
             r"\$\d", r"\?\s*\)", r"AddWithValue", r"Parameters\.Add", r"\.where\([\"'][^\"']*\?",
             r"\.execute\([\"'][^\"']*%s[\"']\s*,", r"query\([\"'][^\"']*\$\d"],
    "cmdi": [r"execFile\(", r"execve\(", r"shell\s*=\s*False", r"escapeshellarg\(", r"shlex\.quote\(",
             r"ProcessStartInfo", r"ArgumentList", r"exec\.Command\((?!\s*\"(sh|bash|cmd))",
             r"subprocess\.(run|call|Popen)\(\s*\[", r"system\(\s*[\"'][^\"']*[\"']\s*,"],
    "pathtraver": [r"basename\(", r"filepath\.Base\(", r"getCanonicalPath", r"path\.normalize",
                   r"os\.path\.realpath", r"GetFullPath", r"startsWith\(|StartsWith\(|\.startswith\(",
                   r"secure_filename\(", r"filepath\.Clean\(",
                   # file_get_contents 등은 URL fetch(ssrf)일 수 있음 — host 검증 시 안전
                   r"parse_url\(|urlparse\(|new\s+URL\(|url\.Parse\(", r"in_array\([^)]*allow", r"allowlist|allowed|whitelist"],
    "ssrf": [r"ALLOW(ED|LIST)|allowlist|allowed|whitelist", r"in_array\([^)]*allow", r"\.includes\(",
             r"urlparse\(|parse_url\(|new\s+URL\(|url\.Parse\("],
    "deser": [r"json\.(loads?|decode|Unmarshal)\(", r"json_decode\(", r"yaml\.safe_load\(",
              r"YAML\.safe_load\(", r"JSON\.parse\(", r"literal_eval\(", r"readValue\("],
    "codei": [r"literal_eval\(", r"FILTER_VALIDATE", r"Integer\(", r"parseInt\(|Number\(",
              r"mathjs|math\.evaluate", r"JSON\.parse\("],
    "xss": [r"escapeHtml\(|htmlspecialchars\(|HtmlEncode\(|Encode\.forHtml|HTMLEscapeString",
            r"DOMPurify\.sanitize\(", r"textContent\s*=", r"escape\(", r"\|\s*e\b", r"bleach\.clean\("],
}

# ── source 비의존 카테고리: 약한/강한 원시형 직접 탐지 ────────────────────────
WEAK_CRYPTO = re.compile(r"\b(DES|TripleDES|3DES|DESede|RC4|Blowfish)\b|MODE_ECB|DES\.new", re.I)
STRONG_CRYPTO = re.compile(r"\bAES\b|AES\.new|Aes\.Create|MODE_GCM|MODE_CBC|ChaCha20", re.I)
WEAK_HASH = re.compile(r"\b(md5|sha1|sha-1)\b|createHash\(\s*[\"'](md5|sha1)", re.I)
STRONG_HASH = re.compile(r"bcrypt|scrypt|argon2|pbkdf2|password_hash|sha-?256|sha-?512|GenerateFromPassword", re.I)
WEAK_RAND = re.compile(r"\bMath\.random\(|\bnew\s+Random\b|\brandom\.(randint|random|choice)\(|mrand\.Int|"
                       r"\bRandom\(\)\.next", re.I)
STRONG_RAND = re.compile(r"SecureRandom|secrets\.(token|choice)|crypto\.randomBytes|crand\.Read|RNGCryptoServiceProvider", re.I)
HARDCODED = re.compile(r"(password|passwd|pwd|secret|api[_-]?key|token|apikey)\s*[:=]\s*[\"'][A-Za-z0-9_\-!@#$%^&*.]{6,}[\"']", re.I)
ENV_SECRET = re.compile(r"os\.environ|getenv|process\.env|System\.getenv|ENV\[|Environment\.GetEnvironmentVariable", re.I)


def _lang_key(language: str) -> str | None:
    l = (language or "").lower()
    if "java" in l and "javascript" not in l and "/ next" not in l and "react" not in l:
        return "java"          # → analyze_java로 위임
    if "python" in l: return "python"
    if "php" in l: return "php"
    if l.strip() == "go" or "golang" in l: return "go"
    if "c#" in l or "csharp" in l or ".net" in l: return "csharp"
    if "ruby" in l or "rails" in l: return "ruby"
    if any(k in l for k in ("node", "express", "javascript", "react", "next", "typescript", "ts")):
        return "node"
    return None


def _has(patterns, code) -> bool:
    return any(re.search(p, code) for p in patterns if p)


def analyze(code: str, language: str) -> dict:
    """다언어 generic taint 판정. Java는 java_graph로 위임."""
    key = _lang_key(language)
    if key == "java":
        from scanops.core.java_graph import analyze_java
        return analyze_java(code)
    if key is None:
        return _u("미지원 언어 → LLM 위임")

    sources = SOURCES.get(key, [])
    has_source = _has(sources, code)

    # ── A. source 비의존 원시형(crypto/hash/rand/secret) — 최우선 ─────────────
    if WEAK_CRYPTO.search(code):
        return _v("crypto", "약한 암호 알고리즘(DES/RC4/ECB 등)")
    if WEAK_HASH.search(code) and not STRONG_HASH.search(code):
        # 비밀번호/토큰 맥락에서 약한 해시면 취약
        if re.search(r"password|passwd|pwd|token|secret", code, re.I):
            return _v("hash", "비밀번호/토큰에 약한 해시(MD5/SHA1)")
        return _u("약한 해시지만 용도 불명 → LLM 위임", "hash")
    if WEAK_RAND.search(code) and not STRONG_RAND.search(code):
        if re.search(r"token|secret|password|session|nonce|otp|key", code, re.I):
            return _v("weakrand", "보안 토큰에 예측 가능한 난수")
        return _u("난수지만 보안 용도 불명 → LLM 위임", "weakrand")
    if HARDCODED.search(code) and not ENV_SECRET.search(code):
        return _v("secret", "하드코딩된 자격증명/시크릿")

    # ── A2. positive-safe: 파라미터화 쿼리 (LLM 오탐의 대표 케이스 veto) ───────
    # LLM은 "SELECT 보이면 SQLi"라고 자주 오탐한다. placeholder 바인딩이 있고
    # 문자열 연결(f-string/concat/template)이 전혀 없으면 확신 safe로 veto한다.
    has_sql_kw = bool(re.search(r"\b(SELECT|INSERT|UPDATE|DELETE|FROM\s+\w|WHERE)\b", code, re.I))
    sql_concat = bool(re.search(
        r"f[\"'][^\"']*\b(SELECT|INSERT|UPDATE|DELETE)\b"          # python f-string
        r"|[\"'][^\"']*\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b[^\"']*[\"']\s*[.+%]"  # concat
        r"|`[^`]*\$\{"                                              # JS 템플릿 리터럴
        r"|#\{",                                                   # ruby 보간
        code, re.I))
    if has_sql_kw and not sql_concat and _has(SANITIZERS["sqli"], code):
        return _s("sqli", "파라미터화 쿼리(placeholder 바인딩, 문자열 연결 없음)", strong=True)

    # ── B. source→sink→sanitizer taint (injection류) ─────────────────────────
    # 카테고리 우선순위: 명령/코드실행 > sqli > deser > path > ssrf > xss
    order = ["cmdi", "codei", "sqli", "deser", "pathtraver", "ssrf", "xss"]
    for cat in order:
        sink_pats = SINKS.get(cat, {}).get(key, [])
        if not sink_pats or not _has(sink_pats, code):
            continue
        # sqli sink는 SQL 키워드가 함께 있을 때만 인정 (r.URL.Query() 등 오매칭 방지)
        if cat == "sqli" and not has_sql_kw:
            continue
        # sink + sanitizer가 같은 자리 → 고신뢰(strong) safe
        if _has(SANITIZERS.get(cat, []), code):
            return _s(cat, f"{cat} sink에 정화/안전 API 적용됨", strong=True)
        # 사용자입력 source가 sink와 함께 있으면 confident vuln
        if has_source:
            return _v(cat, f"사용자 입력이 정화 없이 {cat} sink에 도달")
        # sink는 있으나 source 불명 → unknown
        return _u(f"{cat} sink 존재하나 source 흐름 판정 불가 → LLM 위임", cat)

    # ── C. 위험 sink 미검출 → unknown(LLM 위임) ──────────────────────────────
    # 주의: '강한 해시/난수가 어딘가 있다'는 함수 전체가 안전하다는 뜻이 아니다
    # (실제 CVE는 bcrypt 옆에서 다른 로직 결함으로 터진다). 따라서 safe로 단정하지
    # 않고 unknown으로 위임한다 — false-safe veto 방지.
    return _u("위험 sink 미검출 → LLM 위임")


if __name__ == "__main__":
    # 자체 점검 (paired 뱅크 = 학습측, 평가 벤치마크 아님)
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    from scripts.v12_cases import PAIRS
    ok = tot = 0
    miss = []
    for p in PAIRS:
        rv = analyze(p["vuln"], p["language"])
        rs = analyze(p["safe"], p["language"])
        for label, r, want in [("vuln", rv, "vuln"), ("safe", rs, "safe")]:
            tot += 1
            if r["verdict"] == want:
                ok += 1
            elif r["verdict"] == "unknown":
                pass  # unknown은 LLM 위임 → 오답 아님(보수적)
            else:
                miss.append((p["language"], p["cwe"], label, r["verdict"]))
    print(f"paired 자체점검: 정답 {ok}/{tot}  (unknown 제외)")
    if miss:
        print("오판(취약↔안전 뒤바뀜):")
        for m in miss: print("  ", m)
    else:
        print("✅ 취약↔안전 뒤바뀐 오판 0건 (false-safe/false-vuln 없음)")
