"""
ScanOps Security Benchmark — 공통 프레임워크

친구들과 모델을 비교할 때 이 파일의 로직을 공유한다.
각자 어댑터(adapters/ 폴더)만 구현하면 동일한 20개 케이스로 공정하게 비교 가능.

사용법:
    from benchmark_core import run_benchmark
    from adapters.grok_adapter import query   # 또는 자신의 어댑터

    results = run_benchmark(query, model_name="My Model")
    # → reports/results_My_Model.json 저장
    # → reports/benchmark_My_Model.html 저장
"""

import json
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Callable

REPORTS = Path(__file__).resolve().parent.parent / "reports"

# ── 공통 20개 테스트 케이스 ────────────────────────────────────────────────────
# 이 케이스는 절대 수정하지 말 것 — 모든 모델이 동일한 문제를 풀어야 함

CASES = [
    # React / Next.js
    {
        "id": 1, "language": "React / Next.js",
        "code": 'return <div dangerouslySetInnerHTML={{__html: userInput}} />;',
        "expected_vuln": "XSS",
        "accepted": ["xss", "cross-site scripting", "cwe-79", "cwe-80", "dangerouslysetinnerhtml", "html injection", "dom injection"],
    },
    {
        "id": 2, "language": "React / Next.js",
        "code": 'return <a href={`javascript:${userAction}`}>Click</a>;',
        "expected_vuln": "XSS (javascript: URI)",
        "accepted": ["xss", "cross-site scripting", "cwe-79", "cwe-80", "javascript:", "open redirect", "cwe-601", "url injection", "href injection"],
    },
    {
        "id": 3, "language": "React / Next.js",
        "code": "eval(searchParams.get('callback'));",
        "expected_vuln": "Code Injection via eval",
        "accepted": ["code injection", "cwe-94", "cwe-95", "cwe-78", "eval", "remote code execution", "arbitrary code execution", "script injection", "javascript injection"],
    },
    {
        "id": 4, "language": "React / Next.js",
        "code": '<img src={user.avatar} onError={user.fallback} />',
        "expected_vuln": "XSS via event handler",
        "accepted": ["xss", "cross-site scripting", "cwe-79", "cwe-80", "event handler", "dom-based", "onerror", "prototype pollution", "client-side injection"],
    },
    # Node.js / Express
    {
        "id": 5, "language": "Node.js / Express",
        "code": 'db.query("SELECT * FROM users WHERE id=" + req.params.id);',
        "expected_vuln": "SQL Injection",
        "accepted": ["sql injection", "cwe-89", "sql", "query injection", "database injection"],
    },
    {
        "id": 6, "language": "Node.js / Express",
        "code": "exec(req.body.command);",
        "expected_vuln": "Command Injection",
        "accepted": ["command injection", "cwe-78", "cwe-77", "os command", "shell injection", "remote code execution", "arbitrary command"],
    },
    {
        "id": 7, "language": "Node.js / Express",
        "code": "res.setHeader('Access-Control-Allow-Origin', '*');",
        "expected_vuln": "Insecure CORS",
        "accepted": ["cors", "cwe-942", "cwe-346", "cross-origin", "access-control", "permissive", "wildcard origin", "misconfiguration", "information disclosure"],
    },
    {
        "id": 8, "language": "Node.js / Express",
        "code": "jwt.verify(token, 'hardcoded_secret_key');",
        "expected_vuln": "Hardcoded Secret",
        "accepted": ["hardcoded", "cwe-798", "cwe-259", "hard-coded", "secret", "credential", "jwt", "insecure secret", "embedded secret", "use of hard-coded"],
    },
    # Java Spring Boot
    {
        "id": 9, "language": "Java Spring Boot",
        "code": 'String query = "SELECT * FROM " + tableName;\nstmt.execute(query);',
        "expected_vuln": "SQL Injection",
        "accepted": ["sql injection", "cwe-89", "sql", "query injection", "database injection"],
    },
    {
        "id": 10, "language": "Java Spring Boot",
        "code": "Runtime.getRuntime().exec(userInput);",
        "expected_vuln": "Command Injection",
        "accepted": ["command injection", "cwe-78", "cwe-77", "os command", "shell injection", "remote code execution", "runtime.exec", "arbitrary command"],
    },
    {
        "id": 11, "language": "Java Spring Boot",
        "code": '@RequestMapping(value="/**")\npublic ResponseEntity<?> handle(HttpServletRequest req) {}',
        "expected_vuln": "Overly Permissive Endpoint",
        "accepted": [
            "overly permissive", "cwe-284", "cwe-285", "cwe-862", "cwe-863", "cwe-20", "cwe-269",
            "authorization", "access control", "improper", "permissive", "wildcard", "requestmapping",
            "missing authorization", "broken access control", "privilege", "idor",
        ],
    },
    {
        "id": 12, "language": "Java Spring Boot",
        "code": "if (password.equals(inputPassword)) { grantAccess(); }",
        "expected_vuln": "Timing Attack",
        "accepted": [
            "timing attack", "cwe-208", "cwe-362", "cwe-259", "cwe-798", "cwe-916",
            "hardcoded", "timing", "comparison", "constant-time", "brute force",
            "insecure comparison", "broken authentication", "weak password",
        ],
    },
    # Python
    {
        "id": 13, "language": "Python",
        "code": "import pickle\nobj = pickle.loads(user_data)",
        "expected_vuln": "Insecure Deserialization",
        "accepted": ["deserialization", "cwe-502", "pickle", "arbitrary code", "remote code execution", "code execution", "object injection"],
    },
    {
        "id": 14, "language": "Python",
        "code": "import subprocess\nsubprocess.call(user_input, shell=True)",
        "expected_vuln": "Command Injection",
        "accepted": ["command injection", "cwe-78", "cwe-77", "shell", "subprocess", "os command", "arbitrary command", "shell=true"],
    },
    {
        "id": 15, "language": "Python",
        "code": "import yaml\ndata = yaml.load(user_input)  # not safe_load",
        "expected_vuln": "Arbitrary Code Execution via YAML",
        "accepted": ["yaml", "cwe-502", "deserialization", "code execution", "arbitrary", "cwe-94", "unsafe load", "yaml.load", "injection"],
    },
    {
        "id": 16, "language": "Python",
        "code": 'import os\nos.system(f"ping {host}")',
        "expected_vuln": "Command Injection",
        "accepted": ["command injection", "cwe-78", "cwe-77", "os command", "shell injection", "os.system", "arbitrary command", "remote code execution"],
    },
    # C
    {
        "id": 17, "language": "C",
        "code": "printf(user_input);  // user-controlled format string",
        "expected_vuln": "Format String Attack",
        "accepted": ["format string", "cwe-134", "printf", "format", "memory corruption", "information disclosure"],
    },
    {
        "id": 18, "language": "C",
        "code": "char buf[64];\nstrcpy(buf, argv[1]);  // no bounds check",
        "expected_vuln": "Buffer Overflow",
        "accepted": ["buffer overflow", "cwe-120", "cwe-121", "cwe-122", "cwe-119", "strcpy", "memory", "overflow", "stack overflow", "bounds", "memory corruption"],
    },
    # GitHub Actions YAML
    {
        "id": 19, "language": "GitHub Actions YAML",
        "code": "- run: echo ${{ github.event.issue.title }}",
        "expected_vuln": "Script Injection via untrusted input",
        "accepted": ["injection", "cwe-78", "cwe-77", "cwe-94", "script", "github actions", "untrusted input", "expression injection", "workflow injection", "command injection"],
    },
    {
        "id": 20, "language": "GitHub Actions YAML",
        "code": "- uses: actions/checkout@main  # unpinned version",
        "expected_vuln": "Supply Chain Attack (unpinned action)",
        "accepted": ["supply chain", "cwe-829", "unpinned", "unpined", "dependency", "version pinning", "mutable", "tag", "branch reference", "insecure dependency", "checkout", "version"],
    },

    # ── 확장 케이스 (ID 21–40) ────────────────────────────────────────────────────

    # SQL Injection 추가 (3종 언어)
    {
        "id": 21, "language": "Java Spring Boot",
        "code": 'String hql = "FROM User WHERE name=\'" + username + "\'";\nQuery q = session.createQuery(hql);',
        "expected_vuln": "SQL Injection (HQL)",
        "accepted": ["sql injection", "cwe-89", "hql", "query injection", "hibernate", "injection"],
    },
    {
        "id": 22, "language": "Python",
        "code": "import sqlite3\ncursor.execute(f\"SELECT * FROM users WHERE name='{username}'\")",
        "expected_vuln": "SQL Injection",
        "accepted": ["sql injection", "cwe-89", "sqlite", "query injection", "database injection", "injection"],
    },
    {
        "id": 23, "language": "Node.js / Express",
        "code": "connection.query(`SELECT * FROM products WHERE cat='${req.query.cat}'`, cb);",
        "expected_vuln": "SQL Injection",
        "accepted": ["sql injection", "cwe-89", "sql", "query injection", "injection"],
    },

    # Timing Attack 추가 (Python HMAC, Java token)
    {
        "id": 24, "language": "Java Spring Boot",
        "code": "if (userToken.equals(sessionToken)) {\n    authenticate(user);\n}",
        "expected_vuln": "Timing Attack",
        "accepted": ["timing attack", "cwe-208", "timing", "constant-time", "insecure comparison", "cwe-362", "brute force", "comparison", "bcrypt", "equals", "secure comparison"],
    },
    {
        "id": 25, "language": "Python",
        "code": "if user_hmac == expected_hmac:\n    return grant_access()",
        "expected_vuln": "Timing Attack (HMAC comparison)",
        "accepted": ["timing attack", "cwe-208", "hmac", "timing", "constant-time", "compare_digest", "cwe-362", "brute force"],
    },

    # CORS 추가 (credentials 포함, Java)
    {
        "id": 26, "language": "Node.js / Express",
        "code": "app.use(cors({\n  origin: req.headers.origin,\n  credentials: true\n}));",
        "expected_vuln": "Insecure CORS with credentials",
        "accepted": ["cors", "cwe-942", "cwe-346", "cross-origin", "credentials", "permissive", "wildcard", "misconfiguration"],
    },
    {
        "id": 27, "language": "Java Spring Boot",
        "code": '@CrossOrigin(origins = "*", allowCredentials = "true")\n@GetMapping("/api/data")\npublic ResponseEntity<?> getData() {}',
        "expected_vuln": "Insecure CORS",
        "accepted": ["cors", "cwe-942", "cwe-346", "cross-origin", "crossorigin", "wildcard", "credentials", "permissive"],
    },

    # Hardcoded Secret 추가 (API Key, DB Password)
    {
        "id": 28, "language": "Node.js / Express",
        "code": "const apiKey = 'sk-prod-1a2b3c4d5e6f7890';\nconst client = new OpenAI({ apiKey });",
        "expected_vuln": "Hardcoded API Key",
        "accepted": ["hardcoded", "cwe-798", "cwe-259", "hard-coded", "secret", "credential", "api key"],
    },
    {
        "id": 29, "language": "Java Spring Boot",
        "code": 'private static final String DB_PASS = "admin123";\nconn = DriverManager.getConnection(url, "root", DB_PASS);',
        "expected_vuln": "Hardcoded Credentials",
        "accepted": ["hardcoded", "cwe-798", "cwe-259", "hard-coded", "password", "credential", "database"],
    },

    # C 추가 (Integer Overflow, Use-After-Free)
    {
        "id": 30, "language": "C",
        "code": "int len = atoi(argv[1]);\nchar *buf = malloc(len * sizeof(char));\nmemcpy(buf, src, len);",
        "expected_vuln": "Integer Overflow",
        "accepted": ["integer overflow", "cwe-190", "cwe-680", "overflow", "integer", "malloc", "unsigned", "wrap", "memory"],
    },
    {
        "id": 31, "language": "C",
        "code": "char *ptr = malloc(sizeof(Data));\nfree(ptr);\n/* ... */\nptr->value = 42;  // use after free",
        "expected_vuln": "Use-After-Free",
        "accepted": ["use after free", "use-after-free", "cwe-416", "dangling pointer", "memory", "uaf", "free", "heap"],
    },

    # GitHub Actions 추가 (Secret 노출, 과도한 권한)
    {
        "id": 32, "language": "GitHub Actions YAML",
        "code": '- name: Debug\n  run: echo "Token=${{ secrets.API_TOKEN }}"',
        "expected_vuln": "Secret Exposure in Logs",
        "accepted": ["secret", "cwe-532", "cwe-312", "exposure", "log", "leak", "token", "sensitive", "disclosure"],
    },
    {
        "id": 33, "language": "GitHub Actions YAML",
        "code": "permissions:\n  actions: write\n  contents: write\n  id-token: write\n  packages: write",
        "expected_vuln": "Overly Permissive GitHub Actions Permissions",
        "accepted": ["permission", "cwe-250", "cwe-269", "least privilege", "overly permissive", "write", "excessive", "privilege"],
    },

    # Path Traversal (Python, Node.js)
    {
        "id": 34, "language": "Python",
        "code": "filename = request.args.get('file')\nwith open('/var/data/' + filename) as f:\n    return f.read()",
        "expected_vuln": "Path Traversal",
        "accepted": ["path traversal", "cwe-22", "directory traversal", "path", "traversal", "../", "file inclusion"],
    },
    {
        "id": 35, "language": "Node.js / Express",
        "code": "app.get('/file', (req, res) => {\n  const f = req.query.name;\n  res.sendFile(path.join('/uploads/', f));\n});",
        "expected_vuln": "Path Traversal",
        "accepted": ["path traversal", "cwe-22", "directory traversal", "path", "traversal", "../", "sendfile"],
    },

    # XXE Injection (Java)
    {
        "id": 36, "language": "Java Spring Boot",
        "code": "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\nDocumentBuilder db = dbf.newDocumentBuilder();\nDocument doc = db.parse(userXmlInput);",
        "expected_vuln": "XXE Injection",
        "accepted": ["xxe", "cwe-611", "xml external entity", "xml", "entity", "injection", "xxe injection", "external entity"],
    },

    # SSRF (Python)
    {
        "id": 37, "language": "Python",
        "code": "import requests\nurl = request.args.get('url')\nresponse = requests.get(url)\nreturn response.text",
        "expected_vuln": "Server-Side Request Forgery (SSRF)",
        "accepted": ["ssrf", "cwe-918", "server-side request forgery", "request forgery", "internal", "url", "fetch"],
    },

    # ReDoS (Node.js)
    {
        "id": 38, "language": "Node.js / Express",
        "code": "const pattern = new RegExp(req.query.search);\nconst matches = largeInput.match(pattern);",
        "expected_vuln": "Regular Expression DoS (ReDoS)",
        "accepted": ["redos", "cwe-1333", "regex", "regular expression", "denial of service", "dos", "catastrophic backtracking", "redos"],
    },

    # Open Redirect (React)
    {
        "id": 39, "language": "React / Next.js",
        "code": "const next = searchParams.get('next');\nrouter.push(next);",
        "expected_vuln": "Open Redirect",
        "accepted": ["open redirect", "cwe-601", "redirect", "url", "phishing", "unvalidated redirect", "cwe-20"],
    },

    # Java Deserialization
    {
        "id": 40, "language": "Java Spring Boot",
        "code": "ObjectInputStream ois = new ObjectInputStream(request.getInputStream());\nObject obj = ois.readObject();",
        "expected_vuln": "Insecure Deserialization",
        "accepted": ["deserialization", "cwe-502", "objectinputstream", "readobject", "arbitrary code", "remote code execution", "java deserialization"],
    },
]

# 프롬프트 — 모든 어댑터가 이 형식으로 응답을 유도해야 함
PROMPT_TMPL = """\
You are a security code reviewer.
Analyze this {language} code for security vulnerabilities.

Code:
{code}

Respond in this exact format:
VULNERABILITY: [vulnerability name with CWE ID if known]
SEVERITY: [CRITICAL/HIGH/MEDIUM/LOW]
CVSS: [CVSS base score, e.g. 9.8]
ATTACK: [attack scenario in one sentence]
FIX: [fixed code only, no explanation]\
"""

# ── 파서 ───────────────────────────────────────────────────────────────────────

def parse_response(text: str) -> dict:
    """LLM 응답에서 구조화된 필드를 추출한다."""
    # 1. 모델이 출력하는 garbage 패턴 제거
    # "VULNERABILITY_FIXED is a comment..." 형태의 preamble 제거
    text = re.sub(r"VULNERABILITY_FIXED\s+is\s+[^\n]*\n*", "", text, flags=re.IGNORECASE)
    # "VULNERABILITY_FIXED:" 이후 코드 블록(postamble) 제거
    m_post = re.search(r"\nVULNERABILITY_FIXED\s*:", text, re.IGNORECASE)
    if m_post:
        text = text[:m_post.start()]

    # 2. 키 별칭 정의 — 모델이 사용하는 변형(ATTACK_IDR, FIXED 등) 포함
    KEY_ALIASES = {
        "VULNERABILITY": r"(?:vulnerability|vuln)",
        "SEVERITY":      r"severity",
        "CVSS":          r"cvss(?:[_\s](?:base[_\s])?score)?",
        "ATTACK":        r"attack(?:_idr)?",
        "FIX":           r"fix(?:ed)?",
    }
    fields = {}
    for canonical, pattern in KEY_ALIASES.items():
        if canonical == "FIX":
            continue  # FIX는 아래에서 멀티라인으로 별도 처리

        # 시도 1: KEY: value (같은 줄) — 줄 앞 공백 허용
        m = re.search(
            rf"^[ \t]*\*{{0,2}}{pattern}\*{{0,2}}:[ \t]*(.+)",
            text, re.MULTILINE | re.IGNORECASE,
        )
        value = m.group(1).strip().strip("*").strip() if m else ""

        if not value:
            # 시도 2: KEY:\nvalue (다음 줄에 내용) — 빈 줄 1개까지 허용
            m2 = re.search(
                rf"^[ \t]*\*{{0,2}}{pattern}\*{{0,2}}:[ \t]*\n[ \t]*([^\n]+)",
                text, re.MULTILINE | re.IGNORECASE,
            )
            value = m2.group(1).strip().strip("*").strip() if m2 else "—"

        fields[canonical] = value or "—"

    # 3. FIX: 멀티라인 캡처 (FIXED: 변형 포함, 줄 앞 공백 허용)
    m_fix = re.search(
        r"^[ \t]*\*{0,2}fix(?:ed)?\*{0,2}:[ \t]*([\s\S]+)",
        text, re.MULTILINE | re.IGNORECASE,
    )
    if m_fix:
        fix_raw = m_fix.group(1).strip()
        # 다음 VULNERABILITY: 블록이나 --- 구분자에서 자르기
        cut = re.search(r"\n(?:---+\n|[ \t]*VULNERABILITY\s*:)", fix_raw, re.IGNORECASE)
        if cut:
            fix_raw = fix_raw[:cut.start()].strip()
        raw = re.sub(r"^```[^\n]*\n", "", fix_raw).rstrip("`").strip()
        fields["FIX"] = raw
    else:
        fields["FIX"] = "—"

    for k in ("VULNERABILITY", "SEVERITY", "CVSS", "ATTACK"):
        fields[k] = re.sub(r"\*+", "", fields[k]).strip()

    return fields


def detected(parsed: dict, case) -> bool:
    """
    모델 응답이 기대 취약점을 탐지했는지 판정한다.

    case는 CASES의 dict 또는 하위 호환을 위한 expected_vuln 문자열.
    판정 우선순위:
      1. case["accepted"] 목록의 키워드/CWE ID 매칭 (VULNERABILITY + ATTACK 모두 확인)
      2. expected_vuln 키워드 직접 매칭 (fallback)
    """
    vuln_lower   = parsed.get("VULNERABILITY", "").lower()
    attack_lower = parsed.get("ATTACK", "").lower()
    combined     = vuln_lower + " " + attack_lower

    if isinstance(case, dict):
        expected = case.get("expected_vuln", "")
        accepted = [a.lower() for a in case.get("accepted", [])]
    else:
        expected = case
        accepted = []

    # 1차: accepted 목록 (CWE ID 또는 키워드)
    if accepted and any(a in combined for a in accepted):
        return True

    # 2차: expected_vuln 키워드 직접 매칭 (하위 호환)
    if any(w in vuln_lower for w in expected.lower().split()):
        return True

    return False


# ── 벤치마크 실행 ───────────────────────────────────────────────────────────────

QueryFn = Callable[[str, str], tuple[str, float]]
"""어댑터가 구현해야 하는 함수 시그니처: (language, code) → (response_text, elapsed_sec)"""


def run_benchmark(
    query_fn: QueryFn,
    model_name: str,
    save_json: bool = True,
    verbose: bool = True,
) -> list[dict]:
    """
    공통 20개 케이스를 query_fn으로 실행하고 결과를 반환한다.

    Args:
        query_fn:   어댑터 함수. (language, code) → (response, elapsed) 반환.
        model_name: 리포트에 표시될 모델 이름. 파일명에도 사용.
        save_json:  True면 reports/results_{model_name}.json 저장.
        verbose:    True면 케이스별 진행 상황 출력.

    Returns:
        결과 dict 리스트 (각 케이스에 response, parsed, elapsed, detected 포함)
    """
    REPORTS.mkdir(exist_ok=True)
    results = []
    safe_name = model_name.replace(" ", "_").replace("/", "-")

    if verbose:
        print(f"\n[{model_name}] 벤치마크 시작 — {len(CASES)}개 케이스")
        print("─" * 60)

    for case in CASES:
        if verbose:
            print(f"[{case['id']:02d}/20] [{case['language']}] {case['expected_vuln']}")

        try:
            prompt   = PROMPT_TMPL.format(language=case["language"], code=case["code"])
            response, elapsed = query_fn(case["language"], case["code"])
        except Exception as e:
            if verbose:
                print(f"  오류: {e}\n")
            results.append({**case, "response": "", "parsed": {}, "elapsed": 0.0,
                             "detected": False, "error": str(e)})
            continue

        parsed = parse_response(response)
        ok     = detected(parsed, case)
        results.append({**case, "response": response, "parsed": parsed,
                        "elapsed": elapsed, "detected": ok})

        if verbose:
            tick = "✓" if ok else "✗"
            sev  = parsed.get("SEVERITY", "?")
            print(f"  {tick} {parsed.get('VULNERABILITY','?')[:48]}  [{sev}]  {elapsed}s\n")

    # 요약
    total      = len(results)
    n_detected = sum(1 for r in results if r["detected"])
    valid      = [r for r in results if r["elapsed"] > 0]
    avg_t      = round(sum(r["elapsed"] for r in valid) / len(valid), 2) if valid else 0

    summary = {
        "model_name":  model_name,
        "timestamp":   datetime.now().isoformat(),
        "total":       total,
        "detected":    n_detected,
        "detect_pct":  round(n_detected / total * 100, 1),
        "avg_time":    avg_t,
        "results":     results,
    }

    if save_json:
        out = REPORTS / f"results_{safe_name}.json"
        out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        if verbose:
            print(f"JSON 저장: {out}")

    if verbose:
        print("─" * 60)
        print(f"탐지율: {n_detected}/{total} ({summary['detect_pct']}%)  평균응답: {avg_t}s")

    return summary


# ── HTML 단독 리포트 빌더 ────────────────────────────────────────────────────────

SEVERITY_COLOR = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#16a34a"}
LANG_COLOR = {
    "React / Next.js": "#06b6d4", "Node.js / Express": "#22c55e",
    "Java Spring Boot": "#f97316", "Python": "#a855f7",
    "C": "#64748b", "GitHub Actions YAML": "#ec4899",
}


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_single_html(summary: dict) -> str:
    """단일 모델 결과를 HTML 리포트로 변환한다."""
    model_name = summary["model_name"]
    results    = summary["results"]
    now        = datetime.now().strftime("%Y-%m-%d %H:%M")
    total      = summary["total"]
    n_detected = summary["detected"]
    detect_pct = summary["detect_pct"]
    avg_all    = summary["avg_time"]

    lang_stats: dict[str, list] = {}
    for r in results:
        lang_stats.setdefault(r["language"], []).append(r)

    summary_cards = "".join(
        f"""<div class="stat" style="border-top:4px solid {LANG_COLOR.get(lang,'#94a3b8')};">
          <div class="stat-label">{esc(lang)}</div>
          <div class="stat-value" style="color:{LANG_COLOR.get(lang,'#94a3b8')};">
            {round(sum(r["elapsed"] for r in rows)/len(rows),2)}s</div>
          <div class="stat-sub">평균 · {sum(1 for r in rows if r["detected"])}/{len(rows)} 탐지</div>
        </div>"""
        for lang, rows in lang_stats.items()
    )

    sections = ""
    for lang, rows in lang_stats.items():
        color = LANG_COLOR.get(lang, "#94a3b8")
        cards = ""
        for r in rows:
            sev    = r["parsed"].get("SEVERITY", "").upper()
            sc     = SEVERITY_COLOR.get(sev, "#94a3b8")
            ok     = r["detected"]
            tc     = "#22c55e" if ok else "#ef4444"
            ec     = "#22c55e" if r["elapsed"] < 3 else ("#eab308" if r["elapsed"] < 8 else "#ef4444")
            accepted_hints = ""
            if not ok and r.get("accepted"):
                top_hints = ", ".join(r["accepted"][:6])
                accepted_hints = f'<div class="resp-item full"><span class="resp-label">허용 패턴 (미매칭)</span><span class="resp-value hint">{esc(top_hints)}...</span></div>'
            cards += f"""
            <div class="case-card">
              <div class="case-header">
                <span class="case-num">#{r['id']}</span>
                <span class="expected">예상 취약점: {esc(r['expected_vuln'])}</span>
                <span class="tick" style="color:{tc};">{'✓ 탐지됨' if ok else '✗ 미탐지'}</span>
              </div>
              <div class="code-block"><pre>{esc(r['code'])}</pre></div>
              <div class="response-grid">
                <div class="resp-item"><span class="resp-label">취약점</span>
                  <span class="resp-value">{esc(r['parsed'].get('VULNERABILITY','—'))}</span></div>
                <div class="resp-item"><span class="resp-label">심각도</span>
                  <span class="sev-badge" style="background:{sc};">{sev or '—'}</span></div>
                <div class="resp-item full"><span class="resp-label">공격 시나리오</span>
                  <span class="resp-value">{esc(r['parsed'].get('ATTACK','—'))}</span></div>
                <div class="resp-item full"><span class="resp-label">수정 코드</span>
                  <pre class="fix-block">{esc(r['parsed'].get('FIX','—'))}</pre></div>
                <div class="resp-item"><span class="resp-label">응답시간</span>
                  <span class="resp-value" style="color:{ec};font-weight:700;">{r['elapsed']}s</span></div>
                {accepted_hints}
              </div>
            </div>"""
        sections += f'<section><div class="lang-header" style="background:{color};">{esc(lang)}</div>{cards}</section>'

    chart_labels = json.dumps(list(lang_stats.keys()))
    chart_times  = json.dumps([round(sum(r["elapsed"] for r in v)/len(v),2) for v in lang_stats.values()])
    chart_det    = json.dumps([round(sum(1 for r in v if r["detected"])/len(v)*100,1) for v in lang_stats.values()])
    chart_colors = json.dumps([LANG_COLOR.get(l,"#94a3b8") for l in lang_stats])

    return f"""<!DOCTYPE html><html lang="ko"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(model_name)} 벤치마크 — ScanOps</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#f0f4f8;color:#1e293b;padding:24px}}
h1{{font-size:1.6rem;font-weight:700;margin-bottom:4px}}
.sub{{color:#64748b;font-size:.88rem;margin-bottom:24px}}
code{{font-family:monospace;font-size:.85em;background:#f1f5f9;padding:1px 5px;border-radius:4px}}
.top-stats{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}}
.hero{{background:#1e293b;color:#fff;border-radius:12px;padding:18px 28px;flex:1;min-width:140px}}
.hero-label{{font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;opacity:.6}}
.hero-value{{font-size:2rem;font-weight:800;margin-top:2px}}
.lang-stats{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:28px}}
.stat{{background:#fff;border-radius:12px;padding:14px 18px;flex:1;min-width:130px;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
.stat-label{{font-size:.72rem;font-weight:600;color:#64748b;margin-bottom:4px}}
.stat-value{{font-size:1.5rem;font-weight:800}}
.stat-sub{{font-size:.72rem;color:#94a3b8;margin-top:2px}}
.charts{{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:28px}}
.chart-box{{background:#fff;border-radius:12px;padding:20px;flex:1;min-width:260px;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
.chart-box h2{{font-size:.9rem;font-weight:600;color:#334155;margin-bottom:14px}}
canvas{{max-height:200px}}
.lang-header{{color:#fff;font-weight:700;font-size:.9rem;padding:10px 18px;border-radius:10px 10px 0 0}}
section{{margin-bottom:28px}}
.case-card{{background:#fff;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.07)}}
.case-card+.case-card{{margin-top:1px}}
section .case-card:last-child{{border-radius:0 0 10px 10px}}
.case-header{{display:flex;align-items:center;gap:10px;padding:10px 16px;background:#f8fafc;border-bottom:1px solid #e2e8f0;flex-wrap:wrap}}
.case-num{{font-weight:800;font-size:.8rem;color:#64748b}}
.expected{{font-size:.78rem;color:#475569;flex:1}}
.tick{{font-size:.78rem;font-weight:700}}
.code-block{{background:#0f172a;padding:12px 16px}}
.code-block pre{{color:#e2e8f0;font-family:monospace;font-size:.8rem;line-height:1.6;white-space:pre-wrap;word-break:break-word}}
.response-grid{{display:grid;grid-template-columns:1fr 1fr}}
.resp-item{{padding:10px 16px;border-right:1px solid #f1f5f9;border-bottom:1px solid #f1f5f9}}
.resp-item.full{{grid-column:1/-1;border-right:none}}
.resp-label{{display:block;font-size:.67rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#94a3b8;margin-bottom:3px}}
.resp-value{{font-size:.83rem;color:#334155;line-height:1.5}}
.sev-badge{{display:inline-block;color:#fff;font-size:.75rem;font-weight:700;padding:2px 10px;border-radius:999px}}
.fix-block{{font-family:monospace;font-size:.78rem;color:#1e293b;background:#f0fdf4;padding:8px 10px;border-radius:6px;white-space:pre-wrap;word-break:break-word;line-height:1.6}}
.hint{{font-size:.78rem;color:#94a3b8;font-style:italic}}
</style></head><body>
<h1>{esc(model_name)} — 보안 코드 벤치마크</h1>
<p class="sub">ScanOps · {now} · 총 {total}개 케이스</p>
<div class="top-stats">
  <div class="hero"><div class="hero-label">총 케이스</div><div class="hero-value">{total}</div></div>
  <div class="hero" style="background:#166534;"><div class="hero-label">탐지</div><div class="hero-value">{n_detected}<span style="font-size:1rem;opacity:.8;"> / {total}</span></div></div>
  <div class="hero" style="background:#1d4ed8;"><div class="hero-label">탐지율</div><div class="hero-value">{detect_pct}%</div></div>
  <div class="hero" style="background:#7c3aed;"><div class="hero-label">평균 응답시간</div><div class="hero-value">{avg_all}s</div></div>
</div>
<div class="lang-stats">{summary_cards}</div>
<div class="charts">
  <div class="chart-box"><h2>언어별 평균 응답시간 (초)</h2><canvas id="ct"></canvas></div>
  <div class="chart-box"><h2>언어별 탐지율 (%)</h2><canvas id="cd"></canvas></div>
</div>
{sections}
<script>
const L={chart_labels},T={chart_times},D={chart_det},C={chart_colors};
new Chart(document.getElementById('ct'),{{type:'bar',data:{{labels:L,datasets:[{{label:'평균(초)',data:T,backgroundColor:C,borderRadius:5,borderSkipped:false}}]}},options:{{responsive:true,plugins:{{legend:{{display:false}}}},scales:{{y:{{beginAtZero:true}},x:{{grid:{{display:false}}}}}}}}}});
new Chart(document.getElementById('cd'),{{type:'bar',data:{{labels:L,datasets:[{{label:'탐지율%',data:D,backgroundColor:C,borderRadius:5,borderSkipped:false}}]}},options:{{responsive:true,plugins:{{legend:{{display:false}}}},scales:{{y:{{beginAtZero:true,max:100}},x:{{grid:{{display:false}}}}}}}}}});
</script>
</body></html>"""


def save_html(summary: dict) -> Path:
    """단일 모델 HTML 리포트를 저장하고 경로를 반환한다."""
    REPORTS.mkdir(exist_ok=True)
    safe_name = summary["model_name"].replace(" ", "_").replace("/", "-")
    out = REPORTS / f"benchmark_{safe_name}.html"
    out.write_text(build_single_html(summary), encoding="utf-8")
    return out
