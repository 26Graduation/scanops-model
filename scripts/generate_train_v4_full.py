"""
ScanOps v4 학습 데이터 생성기
================================
목표 : 700+ 새 샘플 생성 → 기존 367개와 합산 1,070개+
커버 : CWE Top-25 (2023) 전수 + 추가 고위험 CWE
형식 : VULNERABILITY / SEVERITY / CVSS / ATTACK / FIX
출력 : data/lora_train_v4_gen.jsonl
병합 : data/lora_train_v4_combined.jsonl  (기존 + 신규, 중복 제거)

실행:
  python scripts/generate_train_v4_full.py
"""

from __future__ import annotations
import json
import random
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

# ── 변수 치환 풀 ──────────────────────────────────────────────────────────────
_USER_VARS   = ["userInput", "req.body.data", "req.params.id", "req.query.q",
                "req.query.search", "req.body.name", "req.body.comment",
                "req.body.title", "params.get('input')", "formData.get('value')"]
_TABLE_NAMES = ["users", "products", "orders", "sessions", "payments",
                "accounts", "items", "records", "logs"]
_COL_NAMES   = ["id", "username", "email", "userId", "productId",
                "name", "status", "token", "role"]
_PATH_VARS   = ["filename", "filepath", "path", "name", "file",
                "document", "resource", "target"]
_CMD_VARS    = ["command", "cmd", "input", "query", "param",
                "host", "target", "arg"]
_SECRET_VALS = ["hardcoded_secret_key", "my_secret_123", "super_secret",
                "abc123!@#", "password123", "admin_pass", "prod_key_xyz"]
_SECRET_VARS = ["SECRET_KEY", "API_KEY", "DB_PASSWORD", "JWT_SECRET",
                "AUTH_TOKEN", "ACCESS_KEY", "PRIVATE_KEY"]


def _pick(lst: list, seed: int) -> str:
    return lst[seed % len(lst)]


def _make_completion(vuln: str, severity: str, cvss: float,
                     attack: str, fix: str) -> str:
    return (
        f"VULNERABILITY: {vuln}\n"
        f"SEVERITY: {severity}\n"
        f"CVSS: {cvss}\n"
        f"ATTACK: {attack}\n"
        f"FIX:\n{fix}"
    )


def _make_sample(language: str, code: str, vuln: str, severity: str,
                 cvss: float, attack: str, fix: str) -> dict:
    prompt = (
        f"Analyze this {language} code for security vulnerabilities:\n\n{code}"
    )
    completion = _make_completion(vuln, severity, cvss, attack, fix)
    return {"prompt": prompt, "completion": completion}


# ══════════════════════════════════════════════════════════════════════════════
# CWE-79  Cross-Site Scripting (XSS)
# ══════════════════════════════════════════════════════════════════════════════
def _xss_samples() -> list[dict]:
    out = []
    # Node.js raw html concat
    for i, v in enumerate(_USER_VARS[:8]):
        code = f"res.send('<div>' + {v} + '</div>');"
        fix  = f"const safe = he.encode({v});\nres.send('<div>' + safe + '</div>');"
        out.append(_make_sample(
            "Node.js / Express", code,
            "CWE-79 Cross-Site Scripting (XSS)", "HIGH", 7.2,
            f"공격자가 {v}에 <script>태그를 삽입해 세션 쿠키를 탈취합니다.",
            fix,
        ))
    # Node.js template literal in response
    for i, v in enumerate(_USER_VARS[:6]):
        code = f"res.send(`<h1>Hello ${{ {v} }}</h1>`);"
        fix  = f"res.send(`<h1>Hello ${{he.encode({v})}}</h1>`);"
        out.append(_make_sample(
            "Node.js / Express", code,
            "CWE-79 Reflected Cross-Site Scripting", "HIGH", 7.2,
            f"{v} 값이 HTML 응답에 직접 삽입돼 XSS 공격이 가능합니다.",
            fix,
        ))
    # React dangerouslySetInnerHTML
    for i, v in enumerate(["content", "html", "markup", "body", "description", "post"]):
        code = f"return <div dangerouslySetInnerHTML={{{{__html: {v}}}}} />;"
        fix  = f"import DOMPurify from 'dompurify';\nreturn <div dangerouslySetInnerHTML={{{{__html: DOMPurify.sanitize({v})}}}} />;"
        out.append(_make_sample(
            "React / Next.js", code,
            "CWE-79 DOM-based Cross-Site Scripting", "HIGH", 7.2,
            f"dangerouslySetInnerHTML로 삽입된 {v}에 악성 HTML이 포함되면 XSS가 실행됩니다.",
            fix,
        ))
    # PHP echo
    for i, v in enumerate(["$_GET['q']", "$_POST['name']", "$_REQUEST['data']", "$_GET['id']"]):
        code = f"echo '<p>' . {v} . '</p>';"
        fix  = f"echo '<p>' . htmlspecialchars({v}, ENT_QUOTES, 'UTF-8') . '</p>';"
        out.append(_make_sample(
            "PHP", code,
            "CWE-79 Reflected XSS", "HIGH", 7.2,
            f"사용자 입력 {v}가 이스케이프 없이 출력돼 스크립트 삽입이 가능합니다.",
            fix,
        ))
    # Java JSP
    for i, v in enumerate(["request.getParameter(\"name\")",
                            "request.getParameter(\"search\")",
                            "request.getParameter(\"q\")"]):
        code = f"out.println(\"<b>\" + {v} + \"</b>\");"
        fix  = f"import org.apache.commons.text.StringEscapeUtils;\nout.println(\"<b>\" + StringEscapeUtils.escapeHtml4({v}) + \"</b>\");"
        out.append(_make_sample(
            "Java Spring Boot", code,
            "CWE-79 Reflected XSS in JSP", "HIGH", 7.2,
            f"{v} 입력값이 HTML 인코딩 없이 출력돼 스크립트 실행이 가능합니다.",
            fix,
        ))
    # Django template
    for i, v in enumerate(["user_input", "query", "search_term"]):
        code = f"return HttpResponse(f'<p>Result: {{{v}}}</p>')"
        fix  = f"from django.utils.html import escape\nreturn HttpResponse(f'<p>Result: {{escape({v})}}</p>')"
        out.append(_make_sample(
            "Python", code,
            "CWE-79 Reflected XSS in Django Response", "HIGH", 7.2,
            f"HttpResponse에 {v}가 직접 삽입돼 사용자 브라우저에서 임의 스크립트가 실행됩니다.",
            fix,
        ))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CWE-89  SQL Injection
# ══════════════════════════════════════════════════════════════════════════════
def _sqli_samples() -> list[dict]:
    out = []
    langs = [
        ("Node.js / Express", "db.query", "?", "parameterized"),
        ("Python",            "cursor.execute", "%s", "parameterized"),
        ("Java Spring Boot",  "stmt.executeQuery", "?", "PreparedStatement"),
        ("PHP",               "mysqli_query($conn,", "'?'", "prepared statement"),
        ("Ruby",              "ActiveRecord::Base.connection.execute", "?", "ActiveRecord"),
        ("Go",                "db.Query",           "?", "parameterized"),
    ]
    tables = _TABLE_NAMES[:6]
    cols   = _COL_NAMES[:6]
    for t in tables:
        for c in cols[:4]:
            for lang, fn, ph, fix_label in langs[:4]:
                inp = "req.params.id" if "Node" in lang else (
                      "user_id" if "Python" in lang else (
                      "request.getParameter(\"id\")" if "Java" in lang else "$_GET['id']"))
                code = f'db.query("SELECT * FROM {t} WHERE {c}=" + {inp});'
                fix  = f'db.query("SELECT * FROM {t} WHERE {c}={ph}", [{inp}]);'
                out.append(_make_sample(
                    lang, code,
                    "CWE-89 SQL Injection", "CRITICAL", 9.8,
                    f"공격자가 {inp}에 ' OR 1=1--를 주입해 {t} 테이블 전체를 열람합니다.",
                    fix,
                ))
                if len(out) % 3 == 0 and len(out) > 10:
                    # UNION 기반 변형
                    code2 = f'db.query(`SELECT {c} FROM {t} WHERE id=\'${{{inp}}}\'`);'
                    fix2  = f'db.query("SELECT {c} FROM {t} WHERE id=?", [{inp}]);'
                    out.append(_make_sample(
                        lang, code2,
                        "CWE-89 SQL Injection (UNION-based)", "CRITICAL", 9.8,
                        f"UNION SELECT 주입으로 {t} 외 다른 테이블 데이터도 추출됩니다.",
                        fix2,
                    ))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CWE-78  OS Command Injection
# ══════════════════════════════════════════════════════════════════════════════
def _cmdi_samples() -> list[dict]:
    out = []
    # Python
    for v in _CMD_VARS[:6]:
        code = f"import os\nos.system(f'ping {{{v}}}')"
        fix  = f"import subprocess\nsubprocess.run(['ping', {v}], check=True, timeout=5)"
        out.append(_make_sample("Python", code,
            "CWE-78 OS Command Injection", "CRITICAL", 9.8,
            f"공격자가 {v}에 ; rm -rf /를 삽입해 서버의 임의 명령을 실행합니다.", fix))
    for v in _CMD_VARS[:5]:
        code = f"import subprocess\nsubprocess.call({v}, shell=True)"
        fix  = f"import subprocess\nsubprocess.call([{v}], shell=False)"
        out.append(_make_sample("Python", code,
            "CWE-78 OS Command Injection via shell=True", "CRITICAL", 9.8,
            f"shell=True 옵션으로 {v}의 셸 메타문자가 그대로 실행됩니다.", fix))
    # Node.js
    for v in ["req.body.command", "req.query.cmd", "req.params.host",
              "req.body.file", "req.query.arg"]:
        code = f"const {{ exec }} = require('child_process');\nexec({v});"
        fix  = f"const {{ execFile }} = require('child_process');\nexecFile('/usr/bin/safe_cmd', [{v}]);"
        out.append(_make_sample("Node.js / Express", code,
            "CWE-78 OS Command Injection", "CRITICAL", 9.8,
            f"exec()에 {v}가 직접 전달돼 임의 셸 명령이 실행됩니다.", fix))
    # Java
    for v in ["userInput", "request.getParameter(\"cmd\")",
              "request.getParameter(\"host\")", "params"]:
        code = f"Runtime.getRuntime().exec({v});"
        fix  = f"ProcessBuilder pb = new ProcessBuilder(List.of(\"/usr/bin/safe\", {v}));\npb.start();"
        out.append(_make_sample("Java Spring Boot", code,
            "CWE-78 OS Command Injection via Runtime.exec", "CRITICAL", 9.8,
            f"Runtime.exec()에 {v}가 전달돼 서버에서 임의 명령이 실행됩니다.", fix))
    # PHP
    for v in ["$_GET['cmd']", "$_POST['input']", "$_REQUEST['host']"]:
        code = f"system({v});"
        fix  = f"$safe = escapeshellarg({v});\nsystem('safe_command ' . $safe);"
        out.append(_make_sample("PHP", code,
            "CWE-78 OS Command Injection", "CRITICAL", 9.8,
            f"PHP system()에 {v}가 전달돼 셸 명령 삽입이 가능합니다.", fix))
    # Go
    for v in ["r.URL.Query().Get(\"cmd\")", "r.FormValue(\"input\")"]:
        code = f'exec.Command("sh", "-c", {v}).Run()'
        fix  = f'exec.Command("/usr/bin/safe", {v}).Run()'
        out.append(_make_sample("Go", code,
            "CWE-78 OS Command Injection", "CRITICAL", 9.8,
            f"sh -c에 {v}가 전달돼 임의 셸 명령이 실행됩니다.", fix))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CWE-22  Path Traversal
# ══════════════════════════════════════════════════════════════════════════════
def _path_traversal_samples() -> list[dict]:
    out = []
    # Python
    for v in _PATH_VARS[:6]:
        code = (f"{v} = request.args.get('file')\n"
                f"with open('/var/data/' + {v}) as f:\n    return f.read()")
        fix  = (f"import os\n{v} = os.path.basename(request.args.get('file', ''))\n"
                f"safe_path = os.path.join('/var/data/', {v})\n"
                f"if not safe_path.startswith('/var/data/'):\n    abort(400)\n"
                f"with open(safe_path) as f:\n    return f.read()")
        out.append(_make_sample("Python", code,
            "CWE-22 Path Traversal", "HIGH", 7.5,
            f"공격자가 {v}에 ../../etc/passwd를 전달해 민감한 파일을 읽습니다.", fix))
    # Node.js
    for v in ["req.query.file", "req.query.name", "req.params.path", "req.body.filename"]:
        code = f"const f = {v};\nres.sendFile(path.join('/uploads/', f));"
        fix  = (f"const f = path.basename({v});\n"
                f"const safe = path.join('/uploads/', f);\n"
                f"if (!safe.startsWith('/uploads/')) return res.sendStatus(400);\n"
                f"res.sendFile(safe);")
        out.append(_make_sample("Node.js / Express", code,
            "CWE-22 Path Traversal", "HIGH", 7.5,
            f"path.join만으로는 {v}에 포함된 ../를 막지 못해 디렉터리 이탈이 발생합니다.", fix))
    # Java
    for v in ["request.getParameter(\"file\")", "request.getParameter(\"doc\")"]:
        code = (f"String fname = {v};\n"
                f"File f = new File(\"/data/\" + fname);\n"
                f"FileInputStream fis = new FileInputStream(f);")
        fix  = (f"String fname = Paths.get({v}).getFileName().toString();\n"
                f"Path safe = Paths.get(\"/data/\").resolve(fname).normalize();\n"
                f"if (!safe.startsWith(\"/data/\")) throw new SecurityException();\n"
                f"FileInputStream fis = new FileInputStream(safe.toFile());")
        out.append(_make_sample("Java Spring Boot", code,
            "CWE-22 Path Traversal", "HIGH", 7.5,
            f"{v}에 ../를 포함시켜 /data/ 외부 파일에 접근할 수 있습니다.", fix))
    # PHP
    for v in ["$_GET['page']", "$_POST['file']"]:
        code = f"include('/var/www/pages/' . {v});"
        fix  = (f"$page = basename({v});\n"
                f"$allowed = ['home', 'about', 'contact'];\n"
                f"if (!in_array($page, $allowed)) die('Invalid page');\n"
                f"include('/var/www/pages/' . $page);")
        out.append(_make_sample("PHP", code,
            "CWE-22 Path Traversal / LFI", "HIGH", 7.5,
            f"include()에 {v}가 그대로 전달돼 로컬 파일 포함 공격이 가능합니다.", fix))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CWE-502  Deserialization of Untrusted Data
# ══════════════════════════════════════════════════════════════════════════════
def _deser_samples() -> list[dict]:
    out = []
    # Python pickle
    for v in ["user_data", "req.body", "cookie_data", "payload", "data"]:
        code = f"import pickle\nobj = pickle.loads({v})"
        fix  = f"import json\nobj = json.loads({v})  # pickle 대신 JSON 사용"
        out.append(_make_sample("Python", code,
            "CWE-502 Deserialization of Untrusted Data", "CRITICAL", 9.8,
            f"pickle.loads()로 신뢰할 수 없는 {v}를 역직렬화해 임의 코드가 실행됩니다.", fix))
    # Python yaml.load
    for v in ["user_input", "config_data", "body", "stream"]:
        code = f"import yaml\ndata = yaml.load({v})"
        fix  = f"import yaml\ndata = yaml.safe_load({v})"
        out.append(_make_sample("Python", code,
            "CWE-502 Unsafe YAML Deserialization", "CRITICAL", 9.8,
            f"yaml.load()는 임의 Python 객체를 생성할 수 있어 {v}를 통해 RCE가 가능합니다.", fix))
    # Java ObjectInputStream
    for v in ["request.getInputStream()", "socket.getInputStream()", "fileInput"]:
        code = f"ObjectInputStream ois = new ObjectInputStream({v});\nObject obj = ois.readObject();"
        fix  = ("// 신뢰할 수 있는 클래스만 허용하는 ObjectInputFilter 적용\n"
                "ObjectInputStream ois = new ObjectInputStream(inputStream);\n"
                "ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter(\n"
                "    \"com.example.SafeClass;!*\"));\n"
                "Object obj = ois.readObject();")
        out.append(_make_sample("Java Spring Boot", code,
            "CWE-502 Java Deserialization (ObjectInputStream)", "CRITICAL", 9.8,
            f"ObjectInputStream.readObject()이 {v}를 역직렬화해 가젯 체인을 통한 RCE가 가능합니다.",
            fix))
    # PHP unserialize
    for v in ["$_COOKIE['data']", "$_POST['payload']", "$_GET['obj']"]:
        code = f"$obj = unserialize({v});"
        fix  = f"$obj = json_decode({v});"
        out.append(_make_sample("PHP", code,
            "CWE-502 PHP Object Injection via unserialize", "CRITICAL", 9.8,
            f"PHP unserialize()로 {v}를 역직렬화해 매직 메서드를 통한 코드 실행이 가능합니다.", fix))
    # Node.js node-serialize
    for v in ["req.body.data", "req.query.obj"]:
        code = f"const serialize = require('node-serialize');\nserialize.unserialize({v});"
        fix  = f"// node-serialize 사용 금지 — JSON.parse()로 대체\nconst obj = JSON.parse({v});"
        out.append(_make_sample("Node.js / Express", code,
            "CWE-502 Node.js Unsafe Deserialization", "CRITICAL", 9.8,
            f"node-serialize는 IIFE 패턴을 허용해 {v}에서 임의 코드 실행이 가능합니다.", fix))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CWE-798  Hard-coded Credentials
# ══════════════════════════════════════════════════════════════════════════════
def _hardcoded_samples() -> list[dict]:
    out = []
    # JWT secret
    for s in _SECRET_VALS[:6]:
        code = f"jwt.verify(token, '{s}');"
        fix  = "jwt.verify(token, process.env.JWT_SECRET);"
        out.append(_make_sample("Node.js / Express", code,
            "CWE-798 Hard-coded JWT Secret", "HIGH", 7.5,
            f"소스코드에 JWT 서명 키 '{s}'가 노출돼 토큰 위조가 가능합니다.", fix))
    # API Key in code
    for var in _SECRET_VARS[:5]:
        val = _pick(_SECRET_VALS, hash(var))
        code = f"const {var} = '{val}';\nconst client = new APIClient({{ {var} }});"
        fix  = f"const {var} = process.env.{var};\nconst client = new APIClient({{ {var} }});"
        out.append(_make_sample("Node.js / Express", code,
            "CWE-798 Hard-coded API Key", "HIGH", 7.5,
            f"API 키 '{val}'이 소스코드에 하드코딩돼 코드 유출 시 즉시 악용됩니다.", fix))
    # Python hardcoded DB password
    for v in ["password", "db_pass", "secret", "key"]:
        code = f"{v} = 'admin123'\nengine = create_engine(f'postgresql://admin:{{{v}}}@db/prod')"
        fix  = (f"import os\n{v} = os.environ['{v.upper()}']\n"
                f"engine = create_engine(f'postgresql://admin:{{{v}}}@db/prod')")
        out.append(_make_sample("Python", code,
            "CWE-798 Hard-coded Database Credential", "HIGH", 7.5,
            f"소스코드에 DB 비밀번호 '{v}'가 노출돼 버전 관리 이력에 영구 기록됩니다.", fix))
    # Java static final
    for v in _SECRET_VARS[:4]:
        val = _pick(_SECRET_VALS, hash(v))
        code = f'private static final String {v} = "{val}";\nconn = DriverManager.getConnection(url, "root", {v});'
        fix  = (f'private static final String {v} = System.getenv("{v}");\n'
                f'conn = DriverManager.getConnection(url, "root", {v});')
        out.append(_make_sample("Java Spring Boot", code,
            "CWE-798 Hard-coded Credentials in Java", "HIGH", 7.5,
            f"static final 상수 {v}에 자격증명이 하드코딩돼 바이너리 역공학으로 추출됩니다.", fix))
    # GitHub Actions
    code = "env:\n  API_TOKEN: 'sk-prod-abc123xyz'\nrun: curl -H \"Authorization: $API_TOKEN\" https://api.example.com"
    fix  = "env:\n  API_TOKEN: ${{ secrets.API_TOKEN }}\nrun: curl -H \"Authorization: $API_TOKEN\" https://api.example.com"
    out.append(_make_sample("GitHub Actions YAML", code,
        "CWE-798 Hard-coded Secret in GitHub Actions", "HIGH", 7.5,
        "워크플로우 파일에 API 토큰이 평문 하드코딩돼 레포 접근 권한이 있는 누구나 확인 가능합니다.",
        fix))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CWE-918  Server-Side Request Forgery (SSRF)
# ══════════════════════════════════════════════════════════════════════════════
def _ssrf_samples() -> list[dict]:
    out = []
    # Python
    for v in ["url", "target_url", "endpoint", "webhook", "callback"]:
        code = f"import requests\n{v} = request.args.get('{v}')\nresponse = requests.get({v})\nreturn response.text"
        fix  = (f"from urllib.parse import urlparse\n"
                f"{v} = request.args.get('{v}')\n"
                f"p = urlparse({v})\n"
                f"if p.hostname not in ALLOWED_HOSTS:\n    abort(400)\n"
                f"response = requests.get({v})\nreturn response.text")
        out.append(_make_sample("Python", code,
            "CWE-918 Server-Side Request Forgery (SSRF)", "HIGH", 8.6,
            f"공격자가 {v}에 http://169.254.169.254를 전달해 클라우드 메타데이터를 탈취합니다.", fix))
    # Node.js
    for v in ["req.query.url", "req.body.endpoint", "req.params.src"]:
        code = f"const axios = require('axios');\nconst data = await axios.get({v});"
        fix  = (f"const url = new URL({v});\n"
                f"if (!ALLOWED_DOMAINS.includes(url.hostname)) throw new Error('SSRF blocked');\n"
                f"const data = await axios.get({v});")
        out.append(_make_sample("Node.js / Express", code,
            "CWE-918 SSRF via axios", "HIGH", 8.6,
            f"{v}가 검증 없이 외부 요청에 사용돼 내부 서비스 접근이 가능합니다.", fix))
    # Java
    for v in ["request.getParameter(\"url\")", "request.getParameter(\"target\")"]:
        code = f"URL url = new URL({v});\nHttpURLConnection conn = (HttpURLConnection) url.openConnection();"
        fix  = (f"// 허용 도메인 화이트리스트 검증 후 요청\n"
                f"String target = {v};\n"
                f"if (!target.matches(\"https://[a-z]+\\.allowed\\.com/.*\")) throw new SecurityException();\n"
                f"URL url = new URL(target);\nHttpURLConnection conn = (HttpURLConnection) url.openConnection();")
        out.append(_make_sample("Java Spring Boot", code,
            "CWE-918 SSRF via HttpURLConnection", "HIGH", 8.6,
            f"외부 URL {v}가 검증 없이 요청돼 내부 네트워크 스캔이 가능합니다.", fix))
    # PHP
    for v in ["$_GET['url']", "$_POST['endpoint']"]:
        code = f"$data = file_get_contents({v});"
        fix  = (f"$url = {v};\n"
                f"if (!preg_match('#^https://[a-z]+\\.allowed\\.com/#', $url)) die('Blocked');\n"
                f"$data = file_get_contents($url);")
        out.append(_make_sample("PHP", code,
            "CWE-918 SSRF via file_get_contents", "HIGH", 8.6,
            f"file_get_contents({v})로 공격자 지정 URL에 서버측 요청이 전송됩니다.", fix))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CWE-287  Improper Authentication
# ══════════════════════════════════════════════════════════════════════════════
def _auth_samples() -> list[dict]:
    out = []
    # JWT none algorithm
    code = "jwt.decode(token, options={ 'algorithms': ['none'] });"
    fix  = "jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });"
    out.append(_make_sample("Node.js / Express", code,
        "CWE-287 JWT None Algorithm Attack", "CRITICAL", 9.8,
        "algorithms: ['none']을 허용해 서명 검증을 우회한 토큰 위조가 가능합니다.", fix))
    # Weak token comparison
    for lang, code, fix, atk in [
        ("Java Spring Boot",
         "if (token.equals(expectedToken)) { grantAccess(); }",
         "if (MessageDigest.isEqual(token.getBytes(), expectedToken.getBytes())) { grantAccess(); }",
         "단순 문자열 비교는 타이밍 공격에 취약해 비밀 토큰을 브루트포스로 추측할 수 있습니다."),
        ("Python",
         "if user_token == expected_token:\n    grant_access()",
         "import hmac\nif hmac.compare_digest(user_token, expected_token):\n    grant_access()",
         "== 비교는 타이밍 차이로 비밀 토큰 값을 한 바이트씩 추측할 수 있습니다."),
        ("Node.js / Express",
         "if (req.headers['x-api-key'] === API_KEY) { next(); }",
         "if (crypto.timingSafeEqual(Buffer.from(req.headers['x-api-key']), Buffer.from(API_KEY))) { next(); }",
         "=== 비교는 타이밍 사이드채널로 API 키 값을 브루트포스할 수 있습니다."),
    ]:
        out.append(_make_sample(lang, code,
            "CWE-208 Observable Timing Discrepancy", "MEDIUM", 5.9, atk, fix))
    # Missing auth check
    for path in ["/api/admin", "/api/users", "/api/config", "/internal/data"]:
        code = f"@GetMapping(\"{path}\")\npublic ResponseEntity<?> adminData() {{\n    return ResponseEntity.ok(sensitiveData);\n}}"
        fix  = f"@GetMapping(\"{path}\")\n@PreAuthorize(\"hasRole('ADMIN')\")\npublic ResponseEntity<?> adminData() {{\n    return ResponseEntity.ok(sensitiveData);\n}}"
        out.append(_make_sample("Java Spring Boot", code,
            "CWE-862 Missing Authorization", "HIGH", 8.1,
            f"@PreAuthorize 없이 {path} 엔드포인트가 노출돼 누구나 민감 데이터에 접근합니다.", fix))
    # SQL-based auth bypass
    for v in ["username", "email", "userId"]:
        code = (f'String query = "SELECT * FROM users WHERE {v}=\'" + {v} + "\'";\n'
                f'ResultSet rs = stmt.executeQuery(query);\n'
                f'if (rs.next()) {{ loginSuccess(); }}')
        fix  = (f'PreparedStatement ps = conn.prepareStatement(\n'
                f'    "SELECT * FROM users WHERE {v}=? AND password=?");\n'
                f'ps.setString(1, {v});\nps.setString(2, hashedPassword);\n'
                f'ResultSet rs = ps.executeQuery();')
        out.append(_make_sample("Java Spring Boot", code,
            "CWE-89 SQL Injection leading to Auth Bypass", "CRITICAL", 9.8,
            f"{v} 필드에 ' OR 1=1-- 주입으로 비밀번호 없이 로그인이 가능합니다.", fix))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CWE-352  Cross-Site Request Forgery (CSRF)
# ══════════════════════════════════════════════════════════════════════════════
def _csrf_samples() -> list[dict]:
    out = []
    # Java Spring – disabled csrf
    for code, fix in [
        ('http.csrf(AbstractHttpConfigurer::disable);',
         'http.csrf(csrf -> csrf\n    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));'),
        ('@EnableWebSecurity\npublic class SecurityConfig {\n    protected void configure(HttpSecurity http) {\n        http.csrf().disable();\n    }\n}',
         '@EnableWebSecurity\npublic class SecurityConfig {\n    protected void configure(HttpSecurity http) {\n        http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());\n    }\n}'),
    ]:
        out.append(_make_sample("Java Spring Boot", code,
            "CWE-352 Cross-Site Request Forgery (CSRF)", "HIGH", 8.8,
            "CSRF 보호를 비활성화해 공격자가 피해자를 통한 상태 변경 요청을 위조할 수 있습니다.", fix))
    # Django – exempt
    for v in ["transfer", "delete_user", "change_password", "update_profile"]:
        code = f"@csrf_exempt\ndef {v}(request):\n    # process state change\n    pass"
        fix  = (f"from django.views.decorators.csrf import csrf_protect\n"
                f"@csrf_protect\ndef {v}(request):\n    # process state change\n    pass")
        out.append(_make_sample("Python", code,
            "CWE-352 CSRF via csrf_exempt", "HIGH", 8.8,
            f"@csrf_exempt이 적용된 {v} 뷰는 CSRF 토큰 없이 상태 변경 요청이 가능합니다.", fix))
    # PHP – no token
    for action in ["transfer", "update", "delete"]:
        code = (f"<?php\nif ($_POST['action'] === '{action}') {{\n"
                f"    {action}Data($_POST['data']);\n}}")
        fix  = (f"<?php\nif (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {{\n"
                f"    die('CSRF detected');\n}}\n"
                f"if ($_POST['action'] === '{action}') {{\n"
                f"    {action}Data($_POST['data']);\n}}")
        out.append(_make_sample("PHP", code,
            "CWE-352 CSRF – No Token Validation", "HIGH", 8.8,
            f"POST {action} 요청에 CSRF 토큰 검증이 없어 타 사이트에서 강제 요청이 가능합니다.", fix))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CWE-434  Unrestricted File Upload
# ══════════════════════════════════════════════════════════════════════════════
def _file_upload_samples() -> list[dict]:
    out = []
    # Python Flask
    for v in ["file", "upload", "attachment", "document"]:
        code = (f"{v} = request.files['{v}']\n"
                f"{v}.save(os.path.join('uploads/', {v}.filename))")
        fix  = (f"ALLOWED = {{'png','jpg','jpeg','gif','pdf'}}\n"
                f"{v} = request.files['{v}']\n"
                f"ext = {v}.filename.rsplit('.', 1)[-1].lower()\n"
                f"if ext not in ALLOWED:\n    abort(400)\n"
                f"safe_name = secure_filename({v}.filename)\n"
                f"{v}.save(os.path.join('uploads/', safe_name))")
        out.append(_make_sample("Python", code,
            "CWE-434 Unrestricted File Upload", "HIGH", 8.8,
            f"파일 확장자 검증 없이 {v}가 저장돼 .php, .jsp 등 악성 파일 업로드 후 실행이 가능합니다.", fix))
    # Node.js multer
    for v in ["image", "profile", "doc", "file"]:
        code = (f"const upload = multer({{ dest: 'uploads/' }});\n"
                f"router.post('/upload', upload.single('{v}'), (req, res) => {{\n"
                f"    res.send('Uploaded');\n}});")
        fix  = (f"const storage = multer.diskStorage({{ destination: 'uploads/' }});\n"
                f"const upload = multer({{\n"
                f"    storage,\n"
                f"    fileFilter: (req, file, cb) => {{\n"
                f"        const ok = /^image\\/(png|jpe?g|gif)$/.test(file.mimetype);\n"
                f"        cb(null, ok);\n"
                f"    }},\n"
                f"    limits: {{ fileSize: 5 * 1024 * 1024 }},\n"
                f"}});\n"
                f"router.post('/upload', upload.single('{v}'), (req, res) => {{\n"
                f"    res.send('Uploaded');\n}});")
        out.append(_make_sample("Node.js / Express", code,
            "CWE-434 Unrestricted File Upload via multer", "HIGH", 8.8,
            f"MIME 타입·크기 제한 없이 {v} 파일을 저장해 악성 실행 파일 업로드가 가능합니다.", fix))
    # Java MultipartFile
    for v in ["file", "upload", "attachment"]:
        code = (f"@PostMapping(\"/upload\")\npublic String upload(@RequestParam MultipartFile {v}) throws IOException {{\n"
                f"    Path p = Paths.get(\"/uploads/\" + {v}.getOriginalFilename());\n"
                f"    Files.write(p, {v}.getBytes());\n"
                f"    return \"ok\";\n}}")
        fix  = (f"@PostMapping(\"/upload\")\npublic String upload(@RequestParam MultipartFile {v}) throws IOException {{\n"
                f"    String orig = StringUtils.cleanPath({v}.getOriginalFilename());\n"
                f"    if (!orig.matches(\".*\\\\.(png|jpg|gif|pdf)$\")) throw new IllegalArgumentException();\n"
                f"    Path p = Paths.get(\"/uploads/\").resolve(orig).normalize();\n"
                f"    if (!p.startsWith(\"/uploads/\")) throw new SecurityException();\n"
                f"    Files.write(p, {v}.getBytes());\n"
                f"    return \"ok\";\n}}")
        out.append(_make_sample("Java Spring Boot", code,
            "CWE-434 Unrestricted File Upload", "HIGH", 8.8,
            f"원본 파일명 {v}.getOriginalFilename() 검증 없이 저장해 경로 이탈 및 악성 파일 실행이 가능합니다.", fix))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CWE-190  Integer Overflow
# ══════════════════════════════════════════════════════════════════════════════
def _int_overflow_samples() -> list[dict]:
    out = []
    # C
    c_cases = [
        ('int len = atoi(argv[1]);\nchar *buf = malloc(len * sizeof(char));\nmemcpy(buf, src, len);',
         'int len = atoi(argv[1]);\nif (len <= 0 || len > MAX_BUF) exit(1);\nchar *buf = malloc((size_t)len);\nmemcpy(buf, src, (size_t)len);',
         'len * sizeof(char) 연산에서 정수 오버플로우 발생 시 malloc()이 너무 작은 버퍼를 할당해 힙 오버플로우로 이어집니다.'),
        ('unsigned int count = atoi(input);\nint *arr = malloc(count * sizeof(int));',
         'size_t count = (size_t)atoi(input);\nif (count > MAX_ITEMS) exit(1);\nint *arr = malloc(count * sizeof(int));',
         'count * sizeof(int) 오버플로우로 매우 작은 버퍼가 할당되어 힙 버퍼 오버플로우가 발생합니다.'),
        ('short x = (short)atoi(argv[1]);\nshort result = x * x;',
         'int x = atoi(argv[1]);\nif (x > 181 || x < -181) { printf("overflow\\n"); return 1; }\nshort result = (short)(x * x);',
         '16비트 short 곱셈 오버플로우로 예상치 못한 음수 결과가 나와 잘못된 분기 로직이 실행됩니다.'),
    ]
    for code, fix, atk in c_cases:
        out.append(_make_sample("C", code,
            "CWE-190 Integer Overflow or Wraparound", "HIGH", 7.8, atk, fix))
    # Java
    java_cases = [
        ('int size = Integer.parseInt(request.getParameter("size"));\nbyte[] buf = new byte[size * 1024];',
         'int size = Integer.parseInt(request.getParameter("size"));\nif (size <= 0 || size > 100) throw new IllegalArgumentException();\nbyte[] buf = new byte[size * 1024];',
         'size * 1024가 Integer.MAX_VALUE를 초과하면 음수 배열 크기로 NegativeArraySizeException 또는 힙 오버플로우가 발생합니다.'),
        ('int total = price * quantity;',
         'long total = (long)price * quantity;\nif (total > Integer.MAX_VALUE) throw new ArithmeticException("overflow");',
         'int 곱셈 오버플로우로 total 값이 음수가 되어 잘못된 결제 금액이 처리됩니다.'),
    ]
    for code, fix, atk in java_cases:
        out.append(_make_sample("Java Spring Boot", code,
            "CWE-190 Integer Overflow", "HIGH", 7.8, atk, fix))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CWE-787 / CWE-119 / CWE-125  Buffer Issues (C)
# ══════════════════════════════════════════════════════════════════════════════
def _buffer_samples() -> list[dict]:
    out = []
    # CWE-787 Out-of-bounds Write
    cases_787 = [
        ('char buf[64];\nstrcpy(buf, argv[1]);',
         'char buf[64];\nstrncpy(buf, argv[1], sizeof(buf) - 1);\nbuf[sizeof(buf) - 1] = \'\\0\';',
         "strcpy()는 경계 검사 없이 복사해 스택 오버플로우와 리턴 주소 덮어쓰기가 가능합니다.",
         "CWE-787 Out-of-bounds Write (Stack Buffer Overflow)", 8.4),
        ('char buf[256];\nsprintf(buf, "Hello %s!", name);',
         'char buf[256];\nsnprintf(buf, sizeof(buf), "Hello %s!", name);',
         "sprintf()는 길이 제한 없이 buf에 기록해 스택 버퍼 오버플로우가 발생합니다.",
         "CWE-787 Out-of-bounds Write via sprintf", 8.4),
        ('void copy_data(char *dst, char *src, int n) {\n    while (n--) *dst++ = *src++;\n}',
         'void copy_data(char *dst, size_t dst_size, char *src, size_t n) {\n    if (n >= dst_size) n = dst_size - 1;\n    memcpy(dst, src, n);\n    dst[n] = \'\\0\';\n}',
         "경계 검사 없이 포인터로 직접 복사해 힙/스택 버퍼 오버플로우가 가능합니다.",
         "CWE-787 Out-of-bounds Write", 8.4),
    ]
    for code, fix, atk, vuln, cvss in cases_787:
        out.append(_make_sample("C", code, vuln, "HIGH", cvss, atk, fix))
    # CWE-125 Out-of-bounds Read
    cases_125 = [
        ('int idx = atoi(user_input);\nreturn array[idx];',
         'int idx = atoi(user_input);\nif (idx < 0 || idx >= ARRAY_SIZE) return -1;\nreturn array[idx];',
         "배열 경계 검증 없이 인덱스를 사용해 힙 메모리를 읽어 민감 정보가 유출됩니다.",
         "CWE-125 Out-of-bounds Read", 7.1),
        ('char c = buf[len];  // len = strlen(buf) returns exclusive end',
         'if (len > 0) { char c = buf[len - 1]; }',
         "len이 버퍼 크기와 같을 때 buf[len]으로 버퍼 밖 1바이트를 읽어 정보 유출이 발생합니다.",
         "CWE-125 Off-by-one Out-of-bounds Read", 5.5),
    ]
    for code, fix, atk, vuln, cvss in cases_125:
        out.append(_make_sample("C", code, vuln, "HIGH", cvss, atk, fix))
    # CWE-416 Use After Free
    cases_416 = [
        ('char *ptr = malloc(SIZE);\nfree(ptr);\nptr->value = 42;',
         'char *ptr = malloc(SIZE);\nfree(ptr);\nptr = NULL;  // UAF 방지',
         "free 후 ptr을 NULL로 초기화하지 않아 해제된 메모리를 참조해 임의 코드 실행이 가능합니다.",
         "CWE-416 Use After Free", 9.8),
        ('free(node->data);\nprocess(node->data);',
         'free(node->data);\nnode->data = NULL;\nprocess(node->data);',
         "node->data free 후 process()에서 재사용해 힙 익스플로잇이 가능합니다.",
         "CWE-416 Use After Free", 9.8),
        ('void cleanup(Resource *r) {\n    if (r->buf) free(r->buf);\n    free(r->buf);  // double free\n}',
         'void cleanup(Resource *r) {\n    if (r->buf) {\n        free(r->buf);\n        r->buf = NULL;\n    }\n}',
         "이중 free로 힙 할당자의 freelist를 오염시켜 임의 쓰기 공격이 가능합니다.",
         "CWE-416 Double Free", 9.8),
    ]
    for code, fix, atk, vuln, cvss in cases_416:
        out.append(_make_sample("C", code, vuln, "CRITICAL", cvss, atk, fix))
    # CWE-476 NULL Pointer Dereference
    cases_476 = [
        ('char *p = malloc(size);\n*p = 0;  // no NULL check',
         'char *p = malloc(size);\nif (!p) { perror("malloc"); exit(1); }\n*p = 0;',
         "malloc() 실패 시 NULL 반환을 체크하지 않아 NULL 역참조로 크래시가 발생합니다.",
         "CWE-476 NULL Pointer Dereference", 5.5),
        ('User *u = getUser(id);\nreturn u->name;',
         'User *u = getUser(id);\nif (!u) return NULL;\nreturn u->name;',
         "getUser() NULL 반환 체크 없이 역참조해 서비스 거부 크래시가 발생합니다.",
         "CWE-476 NULL Pointer Dereference", 5.5),
    ]
    for code, fix, atk, vuln, cvss in cases_476:
        out.append(_make_sample("C", code, vuln, "MEDIUM", cvss, atk, fix))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CWE-94  Code Injection / eval
# ══════════════════════════════════════════════════════════════════════════════
def _code_injection_samples() -> list[dict]:
    out = []
    # Python eval/exec
    for v in ["user_code", "expr", "formula", "query", "input_val"]:
        code = f"result = eval({v})"
        fix  = f"# eval() 대신 ast.literal_eval() 또는 허용 목록 기반 파서 사용\nimport ast\nresult = ast.literal_eval({v})"
        out.append(_make_sample("Python", code,
            "CWE-94 Code Injection via eval()", "CRITICAL", 9.8,
            f"eval({v})로 공격자가 임의 Python 코드를 서버에서 실행합니다.", fix))
    for v in ["user_code", "script", "cmd_str"]:
        code = f"exec({v})"
        fix  = f"# exec() 사용 금지 — 허용 목록 기반 기능으로 대체\nif {v} not in ALLOWED_COMMANDS:\n    raise ValueError()\nrun_safe({v})"
        out.append(_make_sample("Python", code,
            "CWE-94 Code Injection via exec()", "CRITICAL", 9.8,
            f"exec({v})로 임의 Python 코드가 실행돼 서버 전체가 탈취됩니다.", fix))
    # JavaScript eval
    for v in ["req.query.code", "req.body.expr", "searchParams.get('fn')"]:
        code = f"const result = eval({v});"
        fix  = "// eval() 사용 금지 — Function() 또는 VM 샌드박스 사용\nconst vm = require('vm');\nconst result = vm.runInNewContext(safeExpr, {});"
        out.append(_make_sample("Node.js / Express", code,
            "CWE-94 Code Injection via eval()", "CRITICAL", 9.8,
            f"eval({v})로 공격자가 Node.js 컨텍스트에서 임의 JS 코드를 실행합니다.", fix))
    # React
    for v in ["searchParams.get('callback')", "query.fn", "props.code"]:
        code = f"eval({v});"
        fix  = "// eval() 제거 — 콜백은 허용 목록으로만 실행\nconst SAFE = {{ greet: () => alert('hello') }};\nif (SAFE[callbackName]) SAFE[callbackName]();"
        out.append(_make_sample("React / Next.js", code,
            "CWE-94 Code Injection via eval()", "CRITICAL", 9.8,
            f"eval({v})로 공격자가 XSS를 우회해 클라이언트 측 임의 코드를 실행합니다.", fix))
    # PHP
    for v in ["$_GET['code']", "$_POST['expr']"]:
        code = f"eval({v});"
        fix  = f"// eval() 사용 금지 — 화이트리스트 기능만 실행\n$allowed = ['feature_a', 'feature_b'];\nif (in_array({v}, $allowed)) call_safe_func({v});"
        out.append(_make_sample("PHP", code,
            "CWE-94 PHP Code Injection via eval()", "CRITICAL", 9.8,
            f"PHP eval({v})로 공격자가 서버에서 임의 PHP 코드를 실행합니다.", fix))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CWE-611  XXE Injection
# ══════════════════════════════════════════════════════════════════════════════
def _xxe_samples() -> list[dict]:
    out = []
    # Java DocumentBuilder
    cases = [
        ('DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\nDocumentBuilder db = dbf.newDocumentBuilder();\nDocument doc = db.parse(userXmlInput);',
         'DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\ndbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\ndbf.setFeature("http://xml.org/sax/features/external-general-entities", false);\nDocumentBuilder db = dbf.newDocumentBuilder();\nDocument doc = db.parse(userXmlInput);',
         "DOCTYPE 선언 금지 없이 XML을 파싱해 외부 엔티티로 /etc/passwd 등 내부 파일을 읽습니다.",
         "CWE-611 XML External Entity (XXE) Injection"),
        ('SAXParserFactory spf = SAXParserFactory.newInstance();\nSAXParser sp = spf.newSAXParser();\nsp.parse(xmlStream, handler);',
         'SAXParserFactory spf = SAXParserFactory.newInstance();\nspf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nSAXParser sp = spf.newSAXParser();\nsp.parse(xmlStream, handler);',
         "SAXParser에서 DOCTYPE을 허용해 외부 엔티티 참조로 SSRF 또는 파일 유출이 발생합니다.",
         "CWE-611 XXE via SAXParser"),
    ]
    for code, fix, atk, vuln in cases:
        out.append(_make_sample("Java Spring Boot", code, vuln, "HIGH", 8.6, atk, fix))
    # Python lxml
    for v in ["user_xml", "request.data", "body"]:
        code = f"from lxml import etree\nparser = etree.XMLParser()\ntree = etree.fromstring({v}, parser)"
        fix  = f"from lxml import etree\nparser = etree.XMLParser(resolve_entities=False, no_network=True)\ntree = etree.fromstring({v}, parser)"
        out.append(_make_sample("Python", code,
            "CWE-611 XXE Injection via lxml", "HIGH", 8.6,
            f"resolve_entities=True(기본값)로 {v}의 외부 엔티티가 처리돼 파일 유출이 가능합니다.", fix))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CWE-1333  ReDoS
# ══════════════════════════════════════════════════════════════════════════════
def _redos_samples() -> list[dict]:
    out = []
    # Node.js
    for v in ["req.query.search", "req.body.input", "req.params.pattern"]:
        code = f"const pattern = new RegExp({v});\nconst match = largeInput.match(pattern);"
        fix  = (f"// 사용자 입력으로 직접 RegExp 생성 금지\n"
                f"const safePattern = /^[a-zA-Z0-9\\s]+$/;\n"
                f"if (!safePattern.test({v})) throw new Error('Invalid input');\n"
                f"const match = largeInput.match(safePattern);")
        out.append(_make_sample("Node.js / Express", code,
            "CWE-1333 Regular Expression Denial of Service (ReDoS)", "HIGH", 7.5,
            f"공격자가 {v}에 복잡한 패턴을 전달해 백트래킹 폭발로 이벤트 루프를 블록합니다.", fix))
    # Python
    for v in ["user_pattern", "search", "query"]:
        code = f"import re\npattern = re.compile({v})\nresult = pattern.match(text)"
        fix  = (f"import re\n# 입력 패턴 검증 후 컴파일\nif len({v}) > 100 or not re.fullmatch(r'[\\w\\s\\.\\-\\+\\*]+', {v}):\n"
                f"    raise ValueError('Invalid pattern')\n"
                f"pattern = re.compile({v})\nresult = pattern.match(text)")
        out.append(_make_sample("Python", code,
            "CWE-1333 ReDoS via re.compile with user input", "HIGH", 7.5,
            f"공격자가 {v}에 (a+)+ 같은 패턴을 삽입해 CPU를 무한 소비시킵니다.", fix))
    # Java
    for v in ["request.getParameter(\"pattern\")", "userPattern"]:
        code = f"Pattern p = Pattern.compile({v});\nMatcher m = p.matcher(input);"
        fix  = (f"// 정규식 패턴 길이·복잡도 제한\nif ({v}.length() > 100) throw new IllegalArgumentException();\n"
                f"Pattern p = Pattern.compile({v});\nMatcher m = p.matcher(input);")
        out.append(_make_sample("Java Spring Boot", code,
            "CWE-1333 ReDoS via Pattern.compile with user input", "HIGH", 7.5,
            f"제한 없이 컴파일된 {v} 패턴에 공격자가 지수적 매칭 패턴을 제공해 서비스 거부가 발생합니다.", fix))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CWE-601  Open Redirect
# ══════════════════════════════════════════════════════════════════════════════
def _open_redirect_samples() -> list[dict]:
    out = []
    # React / Next.js
    for v in ["searchParams.get('next')", "query.redirect", "router.query.url"]:
        code = f"const next = {v};\nrouter.push(next);"
        fix  = (f"const next = {v};\n"
                f"const safe = next && next.startsWith('/') && !next.startsWith('//') ? next : '/';\n"
                f"router.push(safe);")
        out.append(_make_sample("React / Next.js", code,
            "CWE-601 Open Redirect", "MEDIUM", 6.1,
            f"공격자가 {v}에 https://evil.com을 전달해 피해자를 피싱 사이트로 유도합니다.", fix))
    # Node.js
    for v in ["req.query.next", "req.body.redirect", "req.query.url"]:
        code = f"res.redirect({v});"
        fix  = (f"const dest = {v};\n"
                f"if (!dest.startsWith('/') || dest.startsWith('//')) {{\n"
                f"    return res.redirect('/');\n}}\n"
                f"res.redirect(dest);")
        out.append(_make_sample("Node.js / Express", code,
            "CWE-601 Open Redirect", "MEDIUM", 6.1,
            f"res.redirect({v})에 외부 URL이 전달돼 피싱 및 자격증명 탈취에 악용됩니다.", fix))
    # Java
    for v in ["request.getParameter(\"next\")", "request.getParameter(\"url\")"]:
        code = f"response.sendRedirect({v});"
        fix  = (f"String dest = {v};\n"
                f"if (dest == null || !dest.startsWith(\"/\") || dest.startsWith(\"//\")) dest = \"/\";\n"
                f"response.sendRedirect(dest);")
        out.append(_make_sample("Java Spring Boot", code,
            "CWE-601 Open Redirect via sendRedirect", "MEDIUM", 6.1,
            f"sendRedirect({v})에 외부 도메인 URL이 허용돼 피싱 공격이 가능합니다.", fix))
    # PHP
    for v in ["$_GET['next']", "$_POST['redirect']"]:
        code = f"header('Location: ' . {v});"
        fix  = (f"$dest = {v};\n"
                f"if (!preg_match('#^/#', $dest) || preg_match('#^//#', $dest)) $dest = '/';\n"
                f"header('Location: ' . $dest);")
        out.append(_make_sample("PHP", code,
            "CWE-601 Open Redirect via header Location", "MEDIUM", 6.1,
            f"Location 헤더에 {v}가 직접 사용돼 외부 URL 리다이렉트가 가능합니다.", fix))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CWE-269 / CWE-250  Privilege Escalation / Least Privilege
# ══════════════════════════════════════════════════════════════════════════════
def _privilege_samples() -> list[dict]:
    out = []
    # Python chmod
    cases_py = [
        ('import os\nos.chmod("config.yml", 0o777)',
         'import os\nos.chmod("config.yml", 0o640)',
         "config.yml에 0o777 권한을 부여해 모든 사용자가 읽기·쓰기·실행이 가능해집니다.",
         "CWE-276 Incorrect Default Permissions"),
        ('with open("secrets.env", "w") as f:\n    f.write(secret)',
         'import os\nfd = os.open("secrets.env", os.O_WRONLY | os.O_CREAT, 0o600)\nwith os.fdopen(fd, "w") as f:\n    f.write(secret)',
         "기본 파일 권한으로 secrets.env가 생성돼 같은 시스템 사용자가 읽기가 가능합니다.",
         "CWE-276 Incorrect Default File Permission"),
    ]
    for code, fix, atk, vuln in cases_py:
        out.append(_make_sample("Python", code, vuln, "MEDIUM", 5.5, atk, fix))
    # GitHub Actions excessive permissions
    cases_gh = [
        ("permissions:\n  actions: write\n  contents: write\n  id-token: write\n  packages: write",
         "permissions:\n  contents: read  # 최소 권한 원칙",
         "GitHub Actions에 과도한 write 권한이 부여돼 악성 워크플로우가 저장소·패키지를 수정합니다.",
         "CWE-269 Improper Privilege Management"),
        ("jobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions: write-all",
         "jobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read",
         "write-all 권한으로 빌드 잡이 저장소의 모든 리소스를 수정할 수 있습니다.",
         "CWE-269 Overly Permissive GitHub Actions"),
    ]
    for code, fix, atk, vuln in cases_gh:
        out.append(_make_sample("GitHub Actions YAML", code, vuln, "HIGH", 8.1, atk, fix))
    # Java @RolesAllowed missing
    for path in ["/admin/users", "/admin/config", "/admin/logs"]:
        code = f"@GetMapping(\"{path}\")\npublic List<User> listUsers() {{\n    return userService.findAll();\n}}"
        fix  = f"@GetMapping(\"{path}\")\n@RolesAllowed(\"ADMIN\")\npublic List<User> listUsers() {{\n    return userService.findAll();\n}}"
        out.append(_make_sample("Java Spring Boot", code,
            "CWE-862 Missing Authorization on Admin Endpoint", "HIGH", 8.1,
            f"@RolesAllowed 없이 {path}가 노출돼 일반 사용자가 관리자 데이터에 접근합니다.", fix))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CWE-362  Race Condition / TOCTOU
# ══════════════════════════════════════════════════════════════════════════════
def _race_condition_samples() -> list[dict]:
    out = []
    # C TOCTOU
    cases_c = [
        ('if (access(filename, R_OK) == 0) {\n    fd = open(filename, O_RDONLY);\n}',
         'fd = open(filename, O_RDONLY);\nif (fd == -1) { perror("open"); exit(1); }',
         "access() 체크와 open() 사이에 파일 교체 TOCTOU로 권한 없는 파일이 열립니다.",
         "CWE-362 TOCTOU Race Condition"),
        ('if (stat(tmpfile, &sb) != 0) {\n    fd = creat(tmpfile, 0600);\n}',
         'fd = open(tmpfile, O_CREAT | O_EXCL | O_WRONLY, 0600);\nif (fd == -1) { perror("open"); exit(1); }',
         "stat()과 creat() 사이에 심볼릭 링크 교체로 임의 파일 덮어쓰기가 가능합니다.",
         "CWE-362 TOCTOU via Symlink Attack"),
    ]
    for code, fix, atk, vuln in cases_c:
        out.append(_make_sample("C", code, vuln, "HIGH", 7.0, atk, fix))
    # Python threading
    cases_py = [
        ('balance -= amount  # shared state, no lock',
         'with lock:\n    balance -= amount',
         "락 없이 공유 변수 balance를 수정해 동시 요청 시 이중 출금이 발생합니다.",
         "CWE-362 Race Condition in Bank Transfer"),
        ('if user_sessions[token]["active"]:\n    process(token)',
         'with session_lock:\n    if user_sessions[token]["active"]:\n        process(token)',
         "세션 검증과 처리 사이에 레이스 컨디션으로 세션을 중복 사용합니다.",
         "CWE-362 Race Condition in Session Check"),
    ]
    for code, fix, atk, vuln in cases_py:
        out.append(_make_sample("Python", code, vuln, "HIGH", 7.0, atk, fix))
    # Java synchronized missing
    cases_java = [
        ('private int counter = 0;\npublic void increment() {\n    counter++;\n}',
         'private final AtomicInteger counter = new AtomicInteger(0);\npublic void increment() {\n    counter.incrementAndGet();\n}',
         "counter++ 비원자적 연산으로 동시 스레드가 같은 값을 읽고 갱신해 카운트가 손실됩니다.",
         "CWE-362 Race Condition in Counter"),
        ('if (cache.containsKey(key)) {\n    return cache.get(key);\n}\ncache.put(key, compute(key));\nreturn cache.get(key);',
         'return cache.computeIfAbsent(key, k -> compute(k));',
         "containsKey()–put() 사이 레이스로 키가 중복 계산되거나 오래된 값이 반환됩니다.",
         "CWE-362 Race Condition in Cache Update"),
    ]
    for code, fix, atk, vuln in cases_java:
        out.append(_make_sample("Java Spring Boot", code, vuln, "MEDIUM", 5.9, atk, fix))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CWE-532  Log Injection / Secret Exposure in Logs
# ══════════════════════════════════════════════════════════════════════════════
def _log_injection_samples() -> list[dict]:
    out = []
    # Python logging
    for v in ["password", "token", "secret", "api_key", "credit_card"]:
        code = f"import logging\nlogging.info(f'User data: {{{v}}}={{{v}}}')"
        fix  = f"import logging\nlogging.info('User data: %s=<REDACTED>', '{v}')"
        out.append(_make_sample("Python", code,
            "CWE-532 Sensitive Data Exposure in Logs", "MEDIUM", 5.3,
            f"로그에 {v}가 평문으로 기록돼 로그 파일 접근 시 민감 정보가 유출됩니다.", fix))
    # Node.js
    for v in ["password", "token", "apiKey", "secret"]:
        code = f"console.log('Auth data:', {{ {v} }});"
        fix  = f"console.log('Auth data:', {{ {v}: '[REDACTED]' }});"
        out.append(_make_sample("Node.js / Express", code,
            "CWE-532 Sensitive Data in Console Log", "MEDIUM", 5.3,
            f"console.log에 {v}가 포함돼 로그 집계 시스템에 민감 정보가 저장됩니다.", fix))
    # GitHub Actions secret in echo
    for v in ["API_TOKEN", "SECRET_KEY", "DB_PASSWORD", "AWS_SECRET"]:
        code = f'- name: Debug\n  run: echo "Token=${{{{ secrets.{v} }}}}"'
        fix  = f'- name: Debug\n  run: echo "Token=<REDACTED>"  # secrets는 절대 echo 금지'
        out.append(_make_sample("GitHub Actions YAML", code,
            "CWE-532 GitHub Actions Secret Exposure in Logs", "HIGH", 6.5,
            f"echo로 secrets.{v}를 출력해 빌드 로그에 시크릿이 노출됩니다.", fix))
    # Java logger
    for v in ["password", "token", "creditCard", "ssn"]:
        code = f"logger.debug(\"User info: {v}={{}}\", user.get{v.capitalize()}());"
        fix  = f"logger.debug(\"User info: {v}=<REDACTED>\");"
        out.append(_make_sample("Java Spring Boot", code,
            "CWE-532 Sensitive Data in Application Log", "MEDIUM", 5.3,
            f"logger.debug에 {v} 값이 기록돼 로그 파일 유출 시 민감 정보가 노출됩니다.", fix))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CWE-306  Missing Authentication for Critical Function
# ══════════════════════════════════════════════════════════════════════════════
def _missing_auth_samples() -> list[dict]:
    out = []
    # Java – no auth on critical endpoints
    critical_paths = [
        ("/api/admin/delete", "deleteAll"),
        ("/api/admin/reset", "resetPassword"),
        ("/internal/backup", "triggerBackup"),
        ("/system/shutdown", "shutdown"),
    ]
    for path, func in critical_paths:
        code = f"@PostMapping(\"{path}\")\npublic ResponseEntity<?> {func}() {{\n    service.{func}();\n    return ResponseEntity.ok().build();\n}}"
        fix  = f"@PostMapping(\"{path}\")\n@PreAuthorize(\"hasRole('ADMIN')\")\npublic ResponseEntity<?> {func}() {{\n    service.{func}();\n    return ResponseEntity.ok().build();\n}}"
        out.append(_make_sample("Java Spring Boot", code,
            "CWE-306 Missing Authentication for Critical Function", "CRITICAL", 9.8,
            f"{path} 엔드포인트에 인증 없이 접근해 {func}()를 실행할 수 있습니다.", fix))
    # Node.js – unprotected route
    routes = [
        ("/admin/users", "getAllUsers"),
        ("/admin/config", "getConfig"),
        ("/internal/metrics", "getMetrics"),
    ]
    for path, fn in routes:
        code = f"router.get('{path}', (req, res) => {{\n    res.json({fn}());\n}});"
        fix  = f"router.get('{path}', authMiddleware, adminOnly, (req, res) => {{\n    res.json({fn}());\n}});"
        out.append(_make_sample("Node.js / Express", code,
            "CWE-306 Missing Authentication on Admin Route", "CRITICAL", 9.8,
            f"인증 미들웨어 없이 {path}가 노출돼 누구나 관리 기능을 호출할 수 있습니다.", fix))
    # Python Flask
    for path, fn in [("/admin", "admin_panel"), ("/reset_db", "reset")]:
        code = f"@app.route('{path}')\ndef {fn}():\n    return admin_data()"
        fix  = f"from functools import wraps\n@app.route('{path}')\n@login_required\n@admin_required\ndef {fn}():\n    return admin_data()"
        out.append(_make_sample("Python", code,
            "CWE-306 Missing Authentication on Admin Route", "CRITICAL", 9.8,
            f"{path} 라우트에 인증 데코레이터가 없어 누구나 관리 기능에 접근합니다.", fix))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CWE-20  Improper Input Validation
# ══════════════════════════════════════════════════════════════════════════════
def _input_validation_samples() -> list[dict]:
    out = []
    # Python – no type/range check
    cases = [
        ('age = int(request.args.get("age"))',
         'try:\n    age = int(request.args.get("age", 0))\n    if age < 0 or age > 150:\n        abort(400)\nexcept ValueError:\n    abort(400)',
         "age 파라미터가 음수나 오버플로우 값일 때 비즈니스 로직 오류가 발생합니다.",
         "CWE-20 Missing Input Validation (Age Range)"),
        ('limit = int(request.args.get("limit", 100))\nresults = db.query(limit=limit)',
         'limit = min(max(int(request.args.get("limit", 10)), 1), 100)\nresults = db.query(limit=limit)',
         "limit 파라미터에 매우 큰 값을 전달해 DB 쿼리 부하로 서비스 거부가 가능합니다.",
         "CWE-20 Missing Input Validation (Limit DoS)"),
    ]
    for code, fix, atk, vuln in cases:
        out.append(_make_sample("Python", code, vuln, "MEDIUM", 5.3, atk, fix))
    # Node.js
    cases_node = [
        ('const page = parseInt(req.query.page);\ndb.find({ skip: page * 10 });',
         'const page = Math.max(1, parseInt(req.query.page) || 1);\nif (!Number.isInteger(page)) return res.sendStatus(400);\ndb.find({ skip: (page - 1) * 10 });',
         "page에 NaN이나 음수 전달 시 skip에 NaN·음수가 전달돼 데이터베이스 오류가 발생합니다.",
         "CWE-20 Missing Pagination Input Validation"),
        ('const email = req.body.email;\nawait sendEmail(email);',
         'const email = req.body.email;\nif (typeof email !== "string" || !/.+@.+\\..+/.test(email)) {\n    return res.status(400).json({ error: "Invalid email" });\n}\nawait sendEmail(email);',
         "이메일 형식 검증 없이 sendEmail()을 호출해 헤더 인젝션 또는 스팸 릴레이가 가능합니다.",
         "CWE-20 Missing Email Validation"),
    ]
    for code, fix, atk, vuln in cases_node:
        out.append(_make_sample("Node.js / Express", code, vuln, "MEDIUM", 5.3, atk, fix))
    # Java
    cases_java = [
        ('int quantity = Integer.parseInt(request.getParameter("qty"));\norder.setQuantity(quantity);',
         'int quantity = Integer.parseInt(request.getParameter("qty"));\nif (quantity <= 0 || quantity > 9999) throw new IllegalArgumentException("Invalid qty");\norder.setQuantity(quantity);',
         "qty에 음수를 전달해 가격 계산 오류나 재고 오버플로우를 유발합니다.",
         "CWE-20 Missing Quantity Validation"),
        ('String phone = request.getParameter("phone");\ndb.save(phone);',
         'String phone = request.getParameter("phone");\nif (!phone.matches("^[+]?[0-9]{7,15}$")) throw new IllegalArgumentException();\ndb.save(phone);',
         "전화번호 형식 검증 없이 저장해 SQL 주입 또는 데이터 무결성 침해가 가능합니다.",
         "CWE-20 Missing Phone Validation"),
    ]
    for code, fix, atk, vuln in cases_java:
        out.append(_make_sample("Java Spring Boot", code, vuln, "MEDIUM", 5.3, atk, fix))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CWE-863  Incorrect Authorization (IDOR)
# ══════════════════════════════════════════════════════════════════════════════
def _idor_samples() -> list[dict]:
    out = []
    # Python IDOR
    for resource in ["document", "invoice", "order", "record", "profile"]:
        code = (f"@app.route('/api/{resource}/<int:id>')\n@login_required\n"
                f"def get_{resource}(id):\n"
                f"    return {resource}_service.get_by_id(id)")
        fix  = (f"@app.route('/api/{resource}/<int:id>')\n@login_required\n"
                f"def get_{resource}(id):\n"
                f"    item = {resource}_service.get_by_id(id)\n"
                f"    if item.owner_id != current_user.id:\n"
                f"        abort(403)\n"
                f"    return item")
        out.append(_make_sample("Python", code,
            "CWE-863 Insecure Direct Object Reference (IDOR)", "HIGH", 8.1,
            f"소유자 검증 없이 id로 {resource}를 조회해 다른 사용자의 데이터에 접근합니다.", fix))
    # Node.js IDOR
    for resource in ["user", "order", "file", "message"]:
        code = (f"router.get('/{resource}/:id', authMiddleware, async (req, res) => {{\n"
                f"    const item = await {resource}Service.findById(req.params.id);\n"
                f"    res.json(item);\n}});")
        fix  = (f"router.get('/{resource}/:id', authMiddleware, async (req, res) => {{\n"
                f"    const item = await {resource}Service.findById(req.params.id);\n"
                f"    if (!item || item.userId !== req.user.id) return res.sendStatus(403);\n"
                f"    res.json(item);\n}});")
        out.append(_make_sample("Node.js / Express", code,
            "CWE-863 Insecure Direct Object Reference (IDOR)", "HIGH", 8.1,
            f"/{resource}/:id 엔드포인트에 소유자 검증이 없어 다른 사용자의 데이터를 열람합니다.", fix))
    # Java IDOR
    for resource in ["document", "invoice"]:
        code = (f"@GetMapping(\"/{resource}/{{id}}\")\npublic {resource.capitalize()} get{resource.capitalize()}(@PathVariable Long id) {{\n"
                f"    return service.findById(id);\n}}")
        fix  = (f"@GetMapping(\"/{resource}/{{id}}\")\npublic {resource.capitalize()} get{resource.capitalize()}(@PathVariable Long id,\n"
                f"        @AuthenticationPrincipal UserDetails user) {{\n"
                f"    {resource.capitalize()} item = service.findById(id);\n"
                f"    if (!item.getOwnerId().equals(user.getId())) throw new AccessDeniedException();\n"
                f"    return item;\n}}")
        out.append(_make_sample("Java Spring Boot", code,
            "CWE-863 Insecure Direct Object Reference (IDOR)", "HIGH", 8.1,
            f"/{resource}/{{id}} 조회 시 소유자 검증 없어 다른 사용자의 {resource}에 접근 가능합니다.", fix))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# GitHub Actions YAML — 공급망 / 비밀 노출 / 인젝션
# ══════════════════════════════════════════════════════════════════════════════
def _github_actions_samples() -> list[dict]:
    out = []
    # Unpinned actions
    unpinned = [
        "actions/checkout@main",
        "actions/setup-node@master",
        "actions/upload-artifact@v3",
        "docker/build-push-action@latest",
        "github/codeql-action/analyze@v2",
        "aws-actions/configure-aws-credentials@main",
    ]
    for action in unpinned:
        name = action.split("/")[-1].split("@")[0]
        sha  = "a81bbbf8298c0fa03ea29cdc473d45769f953675"
        code = f"- uses: {action}"
        fix  = f"- uses: {action.split('@')[0]}@{sha}  # 커밋 SHA 고정"
        out.append(_make_sample("GitHub Actions YAML", code,
            "CWE-829 Supply Chain Attack (Unpinned Action)", "HIGH", 8.1,
            f"{action}은 브랜치/태그가 변경되면 악성 코드가 주입될 수 있습니다.", fix))
    # Script injection via github context
    contexts = [
        "github.event.issue.title",
        "github.event.pull_request.title",
        "github.event.comment.body",
        "github.head_ref",
        "github.event.issue.body",
    ]
    for ctx in contexts:
        code = f"- run: echo ${{{{ {ctx} }}}}"
        fix  = (f"- name: Safe echo\n"
                f"  env:\n    INPUT: ${{{{ {ctx} }}}}\n"
                f"  run: echo \"$INPUT\"")
        out.append(_make_sample("GitHub Actions YAML", code,
            "CWE-78 Script Injection via Untrusted GitHub Context", "HIGH", 8.1,
            f"${{{{ {ctx} }}}}가 직접 run 스크립트에 삽입돼 공격자가 명령 주입이 가능합니다.", fix))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CWE-312  Cleartext Storage / CWE-319 Cleartext Transmission
# ══════════════════════════════════════════════════════════════════════════════
def _cleartext_samples() -> list[dict]:
    out = []
    # Python cleartext password storage
    for v in ["password", "user_password", "pwd", "pass_"]:
        code = f"users_db[username] = {v}  # plaintext"
        fix  = (f"import bcrypt\nhashed = bcrypt.hashpw({v}.encode(), bcrypt.gensalt())\n"
                f"users_db[username] = hashed")
        out.append(_make_sample("Python", code,
            "CWE-312 Cleartext Storage of Sensitive Information", "HIGH", 7.5,
            f"비밀번호 {v}를 평문 저장해 DB 유출 시 즉시 노출됩니다.", fix))
    # HTTP (no TLS)
    for url in ["http://api.internal.com/data", "http://payment.service/charge"]:
        code = f"requests.post('{url}', data=payload)"
        fix  = f"requests.post('{url.replace('http://', 'https://')}', data=payload, verify=True)"
        out.append(_make_sample("Python", code,
            "CWE-319 Cleartext Transmission of Sensitive Information", "HIGH", 7.4,
            f"HTTP로 {url}에 민감 데이터를 전송해 중간자 공격으로 탈취됩니다.", fix))
    # Java MD5 password hash
    for hash_alg in ["MD5", "SHA-1"]:
        code = (f"MessageDigest md = MessageDigest.getInstance(\"{hash_alg}\");\n"
                f"byte[] hash = md.digest(password.getBytes());")
        fix  = ('import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;\n'
                'BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);\n'
                'String hash = encoder.encode(password);')
        out.append(_make_sample("Java Spring Boot", code,
            f"CWE-916 Weak {hash_alg} Password Hash", "HIGH", 7.5,
            f"{hash_alg}는 무지개 테이블 공격에 취약해 DB 유출 시 비밀번호가 즉시 크랙됩니다.", fix))
    # Node.js http
    for v in ["userData", "tokenData", "credentials"]:
        code = f"http.post('http://api.example.com/login', {{ data: {v} }})"
        fix  = f"axios.post('https://api.example.com/login', {{ data: {v} }})"
        out.append(_make_sample("Node.js / Express", code,
            "CWE-319 Cleartext Transmission of Credentials", "HIGH", 7.4,
            f"HTTP로 {v}를 전송해 네트워크 도청으로 자격증명이 탈취됩니다.", fix))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CWE-200  Information Disclosure
# ══════════════════════════════════════════════════════════════════════════════
def _info_disclosure_samples() -> list[dict]:
    out = []
    # Stack trace exposure
    for lang, code, fix in [
        ("Node.js / Express",
         "app.use((err, req, res, next) => {\n    res.status(500).json({ error: err.stack });\n});",
         "app.use((err, req, res, next) => {\n    console.error(err);\n    res.status(500).json({ error: 'Internal Server Error' });\n});",
         ),
        ("Python",
         "except Exception as e:\n    return jsonify({'error': str(e), 'trace': traceback.format_exc()}), 500",
         "except Exception as e:\n    app.logger.error(traceback.format_exc())\n    return jsonify({'error': 'Internal Server Error'}), 500",
         ),
        ("Java Spring Boot",
         "@ExceptionHandler\npublic ResponseEntity<?> handle(Exception e) {\n    return ResponseEntity.status(500).body(e.toString());\n}",
         "@ExceptionHandler\npublic ResponseEntity<?> handle(Exception e) {\n    log.error(\"Error\", e);\n    return ResponseEntity.status(500).body(\"Internal Server Error\");\n}",
         ),
    ]:
        out.append(_make_sample(lang, code,
            "CWE-209 Information Disclosure via Error Message", "MEDIUM", 5.3,
            "상세 스택 트레이스가 클라이언트에 노출돼 내부 코드 구조와 라이브러리 버전이 드러납니다.", fix))
    # Debug mode in production
    for lang, code, fix in [
        ("Python", "app.run(debug=True)",
         "app.run(debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true')"),
        ("Node.js / Express", "app.use(morgan('dev'));\napp.use(errorHandler());",
         "if (process.env.NODE_ENV !== 'production') {\n    app.use(morgan('dev'));\n}"),
    ]:
        out.append(_make_sample(lang, code,
            "CWE-94 Debug Mode Enabled in Production", "HIGH", 7.5,
            "프로덕션에서 debug=True가 활성화돼 인터랙티브 디버거를 통한 RCE가 가능합니다.", fix))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CWE-829  Dependency / Supply Chain
# ══════════════════════════════════════════════════════════════════════════════
def _supply_chain_samples() -> list[dict]:
    out = []
    # npm unpinned
    pkgs = ["lodash", "axios", "express", "react", "webpack", "babel-core"]
    for pkg in pkgs:
        code = f'"{pkg}": "*"  // package.json'
        fix  = f'"{pkg}": "^4.17.21"  // 고정 버전 사용'
        out.append(_make_sample("Node.js / Express", code,
            "CWE-829 Inclusion of Functionality from Untrusted Control Sphere", "HIGH", 8.1,
            f"{pkg}의 * 버전 지정은 악성 코드가 포함된 새 버전이 자동 설치될 수 있습니다.", fix))
    # pip unpinned
    pips = ["requests", "django", "flask", "sqlalchemy", "numpy"]
    for pkg in pips:
        code = f"{pkg}  # requirements.txt"
        fix  = f"{pkg}==2.31.0  # 버전 고정"
        out.append(_make_sample("Python", code,
            "CWE-829 Unpinned Python Dependency", "MEDIUM", 5.9,
            f"버전 고정 없는 {pkg}는 pip install 시 악성 패키지 버전이 설치될 수 있습니다.", fix))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CWE-114  Process Control / Dynamic Library Loading
# ══════════════════════════════════════════════════════════════════════════════
def _dynamic_load_samples() -> list[dict]:
    out = []
    # Python import
    for v in ["module_name", "plugin", "handler", "req.query.module"]:
        code = f"module = importlib.import_module({v})\nmodule.run()"
        fix  = (f"ALLOWED_MODULES = {{'plugin_a', 'plugin_b', 'plugin_c'}}\n"
                f"if {v} not in ALLOWED_MODULES:\n    raise ValueError('Disallowed module')\n"
                f"module = importlib.import_module({v})\nmodule.run()")
        out.append(_make_sample("Python", code,
            "CWE-114 Process Control via Dynamic Module Load", "HIGH", 8.1,
            f"공격자가 {v}에 임의 모듈명을 전달해 악성 모듈을 임포트·실행합니다.", fix))
    # Node.js require
    for v in ["req.query.plugin", "config.module"]:
        code = f"const mod = require({v});\nmod.execute();"
        fix  = (f"const ALLOWED = ['plugin-a', 'plugin-b'];\n"
                f"if (!ALLOWED.includes({v})) throw new Error('Disallowed');\n"
                f"const mod = require({v});\nmod.execute();")
        out.append(_make_sample("Node.js / Express", code,
            "CWE-114 Dynamic require() with User Input", "HIGH", 8.1,
            f"require({v})로 공격자가 임의 Node.js 모듈이나 절대 경로 파일을 로드합니다.", fix))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CWE-942  Permissive CORS + CWE-346 Origin Validation
# ══════════════════════════════════════════════════════════════════════════════
def _cors_samples() -> list[dict]:
    out = []
    # Node.js wildcard
    cases = [
        ("res.setHeader('Access-Control-Allow-Origin', '*');",
         "res.setHeader('Access-Control-Allow-Origin', process.env.ALLOWED_ORIGIN);\nres.setHeader('Vary', 'Origin');",
         "모든 오리진에서 Cross-Origin 요청이 허용돼 CSRF 및 데이터 유출이 가능합니다."),
        ("app.use(cors());  // default: allow all",
         "app.use(cors({ origin: ALLOWED_ORIGINS, credentials: false }));",
         "cors() 기본값은 모든 오리진을 허용해 신뢰할 수 없는 도메인에서 API 접근이 가능합니다."),
        ("app.use(cors({\n  origin: req.headers.origin,\n  credentials: true\n}));",
         "app.use(cors({\n  origin: (origin, cb) => cb(null, ALLOWED_ORIGINS.includes(origin)),\n  credentials: true\n}));",
         "요청 헤더의 Origin을 그대로 허용해 어떤 사이트에서도 자격증명 포함 요청이 가능합니다."),
    ]
    for code, fix, atk in cases:
        out.append(_make_sample("Node.js / Express", code,
            "CWE-942 Permissive CORS Policy", "MEDIUM", 6.5, atk, fix))
    # Java @CrossOrigin
    for origins in ["\"*\"", "\"*\", allowCredentials = \"true\""]:
        code = f"@CrossOrigin(origins = {origins})\n@RestController\npublic class ApiController {{}}"
        fix  = "@CrossOrigin(origins = \"https://app.example.com\", allowCredentials = \"false\")\n@RestController\npublic class ApiController {{}}"
        out.append(_make_sample("Java Spring Boot", code,
            "CWE-942 Permissive @CrossOrigin", "MEDIUM", 6.5,
            "@CrossOrigin(\"*\")로 모든 오리진 허용 시 CSRF 공격면이 넓어집니다.", fix))
    # Python Flask-CORS
    for args in ["resources={r'/*': {'origins': '*'}}",
                 "origins='*', supports_credentials=True"]:
        code = f"CORS(app, {args})"
        fix  = "CORS(app, resources={r'/api/*': {'origins': ['https://app.example.com']}}, supports_credentials=False)"
        out.append(_make_sample("Python", code,
            "CWE-942 Permissive Flask-CORS Configuration", "MEDIUM", 6.5,
            f"Flask-CORS(app, {args[:30]}...)은 임의 오리진에서 API 접근을 허용합니다.", fix))
    return out


# ══════════════════════════════════════════════════════════════════════════════
#  데이터 생성 & 저장
# ══════════════════════════════════════════════════════════════════════════════

def _nosql_injection_samples() -> list[dict]:
    """CWE-943 NoSQL Injection (MongoDB 등)"""
    out = []
    # Node.js MongoDB
    for v in ["req.body.username", "req.query.user", "req.body.email", "req.params.id", "req.body.search"]:
        code = f"db.users.find({{ username: {v} }});"
        fix  = (f"const safe = String({v}).replace(/[^a-zA-Z0-9@._-]/g, '');\n"
                f"db.users.find({{ username: safe }});")
        out.append(_make_sample("Node.js / Express", code,
            "CWE-943 NoSQL Injection", "CRITICAL", 9.8,
            f"{v}에 {{\"$ne\": null}}을 전달해 인증 우회나 전체 컬렉션 덤프가 가능합니다.", fix))
    # Node.js Mongoose
    for v in ["req.body", "req.query"]:
        code = f"User.findOne({{ username: {v}.username, password: {v}.password }});"
        fix  = (f"const {{ username, password }} = {v};\n"
                f"if (typeof username !== 'string' || typeof password !== 'string') return res.sendStatus(400);\n"
                f"User.findOne({{ username, password }});")
        out.append(_make_sample("Node.js / Express", code,
            "CWE-943 NoSQL Injection via Mongoose", "CRITICAL", 9.8,
            f"{v}에 JSON으로 {{\"$gt\": \"\"}}을 삽입해 비밀번호 없이 로그인이 가능합니다.", fix))
    # Python PyMongo
    for v in ["request.json", "data", "payload"]:
        code = f"users = db.users.find({{{v}}})"
        fix  = (f"# 사용자 입력을 직접 쿼리 dict로 사용 금지\n"
                f"name = str({v}.get('name', ''))\n"
                f"users = db.users.find({{'name': name}})")
        out.append(_make_sample("Python", code,
            "CWE-943 NoSQL Injection via PyMongo", "CRITICAL", 9.8,
            f"사용자 딕셔너리 {v}가 MongoDB 쿼리에 직접 전달돼 $where·$regex로 임의 도큐먼트 열람이 가능합니다.", fix))
    return out


def _ssti_samples() -> list[dict]:
    """CWE-94 Server-Side Template Injection (SSTI)"""
    out = []
    # Python Jinja2
    for v in ["name", "title", "message", "user_input", "query"]:
        code = (f"from jinja2 import Environment\nenv = Environment()\n"
                f"template = env.from_string('Hello ' + {v})\nresult = template.render()")
        fix  = (f"from jinja2 import Environment\nenv = Environment(autoescape=True)\n"
                f"template = env.from_string('Hello {{{{ name }}}}')\n"
                f"result = template.render(name={v})")
        out.append(_make_sample("Python", code,
            "CWE-94 Server-Side Template Injection (SSTI) via Jinja2", "CRITICAL", 9.8,
            f"공격자가 {v}에 {{{{7*7}}}} 또는 {{{{config}}}}를 삽입해 서버에서 임의 코드를 실행합니다.", fix))
    # Python Flask render_template_string
    for v in ["request.args.get('name')", "request.form['title']", "request.json.get('msg')"]:
        code = f"from flask import render_template_string\nreturn render_template_string(f'<h1>Hello {{{{{v}}}}}</h1>')"
        fix  = (f"from flask import render_template_string\nfrom markupsafe import escape\n"
                f"safe = escape({v})\nreturn render_template_string('<h1>Hello {{{{ name }}}}</h1>', name=safe)")
        out.append(_make_sample("Python", code,
            "CWE-94 SSTI via Flask render_template_string", "CRITICAL", 9.8,
            f"{v}가 템플릿 문자열에 직접 삽입돼 {{{{''.__class__.__mro__[2].__subclasses__()}}}}으로 RCE가 가능합니다.", fix))
    # Node.js Pug/EJS
    for engine, v in [("pug", "req.body.template"), ("ejs", "req.query.tpl")]:
        code = f"const html = require('{engine}').render({v}, data);"
        fix  = f"// 사용자 입력으로 템플릿 직접 렌더링 금지\nconst html = require('{engine}').renderFile('./views/safe.{engine}', data);"
        out.append(_make_sample("Node.js / Express", code,
            f"CWE-94 SSTI via {engine.upper()} with User Input", "CRITICAL", 9.8,
            f"공격자가 {v}에 악성 템플릿을 전달해 Node.js 컨텍스트에서 RCE가 가능합니다.", fix))
    return out


def _mass_assignment_samples() -> list[dict]:
    """CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes"""
    out = []
    # Python Flask/SQLAlchemy
    for model in ["User", "Product", "Order", "Account"]:
        code = (f"data = request.get_json()\n"
                f"user = {model}(**data)\ndb.session.add(user)")
        fix  = (f"data = request.get_json()\n"
                f"allowed = {{'name', 'email', 'password'}}  # 허용 필드만\n"
                f"safe = {{k: v for k, v in data.items() if k in allowed}}\n"
                f"user = {model}(**safe)\ndb.session.add(user)")
        out.append(_make_sample("Python", code,
            "CWE-915 Mass Assignment Vulnerability", "HIGH", 8.1,
            f"요청 JSON 전체를 {model} 모델에 바인딩해 role=admin 등 권한 상승 필드가 주입됩니다.", fix))
    # Node.js Mongoose
    for model in ["User", "Member", "Admin", "Profile"]:
        code = (f"const user = new {model}(req.body);\nawait user.save();")
        fix  = (f"const {{ name, email, password }} = req.body;\n"
                f"const user = new {model}({{ name, email, password }});\nawait user.save();")
        out.append(_make_sample("Node.js / Express", code,
            "CWE-915 Mass Assignment via Mongoose", "HIGH", 8.1,
            f"req.body 전체를 {model} 생성자에 전달해 isAdmin:true 등 숨겨진 필드를 주입합니다.", fix))
    # Java Spring Boot @RequestBody
    for entity in ["UserEntity", "ProductEntity", "RoleEntity"]:
        code = (f"@PostMapping(\"/update\")\npublic ResponseEntity<?> update(@RequestBody {entity} entity) {{\n"
                f"    repository.save(entity);\n    return ResponseEntity.ok().build();\n}}")
        fix  = (f"@PostMapping(\"/update\")\npublic ResponseEntity<?> update(@RequestBody @Validated UpdateDto dto,\n"
                f"        @AuthenticationPrincipal UserDetails user) {{\n"
                f"    {entity} entity = mapper.toEntity(dto);\n"
                f"    entity.setId(user.getId());  // ID는 인증 정보에서\n"
                f"    repository.save(entity);\n    return ResponseEntity.ok().build();\n}}")
        out.append(_make_sample("Java Spring Boot", code,
            "CWE-915 Mass Assignment via @RequestBody", "HIGH", 8.1,
            f"@RequestBody로 {entity} 전체를 바인딩해 role, isAdmin 등 내부 필드가 조작됩니다.", fix))
    return out


def _crypto_samples() -> list[dict]:
    """CWE-330/338 Weak Random + CWE-327 Broken Crypto"""
    out = []
    # Weak random
    for lang, code, fix, atk in [
        ("Python",
         "import random\ntoken = random.randint(0, 999999)",
         "import secrets\ntoken = secrets.randbelow(10**6)",
         "random.randint()은 시드 예측이 가능해 생성된 토큰을 브루트포스로 추측합니다."),
        ("Python",
         "import random\nsession_id = ''.join(random.choices('abcdef0123456789', k=16))",
         "import secrets\nsession_id = secrets.token_hex(16)",
         "random.choices()는 암호학적으로 안전하지 않아 세션 ID 예측이 가능합니다."),
        ("Node.js / Express",
         "const token = Math.random().toString(36).slice(2);",
         "const { randomBytes } = require('crypto');\nconst token = randomBytes(32).toString('hex');",
         "Math.random()은 암호학적으로 취약해 생성된 토큰을 통계적으로 예측합니다."),
        ("Java Spring Boot",
         "String token = String.valueOf(new Random().nextLong());",
         "String token = new BigInteger(130, new SecureRandom()).toString(32);",
         "java.util.Random은 선형 합동 생성기로 출력 시퀀스를 역계산할 수 있습니다."),
        ("PHP",
         "<?php\n$token = rand(100000, 999999);",
         "<?php\n$token = bin2hex(random_bytes(16));",
         "rand()는 PRNG로 세션 토큰·CSRF 토큰 예측 공격이 가능합니다."),
    ]:
        out.append(_make_sample(lang, code,
            "CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator", "HIGH", 7.5, atk, fix))
    # DES/3DES/RC4
    for lang, code, fix, atk in [
        ("Python",
         "from Crypto.Cipher import DES\ncipher = DES.new(key, DES.MODE_ECB)\nenc = cipher.encrypt(data)",
         "from Crypto.Cipher import AES\nfrom Crypto.Random import get_random_bytes\niv = get_random_bytes(16)\ncipher = AES.new(key, AES.MODE_GCM)\nenc, tag = cipher.encrypt_and_digest(data)",
         "DES는 56비트 키로 현대 하드웨어에서 브루트포스 복호화가 몇 시간 내에 가능합니다."),
        ("Java Spring Boot",
         "Cipher cipher = Cipher.getInstance(\"DES/ECB/PKCS5Padding\");\ncipher.init(Cipher.ENCRYPT_MODE, key);",
         "Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");\nbyte[] iv = SecureRandom.getInstanceStrong().generateSeed(12);\ncipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));",
         "DES/ECB는 동일 평문이 동일 암호문을 생성해 패턴 분석 공격이 가능합니다."),
        ("Node.js / Express",
         "const cipher = crypto.createCipher('rc4', key);\nconst enc = cipher.update(data) + cipher.final();",
         "const iv = crypto.randomBytes(12);\nconst cipher = crypto.createCipheriv('aes-256-gcm', key, iv);\nconst enc = Buffer.concat([cipher.update(data), cipher.final()]);",
         "RC4는 편향된 키스트림으로 BEAST·CRIME 공격에 취약해 복호화가 가능합니다."),
    ]:
        out.append(_make_sample(lang, code,
            "CWE-327 Use of a Broken or Risky Cryptographic Algorithm", "HIGH", 7.4, atk, fix))
    # ECB mode
    for lang, code, fix in [
        ("Python",
         "from Crypto.Cipher import AES\ncipher = AES.new(key, AES.MODE_ECB)\nenc = cipher.encrypt(padded_data)",
         "from Crypto.Cipher import AES\nfrom Crypto.Random import get_random_bytes\niv = get_random_bytes(16)\ncipher = AES.new(key, AES.MODE_CBC, iv)\nenc = iv + cipher.encrypt(padded_data)"),
        ("Java Spring Boot",
         "Cipher c = Cipher.getInstance(\"AES/ECB/PKCS5Padding\");\nc.init(Cipher.ENCRYPT_MODE, secretKey);",
         "Cipher c = Cipher.getInstance(\"AES/GCM/NoPadding\");\nbyte[] iv = new byte[12];\nSecureRandom.getInstanceStrong().nextBytes(iv);\nc.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));"),
    ]:
        out.append(_make_sample(lang, code,
            "CWE-327 AES-ECB Mode Weakness", "HIGH", 7.4,
            "AES-ECB는 동일 블록을 동일 암호문으로 변환해 패턴 분석 및 재전송 공격이 가능합니다.", fix))
    return out


def _session_samples() -> list[dict]:
    """CWE-384 Session Fixation + CWE-613 Insufficient Session Expiration"""
    out = []
    # Session fixation
    for lang, code, fix, atk in [
        ("Node.js / Express",
         "app.post('/login', (req, res) => {\n    req.session.user = authenticatedUser;\n    res.redirect('/dashboard');\n});",
         "app.post('/login', (req, res) => {\n    req.session.regenerate((err) => {\n        req.session.user = authenticatedUser;\n        res.redirect('/dashboard');\n    });\n});",
         "로그인 후 세션 ID를 재생성하지 않아 공격자가 미리 설정한 세션 ID로 계정을 하이재킹합니다."),
        ("PHP",
         "session_start();\n$_SESSION['user'] = $authenticated_user;",
         "session_start();\nsession_regenerate_id(true);  // 로그인 후 세션 ID 재생성\n$_SESSION['user'] = $authenticated_user;",
         "session_regenerate_id() 없이 세션 고정 공격으로 공격자가 피해자 세션을 사전 설정합니다."),
    ]:
        out.append(_make_sample(lang, code,
            "CWE-384 Session Fixation", "HIGH", 8.8, atk, fix))
    # Session expiry
    for lang, code, fix, atk in [
        ("Node.js / Express",
         "app.use(session({\n    secret: process.env.SECRET,\n    // no maxAge\n}));",
         "app.use(session({\n    secret: process.env.SECRET,\n    cookie: { maxAge: 30 * 60 * 1000, httpOnly: true, secure: true },\n    rolling: true,\n}));",
         "세션 만료 설정이 없어 로그아웃하지 않은 브라우저에서 세션이 영구 유효합니다."),
        ("Java Spring Boot",
         "@Bean\npublic HttpSessionEventPublisher httpSessionEventPublisher() {\n    return new HttpSessionEventPublisher();\n}\n// session timeout not set",
         "server:\n  servlet:\n    session:\n      timeout: 30m  # application.yml에 세션 만료 설정",
         "세션 타임아웃이 없어 공유 컴퓨터에서 로그아웃 없이 이전 사용자 세션이 재사용됩니다."),
    ]:
        out.append(_make_sample(lang, code,
            "CWE-613 Insufficient Session Expiration", "MEDIUM", 6.5, atk, fix))
    # No httpOnly / secure cookie
    for lang, code, fix in [
        ("Node.js / Express",
         "res.cookie('session', token);  // no httpOnly, no secure",
         "res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'Strict' });"),
        ("PHP",
         "setcookie('session', $token);",
         "setcookie('session', $token, ['httponly' => true, 'secure' => true, 'samesite' => 'Strict']);"),
        ("Java Spring Boot",
         "server.servlet.session.cookie.http-only=false\nserver.servlet.session.cookie.secure=false",
         "server.servlet.session.cookie.http-only=true\nserver.servlet.session.cookie.secure=true\nserver.servlet.session.cookie.same-site=Strict"),
    ]:
        out.append(_make_sample(lang, code,
            "CWE-614 Sensitive Cookie Without 'Secure' Attribute", "MEDIUM", 5.9,
            "httpOnly·secure 속성 없는 쿠키는 XSS로 탈취되거나 HTTP에서 노출됩니다.", fix))
    return out


def _format_string_samples() -> list[dict]:
    """CWE-134 Format String Vulnerability"""
    out = []
    c_cases = [
        ("printf(user_input);", 'printf("%s", user_input);',
         "printf()에 사용자 입력이 포맷 문자열로 전달돼 %n으로 임의 메모리 쓰기가 가능합니다."),
        ("fprintf(stderr, user_msg);", 'fprintf(stderr, "%s", user_msg);',
         "fprintf()에 포맷 문자열 삽입 시 스택 메모리 누출 또는 임의 쓰기가 가능합니다."),
        ("sprintf(buf, user_data);", 'snprintf(buf, sizeof(buf), "%s", user_data);',
         "sprintf()에 포맷 문자열 공격으로 버퍼 오버플로우 및 임의 코드 실행이 가능합니다."),
        ("syslog(LOG_INFO, user_input);", 'syslog(LOG_INFO, "%s", user_input);',
         "syslog()에 %n이 포함된 입력 시 임의 메모리 위치에 쓰기가 가능합니다."),
        ("char buf[256];\nvsprintf(buf, user_fmt, args);",
         "char buf[256];\nvsnprintf(buf, sizeof(buf), \"%s\", args);",
         "vsprintf에 사용자 지정 포맷으로 스택 내용 누출 및 오버플로우가 가능합니다."),
    ]
    for code, fix, atk in c_cases:
        out.append(_make_sample("C", code,
            "CWE-134 Use of Externally-Controlled Format String", "HIGH", 8.4, atk, fix))
    # Python %
    for v in ["user_name", "query", "message", "input_str"]:
        code = f"log_msg = 'User: %s' % {v}\nprint(log_msg)"
        fix  = f"log_msg = f'User: {{str({v})}}'\nprint(log_msg)"
        out.append(_make_sample("Python", code,
            "CWE-134 Format String with User Input", "LOW", 3.7,
            f"% 포맷팅에 {v}가 사용돼 %()s 형태의 딕셔너리 키 누출 가능성이 있습니다.", fix))
    return out


def _jwt_samples() -> list[dict]:
    """JWT 취약점 추가"""
    out = []
    # None algorithm
    cases = [
        ("Node.js / Express",
         "jwt.decode(token, { complete: true });  // no verify",
         "jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });",
         "jwt.decode()는 서명 검증 없이 토큰을 디코드해 위조된 토큰이 그대로 신뢰됩니다."),
        ("Python",
         "import jwt\npayload = jwt.decode(token, options={'verify_signature': False})",
         "import jwt\npayload = jwt.decode(token, SECRET, algorithms=['HS256'])",
         "verify_signature=False로 서명 검증을 비활성화해 임의 페이로드 위조가 가능합니다."),
        ("Java Spring Boot",
         "Jwts.parser().parseClaimsJwt(token);  // unsigned only",
         "Jwts.parserBuilder().setSigningKey(secret).build().parseClaimsJws(token);",
         "parseClaimsJwt()는 unsigned JWT만 처리하지만 서명 알고리즘 none 공격에 취약합니다."),
    ]
    for lang, code, fix, atk in cases:
        out.append(_make_sample(lang, code,
            "CWE-287 JWT Signature Verification Bypass", "CRITICAL", 9.8, atk, fix))
    # Weak secret
    for secret in ["secret", "password", "123456", "jwt_secret", "token"]:
        code = f"jwt.sign(payload, '{secret}', {{ expiresIn: '24h' }});"
        fix  = "jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });"
        out.append(_make_sample("Node.js / Express", code,
            "CWE-798 Hard-coded Weak JWT Secret", "HIGH", 7.5,
            f"'{secret}' 같은 예측 가능한 비밀 키로 서명된 토큰은 무차별 대입으로 위조됩니다.", fix))
    return out


def _prototype_pollution_samples() -> list[dict]:
    """CWE-1321 Prototype Pollution"""
    out = []
    # lodash merge
    for v in ["req.body", "req.query", "userConfig", "options", "data"]:
        code = f"const _ = require('lodash');\n_.merge(target, {v});"
        fix  = f"const _ = require('lodash');\n// lodash < 4.17.12는 취약 — 업데이트 후 사용\nconst safe = JSON.parse(JSON.stringify({v}));  // prototype 프로퍼티 제거\n_.mergeWith(target, safe, (obj, src) => {{\n    if (src && src.__proto__) return {{}};\n}});"
        out.append(_make_sample("Node.js / Express", code,
            "CWE-1321 Prototype Pollution via lodash.merge", "HIGH", 8.1,
            f"공격자가 {v}에 {{\"__proto__\": {{\"isAdmin\": true}}}}를 전달해 모든 객체에 속성을 주입합니다.", fix))
    # Manual recursive merge
    for v in ["userInput", "params", "config", "settings"]:
        code = (f"function merge(dst, src) {{\n"
                f"    for (let key in src) dst[key] = src[key];\n"
                f"}}\nmerge(config, {v});")
        fix  = (f"function merge(dst, src) {{\n"
                f"    for (let key of Object.keys(src)) {{\n"
                f"        if (key === '__proto__' || key === 'constructor') continue;\n"
                f"        dst[key] = src[key];\n"
                f"    }}\n"
                f"}}\nmerge(config, {v});")
        out.append(_make_sample("Node.js / Express", code,
            "CWE-1321 Prototype Pollution via Manual Merge", "HIGH", 8.1,
            f"for...in 루프로 {v}를 병합 시 __proto__ 키가 Object.prototype을 오염시킵니다.", fix))
    # JSON.parse + Object.assign
    for v in ["body", "payload", "data", "opts"]:
        code = f"const parsed = JSON.parse({v});\nObject.assign(defaultConfig, parsed);"
        fix  = (f"const parsed = JSON.parse({v});\n"
                f"const safe = Object.create(null);\n"
                f"for (const k of Object.keys(parsed)) safe[k] = parsed[k];\n"
                f"Object.assign(defaultConfig, safe);")
        out.append(_make_sample("Node.js / Express", code,
            "CWE-1321 Prototype Pollution via Object.assign", "MEDIUM", 6.5,
            f"JSON.parse + Object.assign으로 {v}의 __proto__ 키가 기본 config를 오염시킵니다.", fix))
    return out


def _api_key_samples() -> list[dict]:
    """CWE-522 Insufficiently Protected Credentials (API Key exposure)"""
    out = []
    # Exposed in URL
    for svc in ["stripe", "twilio", "sendgrid", "openai", "aws"]:
        code = f"fetch(`https://api.{svc}.com/v1/charges?api_key=sk_live_abc123xyz`);"
        fix  = (f"fetch('https://api.{svc}.com/v1/charges', {{\n"
                f"    headers: {{ 'Authorization': `Bearer ${{process.env.{svc.upper()}_API_KEY}}` }}\n"
                f"}});")
        out.append(_make_sample("React / Next.js", code,
            "CWE-522 API Key Exposed in URL", "HIGH", 7.5,
            f"{svc} API 키가 URL 쿼리 파라미터에 노출돼 서버 로그·브라우저 히스토리에 기록됩니다.", fix))
    # Exposed in git / dotenv
    for key in ["OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY", "STRIPE_SECRET_KEY", "TWILIO_AUTH_TOKEN"]:
        code = f"# .env\n{key}=sk-prod-realvalue123abc"
        fix  = (f"# .gitignore에 .env 추가\n# .env.example (값 없이 키만)\n{key}=\n# 실제 값은 CI/CD 환경 변수 또는 시크릿 매니저에서 주입")
        out.append(_make_sample("GitHub Actions YAML", code,
            "CWE-522 API Key Committed to Repository", "CRITICAL", 9.1,
            f".env 파일의 {key}가 git에 커밋돼 저장소 접근 권한이 있는 누구나 키를 탈취합니다.", fix))
    # Front-end exposure
    for key in ["NEXT_PUBLIC_API_KEY", "REACT_APP_SECRET", "VUE_APP_TOKEN"]:
        code = f"// 프런트엔드 코드\nconst key = process.env.{key};"
        fix  = (f"// 민감한 키는 백엔드 API를 통해서만 접근\n"
                f"// 프런트엔드에서는 NEXT_PUBLIC_ 없이 사용 불가\n"
                f"// 클라이언트 사이드 코드에 시크릿 노출 금지")
        out.append(_make_sample("React / Next.js", code,
            "CWE-522 API Key Exposed in Client-Side Code", "HIGH", 7.5,
            f"{key}가 번들에 포함돼 브라우저 개발자 도구로 누구나 키 값을 확인합니다.", fix))
    return out


def _xxss_advanced_samples() -> list[dict]:
    """추가 XSS 변형 — CSP 우회, DOM Clobbering, mXSS"""
    out = []
    # Go html/template wrong usage
    for v in ["r.FormValue(\"name\")", "r.URL.Query().Get(\"q\")", "userInput"]:
        code = (f"import \"html/template\"\n"
                f"t := template.Must(template.New(\"\").Parse(\"<div>\" + {v} + \"</div>\"))\n"
                f"t.Execute(w, nil)")
        fix  = (f"import \"html/template\"\n"
                f"t := template.Must(template.New(\"\").Parse(\"<div>{{{{.}}}}</div>\"))\n"
                f"t.Execute(w, {v})")
        out.append(_make_sample("Go", code,
            "CWE-79 XSS in Go html/template via String Concatenation", "HIGH", 7.2,
            f"html/template 문자열 연결 시 {v}의 자동 이스케이프가 우회돼 XSS가 발생합니다.", fix))
    # Ruby ERB
    for v in ["params[:name]", "params[:search]", "request.query_string"]:
        code = f"@output = {v}\n# template: <%= @output.html_safe %>"
        fix  = f"@output = {v}\n# template: <%= @output %>"
        out.append(_make_sample("Ruby", code,
            "CWE-79 XSS via html_safe in Rails", "HIGH", 7.2,
            f"html_safe로 마킹된 {v}의 HTML 이스케이프가 비활성화돼 XSS가 가능합니다.", fix))
    # TypeScript Next.js API
    for v in ["req.query.message", "req.body.html", "req.query.content"]:
        code = (f"export default function handler(req, res) {{\n"
                f"    res.setHeader('Content-Type', 'text/html');\n"
                f"    res.send(`<p>${{{v}}}</p>`);\n}}")
        fix  = (f"import he from 'he';\nexport default function handler(req, res) {{\n"
                f"    res.setHeader('Content-Type', 'text/html');\n"
                f"    res.send(`<p>${{he.encode(String({v}))}}</p>`);\n}}")
        out.append(_make_sample("React / Next.js", code,
            "CWE-79 XSS in Next.js API Route", "HIGH", 7.2,
            f"Next.js API Route에서 {v}가 이스케이프 없이 HTML 응답에 삽입돼 XSS가 발생합니다.", fix))
    # innerHTML
    for v in ["data.content", "response.html", "userMessage", "post.body"]:
        code = f"element.innerHTML = {v};"
        fix  = f"import DOMPurify from 'dompurify';\nelement.innerHTML = DOMPurify.sanitize({v});"
        out.append(_make_sample("React / Next.js", code,
            "CWE-79 DOM XSS via innerHTML", "HIGH", 7.2,
            f"innerHTML에 {v}를 직접 삽입해 DOM 기반 XSS가 발생합니다.", fix))
    # document.write
    for v in ["location.hash.slice(1)", "location.search", "decodeURI(location.hash)"]:
        code = f"document.write({v});"
        fix  = (f"const safeText = document.createTextNode({v});\n"
                f"document.body.appendChild(safeText);")
        out.append(_make_sample("React / Next.js", code,
            "CWE-79 DOM XSS via document.write", "HIGH", 7.2,
            f"document.write({v})로 URL 조각 값이 DOM에 직접 쓰여 XSS가 발생합니다.", fix))
    return out


def _path_trav_advanced_samples() -> list[dict]:
    """경로 탐색 추가 변형"""
    out = []
    # Go
    for v in ["r.URL.Query().Get(\"file\")", "r.FormValue(\"path\")"]:
        code = (f"filePath := filepath.Join(\"/var/data/\", {v})\n"
                f"data, _ := os.ReadFile(filePath)")
        fix  = (f"fname := filepath.Base({v})\n"
                f"safe := filepath.Join(\"/var/data/\", fname)\n"
                f"if !strings.HasPrefix(safe, \"/var/data/\") {{\n"
                f"    http.Error(w, \"Forbidden\", 403)\n    return\n}}\n"
                f"data, _ := os.ReadFile(safe)")
        out.append(_make_sample("Go", code,
            "CWE-22 Path Traversal in Go", "HIGH", 7.5,
            f"filepath.Join만으로는 {v}의 ../을 막지 못해 /var/data/ 밖 파일에 접근합니다.", fix))
    # Ruby Sinatra
    for v in ["params[:file]", "params[:name]"]:
        code = f"send_file File.join('/public/', {v})"
        fix  = (f"fname = File.basename({v})\n"
                f"safe = File.expand_path(File.join('/public/', fname))\n"
                f"raise Forbidden unless safe.start_with?('/public/')\n"
                f"send_file safe")
        out.append(_make_sample("Ruby", code,
            "CWE-22 Path Traversal in Ruby Sinatra", "HIGH", 7.5,
            f"send_file에 {v}가 직접 전달돼 ../를 통해 /public/ 외부 파일이 노출됩니다.", fix))
    # Spring – ResourceLoader
    for v in ["request.getParameter(\"doc\")", "fileName"]:
        code = (f"Resource r = resourceLoader.getResource(\"classpath:docs/\" + {v});\n"
                f"return r.getInputStream();")
        fix  = (f"String safe = Paths.get({v}).getFileName().toString();\n"
                f"Resource r = resourceLoader.getResource(\"classpath:docs/\" + safe);\n"
                f"if (!safe.matches(\"[a-zA-Z0-9._-]+\")) throw new SecurityException();\n"
                f"return r.getInputStream();")
        out.append(_make_sample("Java Spring Boot", code,
            "CWE-22 Path Traversal via Spring ResourceLoader", "HIGH", 7.5,
            f"classpath:docs/{v} 경로 결합 시 ../으로 classpath 루트 파일을 읽습니다.", fix))
    return out


def _sqli_orm_samples() -> list[dict]:
    """ORM 기반 SQL 취약점 추가"""
    out = []
    # Hibernate native query
    for v in ["username", "email", "status", "role"]:
        code = (f'String q = "SELECT u FROM User u WHERE u.{v}=\'" + {v} + "\'";\n'
                f'return em.createQuery(q).getResultList();')
        fix  = (f'TypedQuery<User> q = em.createQuery(\n'
                f'    "SELECT u FROM User u WHERE u.{v}=:val", User.class);\n'
                f'return q.setParameter("val", {v}).getResultList();')
        out.append(_make_sample("Java Spring Boot", code,
            "CWE-89 SQL Injection via Hibernate JPQL", "CRITICAL", 9.8,
            f"JPQL 문자열에 {v}가 직접 삽입돼 HQL 인젝션으로 데이터 추출이 가능합니다.", fix))
    # Django ORM raw()
    for v in ["username", "search", "query"]:
        code = f"users = User.objects.raw(f\"SELECT * FROM users WHERE name = '{{request.GET['{v}']}}'\");"
        fix  = f"users = User.objects.filter(name=request.GET['{v}'])"
        out.append(_make_sample("Python", code,
            "CWE-89 SQL Injection via Django ORM raw()", "CRITICAL", 9.8,
            f"raw() 쿼리에 request.GET['{v}']를 직접 삽입해 SQL 인젝션이 가능합니다.", fix))
    # SQLAlchemy text()
    for v in ["name", "email", "search"]:
        code = (f"from sqlalchemy import text\n"
                f"result = db.execute(text(f\"SELECT * FROM users WHERE {v}='{{user_{v}}}'\"))")
        param_dict = "{'" + v + "': user_" + v + "}"
        fix  = (f"from sqlalchemy import text\n"
                f"result = db.execute(text('SELECT * FROM users WHERE {v}=:{v}'), {param_dict})")
        out.append(_make_sample("Python", code,
            "CWE-89 SQL Injection via SQLAlchemy text()", "CRITICAL", 9.8,
            f"SQLAlchemy text()에 user_{v}가 직접 포맷팅돼 SQL 인젝션이 가능합니다.", fix))
    # Sequelize where with raw
    for v in ["req.query.name", "req.body.search", "req.params.id"]:
        code = f"User.findAll({{ where: db.literal(`name='${{{v}}}'`) }});"
        fix  = f"User.findAll({{ where: {{ name: {v} }} }});"
        out.append(_make_sample("Node.js / Express", code,
            "CWE-89 SQL Injection via Sequelize.literal()", "CRITICAL", 9.8,
            f"Sequelize.literal()에 {v}가 직접 삽입돼 SQL 메타문자로 인젝션이 가능합니다.", fix))
    return out


def _ldap_xpath_samples() -> list[dict]:
    """CWE-90 LDAP Injection + CWE-643 XPath Injection"""
    out = []
    # LDAP Injection
    for lang, v, code, fix in [
        ("Java Spring Boot", "username",
         "String filter = \"(uid=\" + username + \")\";\nctx.search(\"dc=example,dc=com\", filter, ctrl);",
         "String safe = username.replaceAll(\"[()\\\\\\\\|&!*=<>~]\", \"\");\nString filter = \"(uid=\" + safe + \")\";\nctx.search(\"dc=example,dc=com\", filter, ctrl);"),
        ("Python", "user_input",
         "filter_str = f'(cn={user_input})'\nconn.search('dc=example,dc=com', filter_str)",
         "from ldap3.utils.conv import escape_filter_chars\nsafe = escape_filter_chars(user_input)\nfilter_str = f'(cn={safe})'\nconn.search('dc=example,dc=com', filter_str)"),
        ("PHP", "$username",
         "$filter = '(uid=' . $username . ')';\nldap_search($conn, $dn, $filter);",
         "$safe = ldap_escape($username, '', LDAP_ESCAPE_FILTER);\n$filter = '(uid=' . $safe . ')';\nldap_search($conn, $dn, $filter);"),
    ]:
        out.append(_make_sample(lang, code,
            "CWE-90 LDAP Injection", "HIGH", 8.1,
            f"LDAP 필터에 {v}가 직접 삽입돼 )(uid=*) 주입으로 모든 계정을 인증 없이 열람합니다.", fix))
    # LDAP additional
    for lang, v, code, fix in [
        ("Node.js / Express", "req.body.username",
         "const filter = `(uid=${req.body.username})`;\nclient.search('dc=corp,dc=com', { filter }, cb);",
         "const safe = req.body.username.replace(/[()\\\\|&!=<>~*]/g, '');\nconst filter = `(uid=${safe})`;\nclient.search('dc=corp,dc=com', { filter }, cb);"),
        ("Java Spring Boot", "email",
         "String q = \"(&(objectClass=person)(mail=\" + email + \"))\";\nctx.search(base, q, ctrl);",
         "String safe = email.replaceAll(\"[()\\\\\\\\|&!*=<>~]\", \"\");\nString q = \"(&(objectClass=person)(mail=\" + safe + \"))\";\nctx.search(base, q, ctrl);"),
        ("Python", "group_name",
         "conn.search('dc=corp,dc=com', f'(cn={group_name})')",
         "from ldap3.utils.conv import escape_filter_chars\nconn.search('dc=corp,dc=com', f'(cn={escape_filter_chars(group_name)})')"),
    ]:
        out.append(_make_sample(lang, code,
            "CWE-90 LDAP Injection", "HIGH", 8.1,
            f"LDAP 필터 {v}에 )(objectClass=* 주입으로 전체 디렉터리 정보가 노출됩니다.", fix))
    # XPath Injection
    for lang, v, code, fix in [
        ("Java Spring Boot", "username",
         "String xp = \"//user[name='\" + username + \"']\";\nNodeList nodes = (NodeList) xpath.evaluate(xp, doc, XPathConstants.NODESET);",
         "String xp = \"//user[name=$username]\";\nxpath.setXPathVariableResolver(var -> var.getLocalPart().equals(\"username\") ? username : null);\nNodeList nodes = (NodeList) xpath.evaluate(xp, doc, XPathConstants.NODESET);"),
        ("Python", "user_input",
         "expr = f\"//item[name='{user_input}']\"\ntree.xpath(expr)",
         "from lxml import etree\nexpr = \"//item[name=$name]\"\ntree.xpath(expr, name=user_input)"),
        ("Node.js / Express", "req.body.user",
         "const expr = `//users/user[name='${req.body.user}']`;\nconst result = doc.evaluate(expr, doc, null, XPathResult.ANY_TYPE, null);",
         "// 파라미터화된 XPath 사용 또는 입력값 이스케이프\nconst safe = req.body.user.replace(/['\\\\']/g, '');\nconst expr = `//users/user[name='${safe}']`;\nconst result = doc.evaluate(expr, doc, null, XPathResult.ANY_TYPE, null);"),
    ]:
        out.append(_make_sample(lang, code,
            "CWE-643 XPath Injection", "HIGH", 7.5,
            f"XPath 쿼리에 {v}가 직접 삽입돼 ' or '1'='1 주입으로 모든 노드가 반환됩니다.", fix))
    return out


def _misc_vuln_samples() -> list[dict]:
    """기타 취약점 — XML, Email Header Injection, HTTP Param Pollution"""
    out = []
    # Email Header Injection (CWE-93)
    for lang, v, code, fix in [
        ("Python", "subject",
         "import smtplib\nmsg = f'Subject: {subject}\\n\\n{body}'\nsmtp.sendmail(frm, to, msg)",
         "import re\nsubject = re.sub(r'[\\r\\n]', '', subject)\nmsg = f'Subject: {subject}\\n\\n{body}'\nsmtp.sendmail(frm, to, msg)"),
        ("PHP", "$subject",
         "mail($to, $subject, $message);",
         "$subject = str_replace(['\\r', '\\n'], '', $subject);\nmail($to, $subject, $message);"),
        ("Node.js / Express", "req.body.subject",
         "transporter.sendMail({ to, subject: req.body.subject, text: body });",
         "const subject = req.body.subject.replace(/[\\r\\n]/g, '');\ntransporter.sendMail({ to, subject, text: body });"),
    ]:
        out.append(_make_sample(lang, code,
            "CWE-93 Email Header Injection", "MEDIUM", 5.3,
            f"{v}에 \\r\\n을 삽입해 BCC 헤더를 추가하거나 스팸 릴레이를 유발합니다.", fix))
    # HTTP Response Splitting (CWE-113)
    for lang, code, fix in [
        ("Node.js / Express",
         "res.setHeader('Location', req.query.url);",
         "const url = req.query.url.replace(/[\\r\\n]/g, '');\nres.setHeader('Location', url);"),
        ("Python",
         "redirect_url = request.args.get('url')\nreturn redirect(redirect_url)",
         "import re\nredirect_url = re.sub(r'[\\r\\n]', '', request.args.get('url', '/'))\nreturn redirect(redirect_url)"),
        ("Java Spring Boot",
         "response.setHeader(\"Location\", request.getParameter(\"url\"));",
         "String url = request.getParameter(\"url\").replaceAll(\"[\\\\r\\\\n]\", \"\");\nresponse.setHeader(\"Location\", url);"),
    ]:
        out.append(_make_sample(lang, code,
            "CWE-113 HTTP Response Splitting", "MEDIUM", 5.9,
            "URL에 \\r\\n을 삽입해 응답 헤더를 분리하고 추가 HTTP 헤더나 응답 본문을 주입합니다.", fix))
    # Insecure TLS/SSL (CWE-295)
    for lang, code, fix in [
        ("Python",
         "import requests\nrequests.get(url, verify=False)",
         "import requests\nrequests.get(url, verify=True)  # 또는 verify='/path/to/ca-bundle.crt'"),
        ("Node.js / Express",
         "https.request({ rejectUnauthorized: false });",
         "https.request({ rejectUnauthorized: true });  // 기본값 true 유지"),
        ("Java Spring Boot",
         "SSLContext ctx = SSLContext.getInstance(\"TLS\");\nctx.init(null, new TrustManager[]{ new X509TrustManager() {\n    public void checkClientTrusted(X509Certificate[] c, String a) {}\n    public void checkServerTrusted(X509Certificate[] c, String a) {}\n    public X509Certificate[] getAcceptedIssuers() { return null; }\n}}, null);",
         "// TrustAllCerts 대신 정규 CA 인증서 신뢰\nSSLContext ctx = SSLContext.getDefault();  // 시스템 기본 TrustStore 사용"),
    ]:
        out.append(_make_sample(lang, code,
            "CWE-295 Improper Certificate Validation", "HIGH", 7.4,
            "TLS 인증서 검증을 비활성화해 중간자 공격으로 암호화된 통신이 도청됩니다.", fix))
    # Regex injection → already in redos but different angle
    for lang, code, fix in [
        ("Node.js / Express",
         "if (new RegExp(req.query.filter).test(filename)) serve(filename);",
         "const safe = req.query.filter.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&');\nif (new RegExp('^' + safe + '$').test(filename)) serve(filename);"),
        ("Python",
         "import re\nif re.search(request.args.get('pattern'), content):\n    return content",
         "import re\npattern = re.escape(request.args.get('pattern', ''))\nif re.search(pattern, content):\n    return content"),
    ]:
        out.append(_make_sample(lang, code,
            "CWE-625 Permissive Regular Expression with User Input", "MEDIUM", 6.1,
            "사용자 제공 패턴을 이스케이프 없이 정규식에 사용해 ReDoS 또는 경로 조작이 가능합니다.", fix))
    return out


def _insecure_headers_samples() -> list[dict]:
    """CWE-116 / CWE-693 보안 헤더 누락"""
    out = []
    header_cases = [
        ("Node.js / Express",
         "// 보안 헤더 없는 Express 앱\nconst app = express();\napp.use(router);",
         "const helmet = require('helmet');\napp.use(helmet());  // X-Frame-Options, CSP, HSTS 등 자동 설정",
         "보안 헤더(HSTS, CSP, X-Frame-Options)가 없어 클릭재킹·XSS·다운그레이드 공격에 취약합니다.",
         "CWE-693 Missing Security Headers"),
        ("Node.js / Express",
         "res.setHeader('X-Powered-By', 'Express');",
         "app.disable('x-powered-by');  // 서버 기술 스택 정보 숨기기",
         "X-Powered-By 헤더로 서버 프레임워크가 노출돼 알려진 취약점을 타겟 공격합니다.",
         "CWE-200 Server Technology Disclosure via X-Powered-By"),
        ("Python",
         "@app.after_request\ndef no_security_headers(response):\n    return response",
         "@app.after_request\ndef set_security_headers(response):\n    response.headers['X-Content-Type-Options'] = 'nosniff'\n    response.headers['X-Frame-Options'] = 'DENY'\n    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'\n    response.headers['Content-Security-Policy'] = \"default-src 'self'\"\n    return response",
         "Flask 응답에 보안 헤더가 없어 MIME 스니핑·클릭재킹·MITM 공격이 가능합니다.",
         "CWE-693 Missing Security Headers in Flask"),
        ("Java Spring Boot",
         "@Override\nprotected void configure(HttpSecurity http) throws Exception {\n    http.headers().disable();\n}",
         "@Override\nprotected void configure(HttpSecurity http) throws Exception {\n    http.headers()\n        .contentSecurityPolicy(\"default-src 'self'\")\n        .and().frameOptions().deny()\n        .xssProtection().block(true);\n}",
         "headers().disable()로 Spring Security의 기본 보안 헤더가 모두 제거됩니다.",
         "CWE-693 Spring Security Headers Disabled"),
        ("Node.js / Express",
         "res.setHeader('Access-Control-Allow-Origin', '*');\nres.setHeader('Access-Control-Allow-Credentials', 'true');",
         "res.setHeader('Access-Control-Allow-Origin', process.env.ALLOWED_ORIGIN);\n// credentials: true는 와일드카드 오리진과 함께 사용 불가",
         "와일드카드 오리진과 Allow-Credentials: true 조합으로 민감한 쿠키를 포함한 크로스오리진 요청이 가능합니다.",
         "CWE-942 CORS with Wildcard Origin and Credentials"),
    ]
    for lang, code, fix, atk, vuln in header_cases:
        out.append(_make_sample(lang, code, vuln, "MEDIUM", 6.1, atk, fix))

    # CSP bypass
    csp_cases = [
        ("Node.js / Express",
         "res.setHeader('Content-Security-Policy', \"default-src *; script-src *\");",
         "res.setHeader('Content-Security-Policy', \"default-src 'self'; script-src 'self' 'nonce-{random}'; object-src 'none'\");",
         "script-src *는 모든 외부 도메인의 스크립트를 허용해 CSP가 XSS를 전혀 차단하지 못합니다.",
         "CWE-116 Overly Permissive Content Security Policy"),
        ("Node.js / Express",
         "res.setHeader('Content-Security-Policy', \"default-src 'self'; script-src 'unsafe-inline'\");",
         "res.setHeader('Content-Security-Policy', \"default-src 'self'; script-src 'self' 'nonce-{random}'\");",
         "unsafe-inline 허용으로 인라인 스크립트를 통한 XSS 공격이 CSP를 우회합니다.",
         "CWE-116 CSP with unsafe-inline Allows XSS"),
    ]
    for lang, code, fix, atk, vuln in csp_cases:
        out.append(_make_sample(lang, code, vuln, "MEDIUM", 6.1, atk, fix))
    return out


def _sqli_blind_samples() -> list[dict]:
    """블라인드 SQL 인젝션 + 2차 인젝션 추가 변형"""
    out = []
    # Time-based blind
    for lang, code, fix, atk in [
        ("Python",
         "query = f\"SELECT * FROM users WHERE username='{username}'\"",
         "cursor.execute('SELECT * FROM users WHERE username=%s', (username,))",
         "time 기반 블라인드 SQL 인젝션으로 ' AND SLEEP(5)-- 주입 시 DB 정보를 비트 단위로 추출합니다."),
        ("Node.js / Express",
         "db.query(`SELECT * FROM orders WHERE status='${req.query.status}'`)",
         "db.query('SELECT * FROM orders WHERE status=?', [req.query.status])",
         "블라인드 인젝션으로 AND (SELECT SLEEP(5)) 주입 시 응답 시간으로 정보를 추출합니다."),
        ("PHP",
         "$sql = \"SELECT * FROM products WHERE cat='\" . $_GET['cat'] . \"'\";",
         "$stmt = $pdo->prepare('SELECT * FROM products WHERE cat=?');\n$stmt->execute([$_GET['cat']]);",
         "PHP $_GET를 직접 쿼리에 삽입해 SLEEP 기반 블라인드 인젝션으로 DB 스키마가 노출됩니다."),
        ("Java Spring Boot",
         "String q = \"SELECT * FROM accounts WHERE type='\" + type + \"' AND active=1\";\nList<Account> r = jdbcTemplate.queryForList(q, Account.class);",
         "List<Account> r = jdbcTemplate.queryForList(\n    \"SELECT * FROM accounts WHERE type=? AND active=1\",\n    Account.class, type);",
         "JDBC에서 type을 직접 연결해 UNION 또는 SLEEP 기반 인젝션으로 accounts 테이블이 노출됩니다."),
    ]:
        out.append(_make_sample(lang, code,
            "CWE-89 Blind SQL Injection", "CRITICAL", 9.8, atk, fix))
    # Second-order injection
    for lang, code, fix in [
        ("Python",
         "# 등록 시 저장\nusername = request.form['username']  # 'admin'--\ncursor.execute('INSERT INTO users (name) VALUES (%s)', (username,))\n\n# 나중에 이름으로 조회 (위험)\nquery = f\"SELECT * FROM users WHERE name='{stored_name}'\"",
         "# 조회 시에도 파라미터화된 쿼리 사용\ncursor.execute('SELECT * FROM users WHERE name=%s', (stored_name,))"),
        ("Node.js / Express",
         "// 저장 시\nawait db.query('INSERT INTO profiles (bio) VALUES (?)', [bio]);\n\n// 조회 후 재사용 (위험)\nconst user = await db.query(`SELECT * FROM users WHERE bio='${storedBio}'`);",
         "// 조회 시도 파라미터화\nconst user = await db.query('SELECT * FROM users WHERE bio=?', [storedBio]);"),
    ]:
        out.append(_make_sample(lang, code,
            "CWE-89 Second-Order SQL Injection", "CRITICAL", 9.8,
            "첫 번째 요청에서 DB에 저장된 악성 SQL 페이로드가 두 번째 쿼리에서 실행됩니다.", fix))
    return out


def _spring_security_samples() -> list[dict]:
    """Spring Security 설정 오류"""
    out = []
    cases = [
        ('http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll());',
         'http.authorizeHttpRequests(auth -> auth\n    .requestMatchers("/public/**").permitAll()\n    .anyRequest().authenticated());',
         "anyRequest().permitAll()로 모든 엔드포인트가 인증 없이 접근 가능해집니다.",
         "CWE-306 Spring Security permitAll() Misconfiguration"),
        ('http.headers(headers -> headers.frameOptions(HeadersConfigurer.HeadersSpec::disable));',
         'http.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));',
         "X-Frame-Options 비활성화로 클릭재킹 공격에 취약해집니다.",
         "CWE-1021 Clickjacking via Disabled X-Frame-Options"),
        ('http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));\n// JWT 없이 상태 없는 인증만 사용',
         'http.sessionManagement(session -> session\n    .sessionCreationPolicy(SessionCreationPolicy.STATELESS))\n    .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);',
         "STATELESS 정책에서 JWT 필터 없이 인증 구현 시 모든 요청이 인증 없이 처리됩니다.",
         "CWE-287 Missing JWT Filter in Stateless Spring Security"),
        ('@Bean\npublic WebSecurityCustomizer ignore() {\n    return web -> web.ignoring().requestMatchers("/**");\n}',
         '// WebSecurityCustomizer.ignoring() 사용 금지\n// 대신 authorizeHttpRequests에서 permitAll()로 세분화 설정',
         "ignoring(\"/**\")은 Spring Security 필터 체인을 완전히 우회해 모든 보안 기능이 무효화됩니다.",
         "CWE-284 Spring Security Filter Chain Bypass"),
        ('http.csrf(csrf -> csrf.ignoringRequestMatchers("/**"));',
         'http.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));',
         "모든 경로에서 CSRF 보호를 비활성화해 상태 변경 요청 위조가 가능합니다.",
         "CWE-352 CSRF Protection Disabled for All Paths"),
        ('@PreAuthorize("isAuthenticated()")\npublic void deleteUser(Long id) {\n    userRepo.deleteById(id);\n}',
         '@PreAuthorize("hasRole(\'ADMIN\') and #id == authentication.principal.id or hasRole(\'ADMIN\')")\npublic void deleteUser(Long id) {\n    userRepo.deleteById(id);\n}',
         "isAuthenticated()만으로는 권한 수준 검증이 안 돼 일반 사용자가 다른 사용자를 삭제합니다.",
         "CWE-862 Insufficient Spring Security @PreAuthorize"),
        ('SecurityContext ctx = SecurityContextHolder.getContext();\nAuthentication auth = ctx.getAuthentication();\nif (auth != null) { grantAccess(); }',
         'Authentication auth = SecurityContextHolder.getContext().getAuthentication();\nif (auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken)) {\n    grantAccess();\n}',
         "auth != null 체크만으로는 AnonymousAuthenticationToken을 필터링하지 못해 미인증 사용자가 접근합니다.",
         "CWE-287 Improper Authentication Check with Spring SecurityContext"),
    ]
    for code, fix, atk, vuln in cases:
        out.append(_make_sample("Java Spring Boot", code, vuln, "HIGH", 8.1, atk, fix))
    return out


def _go_ruby_extra_samples() -> list[dict]:
    """Go / Ruby 추가 취약점 샘플"""
    out = []
    # Go SQL injection
    for v in ["r.URL.Query().Get(\"id\")", "r.FormValue(\"name\")", "r.URL.Query().Get(\"search\")"]:
        code = f'rows, _ := db.Query("SELECT * FROM users WHERE id=" + {v})'
        fix  = f'rows, _ := db.Query("SELECT * FROM users WHERE id=?", {v})'
        out.append(_make_sample("Go", code,
            "CWE-89 SQL Injection in Go", "CRITICAL", 9.8,
            f"Go db.Query()에 {v}가 직접 연결돼 SQL 인젝션으로 전체 테이블 조회가 가능합니다.", fix))
    # Go command injection
    for v in ["r.FormValue(\"cmd\")", "r.URL.Query().Get(\"host\")"]:
        code = f'exec.Command("sh", "-c", {v}).Run()'
        fix  = f'exec.Command("/usr/bin/ping", "-c", "4", {v}).Run()'
        out.append(_make_sample("Go", code,
            "CWE-78 OS Command Injection in Go", "CRITICAL", 9.8,
            f"sh -c에 {v}가 전달돼 임의 셸 명령 실행이 가능합니다.", fix))
    # Go SSRF
    for v in ["r.URL.Query().Get(\"url\")", "r.FormValue(\"target\")"]:
        code = f'resp, _ := http.Get({v})'
        fix  = (f'u, _ := url.Parse({v})\n'
                f'if u.Hostname() != "allowed.example.com" {{\n'
                f'    http.Error(w, "Blocked", 400)\n    return\n}}\n'
                f'resp, _ := http.Get({v})')
        out.append(_make_sample("Go", code,
            "CWE-918 SSRF in Go http.Get", "HIGH", 8.6,
            f"http.Get({v})에 공격자가 내부 서비스 URL을 전달해 클라우드 메타데이터를 탈취합니다.", fix))
    # Ruby SQL injection (ActiveRecord)
    for v in ["params[:name]", "params[:search]", "params[:id]"]:
        code = f"User.where(\"name = '#{{{v}}}'\")"
        fix  = f"User.where(name: {v})"
        out.append(_make_sample("Ruby", code,
            "CWE-89 SQL Injection in Rails ActiveRecord", "CRITICAL", 9.8,
            f"ActiveRecord where()에 {v}가 직접 삽입돼 SQL 인젝션으로 데이터베이스 전체가 노출됩니다.", fix))
    # Ruby command injection
    for v in ["params[:cmd]", "params[:host]", "request.params[:input]"]:
        code = f"`ping #{{{v}}}`"
        fix  = f"system('ping', '-c', '4', {v})"
        out.append(_make_sample("Ruby", code,
            "CWE-78 OS Command Injection in Ruby", "CRITICAL", 9.8,
            f"백틱 명령에 {v}가 직접 삽입돼 ; rm -rf / 같은 명령 주입이 가능합니다.", fix))
    # Ruby path traversal
    for v in ["params[:file]", "request.params[:doc]"]:
        code = f"File.read(\"/var/data/\" + {v})"
        fix  = (f"safe = File.basename({v})\n"
                f"path = File.expand_path(File.join('/var/data/', safe))\n"
                f"raise Forbidden unless path.start_with?('/var/data/')\n"
                f"File.read(path)")
        out.append(_make_sample("Ruby", code,
            "CWE-22 Path Traversal in Ruby", "HIGH", 7.5,
            f"File.read에 {v}가 직접 연결돼 ../를 통한 디렉터리 이탈이 가능합니다.", fix))
    # PHP additional
    for v in ["$_GET['id']", "$_POST['search']", "$_REQUEST['q']"]:
        code = f"$result = mysqli_query($conn, \"SELECT * FROM users WHERE id={v}\");"
        fix  = f"$stmt = $conn->prepare('SELECT * FROM users WHERE id=?');\n$stmt->bind_param('s', {v});\n$stmt->execute();"
        out.append(_make_sample("PHP", code,
            "CWE-89 SQL Injection in PHP", "CRITICAL", 9.8,
            f"mysqli_query에 {v}가 직접 삽입돼 SQL 인젝션으로 DB 전체 열람이 가능합니다.", fix))
    # PHP LFI
    for v in ["$_GET['page']", "$_GET['lang']", "$_POST['module']"]:
        code = f"include({v} . '.php');"
        fix  = (f"$allowed = ['home', 'about', 'contact'];\n"
                f"if (!in_array({v}, $allowed, true)) die('Forbidden');\n"
                f"include({v} . '.php');")
        out.append(_make_sample("PHP", code,
            "CWE-22 Local File Inclusion in PHP", "HIGH", 8.6,
            f"include({v})에 공격자가 ../../../etc/passwd를 전달해 서버 파일이 노출됩니다.", fix))
    return out


def build_all_samples() -> list[dict]:
    all_samples: list[dict] = []
    generators = [
        _xss_samples,
        _sqli_samples,
        _cmdi_samples,
        _path_traversal_samples,
        _deser_samples,
        _hardcoded_samples,
        _ssrf_samples,
        _auth_samples,
        _csrf_samples,
        _file_upload_samples,
        _int_overflow_samples,
        _buffer_samples,
        _code_injection_samples,
        _xxe_samples,
        _redos_samples,
        _open_redirect_samples,
        _privilege_samples,
        _race_condition_samples,
        _log_injection_samples,
        _missing_auth_samples,
        _input_validation_samples,
        _idor_samples,
        _github_actions_samples,
        _cleartext_samples,
        _info_disclosure_samples,
        _supply_chain_samples,
        _dynamic_load_samples,
        _cors_samples,
        # ── 추가 CWE ──────────────────────────────────────────
        _nosql_injection_samples,
        _ssti_samples,
        _mass_assignment_samples,
        _crypto_samples,
        _session_samples,
        _format_string_samples,
        _jwt_samples,
        _prototype_pollution_samples,
        _api_key_samples,
        _xxss_advanced_samples,
        _path_trav_advanced_samples,
        _sqli_orm_samples,
        _spring_security_samples,
        _go_ruby_extra_samples,
        _insecure_headers_samples,
        _sqli_blind_samples,
        _misc_vuln_samples,
        _ldap_xpath_samples,
    ]
    for gen in generators:
        samples = gen()
        all_samples.extend(samples)
        print(f"  [{gen.__name__:35s}] {len(samples):4d} 샘플")
    return all_samples


def _dedup(samples: list[dict]) -> list[dict]:
    """prompt 기준 중복 제거."""
    seen = set()
    out  = []
    for s in samples:
        key = s["prompt"].strip()[:200]
        if key not in seen:
            seen.add(key)
            out.append(s)
    return out


def _load_existing() -> list[dict]:
    existing = []
    for fname in ["lora_train_v4.jsonl", "lora_train_v4_additional.jsonl"]:
        p = DATA_DIR / fname
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    try:
                        existing.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    return existing


def main():
    print("=" * 60)
    print("  ScanOps v4 학습 데이터 생성기")
    print("=" * 60)

    print("\n[1/4] 새 샘플 생성 중...")
    new_samples = build_all_samples()
    new_samples = _dedup(new_samples)
    print(f"\n  신규 샘플 총계: {len(new_samples):,}개")

    # 신규 데이터 저장
    gen_path = DATA_DIR / "lora_train_v4_gen.jsonl"
    DATA_DIR.mkdir(exist_ok=True)
    gen_path.write_text(
        "\n".join(json.dumps(s, ensure_ascii=False) for s in new_samples),
        encoding="utf-8",
    )
    print(f"\n[2/4] 신규 데이터 저장: {gen_path}")

    # 기존 데이터 로드
    print("\n[3/4] 기존 데이터 병합 중...")
    existing = _load_existing()
    print(f"  기존 데이터: {len(existing):,}개")

    # 합산 & 중복 제거 (기존 우선)
    combined = _dedup(existing + new_samples)
    random.seed(42)
    random.shuffle(combined)
    print(f"  합산 (중복 제거 후): {len(combined):,}개")

    # 합산 데이터 저장
    combined_path = DATA_DIR / "lora_train_v4_combined.jsonl"
    combined_path.write_text(
        "\n".join(json.dumps(s, ensure_ascii=False) for s in combined),
        encoding="utf-8",
    )
    print(f"\n[4/4] 합산 데이터 저장: {combined_path}")

    print("\n" + "=" * 60)
    print(f"  완료!  신규 {len(new_samples):,}개 / 합산 {len(combined):,}개")
    print("  v4 재훈련 시 lora_train_v4_combined.jsonl 사용")
    print("=" * 60)


if __name__ == "__main__":
    main()
