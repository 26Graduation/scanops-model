"""
V12 paired 케이스 뱅크 — OWASP-free, 다언어, 취약/안전 쌍
================================================================
같은 sink·같은 연산을 '취약 버전'과 '안전 버전'으로 쌍지어 둔다.
이렇게 해야 모델이 "긴 코드=안전" 같은 스타일 단축학습 대신 **데이터 흐름의
정화(sanitization) 여부**로 판별하도록 강제된다. (OWASP가 쓰는 적대적 설계와
같은 원리지만, 코드는 우리가 직접 작성 → 벤치마크 누수 없음.)

각 항목: language, cwe, name, vuln(취약 코드), safe(안전 코드)
build_dataset_v12 가 이를 취약/안전 두 행으로 전개한다.
"""
from __future__ import annotations

# (language, cwe, name, vuln_code, safe_code)
PAIRS: list[dict] = [
    # ── SQL Injection (CWE-89) ──────────────────────────────────────────────
    {"language": "Python", "cwe": "CWE-89", "name": "SQL Injection",
     "vuln": 'cur.execute("SELECT * FROM users WHERE name=\'" + name + "\'")',
     "safe": 'cur.execute("SELECT * FROM users WHERE name=%s", (name,))'},
    {"language": "Java", "cwe": "CWE-89", "name": "SQL Injection",
     "vuln": 'st.executeQuery("SELECT * FROM acct WHERE id=" + request.getParameter("id"));',
     "safe": 'PreparedStatement ps = c.prepareStatement("SELECT * FROM acct WHERE id=?"); ps.setString(1, request.getParameter("id"));'},
    {"language": "PHP", "cwe": "CWE-89", "name": "SQL Injection",
     "vuln": '$db->query("SELECT * FROM posts WHERE slug=\'" . $_GET["slug"] . "\'");',
     "safe": '$s = $db->prepare("SELECT * FROM posts WHERE slug=?"); $s->execute([$_GET["slug"]]);'},
    {"language": "Go", "cwe": "CWE-89", "name": "SQL Injection",
     "vuln": 'db.Query("SELECT * FROM users WHERE email=\'" + r.URL.Query().Get("email") + "\'")',
     "safe": 'db.Query("SELECT * FROM users WHERE email=$1", r.URL.Query().Get("email"))'},
    {"language": "C#", "cwe": "CWE-89", "name": "SQL Injection",
     "vuln": 'var cmd = new SqlCommand("SELECT * FROM u WHERE n=\'" + Request["n"] + "\'", conn);',
     "safe": 'var cmd = new SqlCommand("SELECT * FROM u WHERE n=@n", conn); cmd.Parameters.AddWithValue("@n", Request["n"]);'},

    # ── Command Injection (CWE-78) ──────────────────────────────────────────
    {"language": "Python", "cwe": "CWE-78", "name": "OS Command Injection",
     "vuln": 'os.system("ping -c1 " + request.args.get("host"))',
     "safe": 'subprocess.run(["ping", "-c1", request.args.get("host")], check=True)'},
    {"language": "Node.js / Express", "cwe": "CWE-78", "name": "OS Command Injection",
     "vuln": 'exec("convert " + req.query.file + " out.png");',
     "safe": 'execFile("convert", [req.query.file, "out.png"]);'},
    {"language": "Go", "cwe": "CWE-78", "name": "OS Command Injection",
     "vuln": 'exec.Command("sh", "-c", "tar xf " + r.FormValue("f")).Run()',
     "safe": 'exec.Command("tar", "xf", r.FormValue("f")).Run()'},
    {"language": "PHP", "cwe": "CWE-78", "name": "OS Command Injection",
     "vuln": 'system("nslookup " . $_GET["domain"]);',
     "safe": 'system("nslookup " . escapeshellarg($_GET["domain"]));'},

    # ── XSS (CWE-79) ────────────────────────────────────────────────────────
    {"language": "Node.js / Express", "cwe": "CWE-79", "name": "Cross-Site Scripting",
     "vuln": 'res.send("<h1>Hello " + req.query.name + "</h1>");',
     "safe": 'res.send("<h1>Hello " + escapeHtml(req.query.name) + "</h1>");'},
    {"language": "React / Next.js", "cwe": "CWE-79", "name": "Cross-Site Scripting",
     "vuln": 'return <div dangerouslySetInnerHTML={{__html: comment.body}} />;',
     "safe": 'return <div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(comment.body)}} />;'},
    {"language": "PHP", "cwe": "CWE-79", "name": "Cross-Site Scripting",
     "vuln": 'echo "<p>" . $_GET["q"] . "</p>";',
     "safe": 'echo "<p>" . htmlspecialchars($_GET["q"], ENT_QUOTES) . "</p>";'},
    {"language": "Java", "cwe": "CWE-79", "name": "Cross-Site Scripting",
     "vuln": 'response.getWriter().write("<div>" + request.getParameter("c") + "</div>");',
     "safe": 'response.getWriter().write("<div>" + Encode.forHtml(request.getParameter("c")) + "</div>");'},

    # ── Path Traversal (CWE-22) ─────────────────────────────────────────────
    {"language": "Python", "cwe": "CWE-22", "name": "Path Traversal",
     "vuln": 'open(os.path.join(BASE, request.args.get("f"))).read()',
     "safe": 'p = os.path.realpath(os.path.join(BASE, request.args.get("f")))\nif not p.startswith(BASE): abort(403)\nopen(p).read()'},
    {"language": "Node.js / Express", "cwe": "CWE-22", "name": "Path Traversal",
     "vuln": 'fs.readFile(path.join(DIR, req.query.name), cb);',
     "safe": 'const p = path.normalize(path.join(DIR, req.query.name));\nif (!p.startsWith(DIR)) return res.sendStatus(403);\nfs.readFile(p, cb);'},
    {"language": "Java", "cwe": "CWE-22", "name": "Path Traversal",
     "vuln": 'new FileInputStream(new File(BASE, request.getParameter("name")));',
     "safe": 'File f = new File(BASE, request.getParameter("name"));\nif (!f.getCanonicalPath().startsWith(BASE)) throw new SecurityException();\nnew FileInputStream(f);'},
    {"language": "Go", "cwe": "CWE-22", "name": "Path Traversal",
     "vuln": 'http.ServeFile(w, r, "./files/" + r.URL.Query().Get("name"))',
     "safe": 'name := filepath.Base(r.URL.Query().Get("name"))\nhttp.ServeFile(w, r, filepath.Join("./files", name))'},

    # ── SSRF (CWE-918) ──────────────────────────────────────────────────────
    {"language": "Python", "cwe": "CWE-918", "name": "Server-Side Request Forgery",
     "vuln": 'requests.get(request.args.get("url"))',
     "safe": 'u = request.args.get("url")\nif urlparse(u).hostname not in ALLOWED_HOSTS: abort(400)\nrequests.get(u)'},
    {"language": "Node.js / Express", "cwe": "CWE-918", "name": "Server-Side Request Forgery",
     "vuln": 'const r = await fetch(req.query.target);',
     "safe": 'if (!ALLOWLIST.includes(new URL(req.query.target).host)) return res.sendStatus(400);\nconst r = await fetch(req.query.target);'},
    {"language": "Go", "cwe": "CWE-918", "name": "Server-Side Request Forgery",
     "vuln": 'http.Get(r.URL.Query().Get("u"))',
     "safe": 'u, _ := url.Parse(r.URL.Query().Get("u"))\nif !allowed[u.Host] { http.Error(w, "bad", 400); return }\nhttp.Get(u.String())'},

    # ── Insecure Deserialization (CWE-502) ──────────────────────────────────
    {"language": "Python", "cwe": "CWE-502", "name": "Insecure Deserialization",
     "vuln": 'data = pickle.loads(base64.b64decode(request.data))',
     "safe": 'data = json.loads(request.data)'},
    {"language": "Java", "cwe": "CWE-502", "name": "Insecure Deserialization",
     "vuln": 'Object o = new ObjectInputStream(request.getInputStream()).readObject();',
     "safe": 'Object o = new ObjectMapper().readValue(request.getInputStream(), Dto.class);'},
    {"language": "PHP", "cwe": "CWE-502", "name": "Insecure Deserialization",
     "vuln": '$obj = unserialize($_COOKIE["prefs"]);',
     "safe": '$obj = json_decode($_COOKIE["prefs"], true);'},

    # ── Weak Crypto / Hash (CWE-327 / CWE-328) ──────────────────────────────
    {"language": "Python", "cwe": "CWE-327", "name": "Use of Broken Cipher (DES)",
     "vuln": 'cipher = DES.new(key, DES.MODE_ECB)',
     "safe": 'cipher = AES.new(key, AES.MODE_GCM)'},
    {"language": "Java", "cwe": "CWE-328", "name": "Weak Hash (MD5)",
     "vuln": 'MessageDigest.getInstance("MD5").digest(pw.getBytes());',
     "safe": 'MessageDigest.getInstance("SHA-256").digest(pw.getBytes());'},
    {"language": "Node.js / Express", "cwe": "CWE-328", "name": "Weak Hash (SHA-1) for Password",
     "vuln": 'const h = crypto.createHash("sha1").update(password).digest("hex");',
     "safe": 'const h = await bcrypt.hash(password, 12);'},
    {"language": "C#", "cwe": "CWE-327", "name": "Use of Broken Cipher (TripleDES)",
     "vuln": 'using var des = TripleDES.Create();',
     "safe": 'using var aes = Aes.Create();'},

    # ── Insecure Randomness (CWE-330) ───────────────────────────────────────
    {"language": "Java", "cwe": "CWE-330", "name": "Insecure Randomness for Token",
     "vuln": 'String token = Long.toString(new Random().nextLong());',
     "safe": 'byte[] b = new byte[32]; new SecureRandom().nextBytes(b); String token = Base64.getEncoder().encodeToString(b);'},
    {"language": "Python", "cwe": "CWE-330", "name": "Insecure Randomness for Token",
     "vuln": 'token = str(random.randint(0, 999999))',
     "safe": 'token = secrets.token_urlsafe(32)'},

    # ── Hardcoded Secret (CWE-798) ──────────────────────────────────────────
    {"language": "Python", "cwe": "CWE-798", "name": "Hardcoded Credentials",
     "vuln": 'conn = connect(host=DB, user="admin", password="P@ssw0rd123")',
     "safe": 'conn = connect(host=DB, user="admin", password=os.environ["DB_PASS"])'},
    {"language": "Go", "cwe": "CWE-798", "name": "Hardcoded API Key",
     "vuln": 'const apiKey = "sk_live_51H8xQh2eZvKYlo3"',
     "safe": 'apiKey := os.Getenv("STRIPE_KEY")'},

    # ── XXE (CWE-611) ───────────────────────────────────────────────────────
    {"language": "Java", "cwe": "CWE-611", "name": "XML External Entity",
     "vuln": 'DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(request.getInputStream());',
     "safe": 'DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\nf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nf.newDocumentBuilder().parse(request.getInputStream());'},
    {"language": "Python", "cwe": "CWE-611", "name": "XML External Entity",
     "vuln": 'tree = lxml.etree.parse(request.stream)',
     "safe": 'parser = lxml.etree.XMLParser(resolve_entities=False, no_network=True)\ntree = lxml.etree.parse(request.stream, parser)'},

    # ── Open Redirect (CWE-601) ─────────────────────────────────────────────
    {"language": "Node.js / Express", "cwe": "CWE-601", "name": "Open Redirect",
     "vuln": 'res.redirect(req.query.next);',
     "safe": 'res.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/");'},
    {"language": "Python", "cwe": "CWE-601", "name": "Open Redirect",
     "vuln": 'return redirect(request.args.get("url"))',
     "safe": 'nxt = request.args.get("url", "/")\nreturn redirect(nxt if nxt.startswith("/") else "/")'},

    # ── Code Injection / eval (CWE-94) ──────────────────────────────────────
    {"language": "Python", "cwe": "CWE-94", "name": "Code Injection via eval",
     "vuln": 'result = eval(request.form["expr"])',
     "safe": 'result = ast.literal_eval(request.form["expr"])'},
    {"language": "Node.js / Express", "cwe": "CWE-94", "name": "Code Injection via vm",
     "vuln": 'const out = eval(req.body.formula);',
     "safe": 'const out = mathjs.evaluate(req.body.formula);'},

    # ── LDAP Injection (CWE-90) ─────────────────────────────────────────────
    {"language": "Java", "cwe": "CWE-90", "name": "LDAP Injection",
     "vuln": 'ctx.search("ou=people", "(uid=" + request.getParameter("u") + ")", sc);',
     "safe": 'ctx.search("ou=people", "(uid=" + Encode.forLdap(request.getParameter("u")) + ")", sc);'},

    # ── SSTI (CWE-1336) ─────────────────────────────────────────────────────
    {"language": "Python", "cwe": "CWE-1336", "name": "Server-Side Template Injection",
     "vuln": 'return render_template_string("Hi " + request.args.get("name"))',
     "safe": 'return render_template("hi.html", name=request.args.get("name"))'},

    # ── 추가 배치: 언어·sink 다양화 (안전 풀 확장) ──────────────────────────
    # SQLi 다른 sink/언어
    {"language": "Ruby", "cwe": "CWE-89", "name": "SQL Injection",
     "vuln": 'User.where("name = \'#{params[:name]}\'")',
     "safe": 'User.where("name = ?", params[:name])'},
    {"language": "Kotlin", "cwe": "CWE-89", "name": "SQL Injection",
     "vuln": 'stmt.executeQuery("SELECT * FROM t WHERE id=" + req.getParameter("id"))',
     "safe": 'val ps = conn.prepareStatement("SELECT * FROM t WHERE id=?"); ps.setString(1, req.getParameter("id"))'},
    {"language": "Node.js / Express", "cwe": "CWE-89", "name": "NoSQL Injection",
     "vuln": 'User.find({ $where: "this.name == \'" + req.query.n + "\'" });',
     "safe": 'User.find({ name: req.query.n });'},
    # Command injection 추가
    {"language": "Ruby", "cwe": "CWE-78", "name": "OS Command Injection",
     "vuln": 'system("convert #{params[:file]} out.png")',
     "safe": 'system("convert", params[:file], "out.png")'},
    {"language": "C#", "cwe": "CWE-78", "name": "OS Command Injection",
     "vuln": 'Process.Start("cmd.exe", "/c ping " + Request["host"]);',
     "safe": 'Process.Start(new ProcessStartInfo { FileName = "ping", ArgumentList = { Request["host"] } });'},
    # XSS 추가
    {"language": "TypeScript", "cwe": "CWE-79", "name": "DOM-based XSS",
     "vuln": 'el.innerHTML = location.hash.slice(1);',
     "safe": 'el.textContent = location.hash.slice(1);'},
    {"language": "Go", "cwe": "CWE-79", "name": "Cross-Site Scripting",
     "vuln": 'fmt.Fprintf(w, "<p>%s</p>", r.URL.Query().Get("q"))',
     "safe": 'fmt.Fprintf(w, "<p>%s</p>", template.HTMLEscapeString(r.URL.Query().Get("q")))'},
    # Path traversal 추가
    {"language": "PHP", "cwe": "CWE-22", "name": "Path Traversal",
     "vuln": 'readfile("/var/data/" . $_GET["file"]);',
     "safe": 'readfile("/var/data/" . basename($_GET["file"]));'},
    {"language": "C#", "cwe": "CWE-22", "name": "Path Traversal",
     "vuln": 'File.ReadAllText(Path.Combine(root, Request["name"]));',
     "safe": 'var full = Path.GetFullPath(Path.Combine(root, Request["name"]));\nif (!full.StartsWith(root)) throw new UnauthorizedAccessException();\nFile.ReadAllText(full);'},
    # SSRF 추가
    {"language": "Java", "cwe": "CWE-918", "name": "Server-Side Request Forgery",
     "vuln": 'new URL(request.getParameter("url")).openStream();',
     "safe": 'URL u = new URL(request.getParameter("url"));\nif (!ALLOWED.contains(u.getHost())) throw new SecurityException();\nu.openStream();'},
    # Deserialization 추가
    {"language": "Ruby", "cwe": "CWE-502", "name": "Insecure Deserialization",
     "vuln": 'obj = Marshal.load(Base64.decode64(params[:data]))',
     "safe": 'obj = JSON.parse(params[:data])'},
    # 약한 암호/해시 추가
    {"language": "Go", "cwe": "CWE-328", "name": "Weak Hash (MD5)",
     "vuln": 'sum := md5.Sum([]byte(password))',
     "safe": 'hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)'},
    {"language": "PHP", "cwe": "CWE-327", "name": "Weak Password Hash (MD5)",
     "vuln": '$h = md5($password);',
     "safe": '$h = password_hash($password, PASSWORD_BCRYPT);'},
    # 안전한 난수 추가
    {"language": "Node.js / Express", "cwe": "CWE-330", "name": "Insecure Randomness for Token",
     "vuln": 'const token = Math.random().toString(36).slice(2);',
     "safe": 'const token = crypto.randomBytes(32).toString("hex");'},
    {"language": "Go", "cwe": "CWE-330", "name": "Insecure Randomness for Token",
     "vuln": 'token := fmt.Sprintf("%d", mrand.Int())',
     "safe": 'b := make([]byte, 32); crand.Read(b); token := hex.EncodeToString(b)'},
    # 하드코딩 시크릿 추가
    {"language": "Java", "cwe": "CWE-798", "name": "Hardcoded Credentials",
     "vuln": 'String pw = "SuperSecret2024!";',
     "safe": 'String pw = System.getenv("APP_DB_PASSWORD");'},
    {"language": "JavaScript", "cwe": "CWE-798", "name": "Hardcoded JWT Secret",
     "vuln": 'jwt.sign(payload, "my-secret-key");',
     "safe": 'jwt.sign(payload, process.env.JWT_SECRET);'},
    # Open redirect 추가
    {"language": "Java", "cwe": "CWE-601", "name": "Open Redirect",
     "vuln": 'response.sendRedirect(request.getParameter("url"));',
     "safe": 'String u = request.getParameter("url");\nresponse.sendRedirect(u != null && u.startsWith("/") ? u : "/");'},
    # eval/code injection 추가
    {"language": "PHP", "cwe": "CWE-94", "name": "Code Injection via eval",
     "vuln": 'eval("$x = " . $_GET["expr"] . ";");',
     "safe": '$x = filter_var($_GET["expr"], FILTER_VALIDATE_INT);'},
    {"language": "Ruby", "cwe": "CWE-94", "name": "Code Injection via eval",
     "vuln": 'eval(params[:code])',
     "safe": 'Integer(params[:code]) rescue 0'},
    # XXE 추가
    {"language": "C#", "cwe": "CWE-611", "name": "XML External Entity",
     "vuln": 'var doc = new XmlDocument(); doc.Load(Request.InputStream);',
     "safe": 'var doc = new XmlDocument { XmlResolver = null }; doc.Load(Request.InputStream);'},
    # 인증/접근제어 (CWE-639 / CWE-862)
    {"language": "Node.js / Express", "cwe": "CWE-639", "name": "IDOR / Broken Object-Level Auth",
     "vuln": 'const acct = await Account.findById(req.params.id);\nres.json(acct);',
     "safe": 'const acct = await Account.findOne({ _id: req.params.id, owner: req.user.id });\nif (!acct) return res.sendStatus(403);\nres.json(acct);'},
    {"language": "Python", "cwe": "CWE-862", "name": "Missing Authorization",
     "vuln": '@app.post("/admin/delete")\ndef delete(): db.drop(request.form["table"])',
     "safe": '@app.post("/admin/delete")\n@require_role("admin")\ndef delete(): db.drop(request.form["table"])'},
    # 안전 코드 다양성 (취약 아님을 정확히 판별하도록)
    {"language": "Python", "cwe": "CWE-89", "name": "SQL Injection",
     "vuln": 'db.execute(f"DELETE FROM logs WHERE user={uid}")',
     "safe": 'db.execute("DELETE FROM logs WHERE user=%s", (uid,))'},
    {"language": "Java", "cwe": "CWE-78", "name": "OS Command Injection",
     "vuln": 'Runtime.getRuntime().exec("git clone " + request.getParameter("repo"));',
     "safe": 'new ProcessBuilder("git", "clone", request.getParameter("repo")).start();'},
    {"language": "Go", "cwe": "CWE-22", "name": "Path Traversal",
     "vuln": 'os.ReadFile("uploads/" + r.FormValue("name"))',
     "safe": 'os.ReadFile(filepath.Join("uploads", filepath.Base(r.FormValue("name"))))'},
    {"language": "PHP", "cwe": "CWE-918", "name": "Server-Side Request Forgery",
     "vuln": 'file_get_contents($_GET["url"]);',
     "safe": '$h = parse_url($_GET["url"], PHP_URL_HOST);\nif (!in_array($h, $allowed)) die("blocked");\nfile_get_contents($_GET["url"]);'},
    {"language": "TypeScript", "cwe": "CWE-89", "name": "SQL Injection",
     "vuln": 'await pool.query(`SELECT * FROM u WHERE id = ${req.params.id}`);',
     "safe": 'await pool.query("SELECT * FROM u WHERE id = $1", [req.params.id]);'},
    {"language": "C#", "cwe": "CWE-79", "name": "Cross-Site Scripting",
     "vuln": 'Response.Write("<span>" + Request["msg"] + "</span>");',
     "safe": 'Response.Write("<span>" + HttpUtility.HtmlEncode(Request["msg"]) + "</span>");'},
]


def expand():
    """(language, code, name, cwe, is_safe) 튜플로 전개."""
    for p in PAIRS:
        yield p["language"], p["vuln"], p["name"], p["cwe"], False
        yield p["language"], p["safe"], p["name"], p["cwe"], True


if __name__ == "__main__":
    from collections import Counter
    items = list(expand())
    print(f"PAIRS {len(PAIRS)} → rows {len(items)} (취약 {len(PAIRS)} + 안전 {len(PAIRS)})")
    print("언어:", dict(Counter(i[0] for i in items)))
    print("CWE:", dict(Counter(i[3] for i in items)))
