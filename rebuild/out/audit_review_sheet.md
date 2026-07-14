# 오탐 감사 — 수동 재확인 시트
심판: claude-opus-4-8 / 규칙: 구체적 공격 경로가 코드에 보일 때만 VALID

## claude — 수동 재확인 10건 (심판 판정에 동의하는지 체크)

### [VALID] test #1024 — CVE-2023-3863 (패치된 CWE: CWE-416, C)
- 분석기 주장: **CWE-416** — nfc_llcp_remove_local returns local after list_del inside the loop but continues execution unconditionally calling nfc_llcp_local_put and pr_warn even when found, risking premature refcount release and use of freed local pointer.
- 심판 근거: The `if (local->dev == dev)` block lacks `return local;` after `list_del`/`spin_unlock`, so a found `local` falls through to the unconditional `nfc_llcp_local_put(local)`, prematurely dropping its refcount before the caller uses it (`llcp_sock->local = local`), a distinct UAF.
- [ ] 심판 판정에 동의  /  [ ] 비동의 (메모: ______)

```C
int err;
	if (skb == NULL) {
		err = -ENOMEM;
		goto out;
	}
	err = nfc_data_exchange(dev, local->target_idx, skb,
out:
	nfc_llcp_local_put(local);
	return err;
/* Protects llcp_devices list */
static DEFINE_SPINLOCK(llcp_devices_lock);
static struct nfc_llcp_local *nfc_llcp_local_get(struct nfc_llcp_local *local)
	struct nfc_llcp_local *res = NULL;
	spin_lock(&llcp_devices_lock);
		if (local->dev == dev) {
			res = nfc_llcp_local_get(local);
			break;
		}
	spin_unlock(&llcp_devices_lock);

	return res;
}

static struct nfc_llcp_local *nfc_llcp_remove_local(struct nfc_dev *dev)
{
	struct nfc_llcp_local *local, *tmp;

	spin_lock(&llcp_devices_lock);
	list_for_each_entry_safe(local, tmp, &llcp_devices, list)
		if (local->dev == dev) {
			list_del(&local->list);
			spin_unlock(&llcp_devices_lock);
		}
	spin_unlock(&llcp_devices_lock);
	pr_warn("Shutting down device not found\n");
	nfc_llcp_local_put(local);

	int err;
		err = -EINVAL;
		goto out;
	err = nfc_llcp_parse_gb_tlv(local,
out:
	nfc_llcp_local_put(local);
	return err;
	nfc_llcp_local_put(local);


	nfc_llcp_local_put(local);

	nfc_llcp_local_put(local);
	struct nfc_llcp_local *local = nfc_llcp_remove_local(dev);
	llcp_sock->local = local;
	llcp_sock->local = local;
		goto sock_llcp_put_local;
		goto sock_llcp_put_local;
	llcp_sock->local = local;
		goto sock_llcp_nullify;
sock_llcp_nullify:
sock_llcp_put_local:
	nfc_llcp_local_put(local);

		goto put_local;
put_local:
	nfc_llcp_local_put(local);

			goto put_local;
put_
… (생략)
```

### [VALID] test #404 — CVE-2023-43256 (패치된 CWE: CWE-22, JavaScript)
- 분석기 주장: **CWE-22** — (사유 없음)
- 심판 근거: `HLS_CHUNK_REGEX = /index[0-9]+.ts/` is unanchored (no `^`/`$`), so `.test('../../index1.ts')` passes validation, allowing path traversal via the `file` param.
- [ ] 심판 판정에 동의  /  [ ] 비동의 (메모: ______)

```JavaScript
const { Error404, Error400 } = require('../../../utils/httpErrors');
const { validateFilename, validateSessionId } = require('../utils/validateStreamParams');
      validateSessionId(req.params.folder);
      validateFilename(req.params.file);
      if (e instanceof Error400) {
        throw e;
      }
const { Error400 } = require('../../../utils/httpErrors');

const SESSION_ID_REGEX = /^camera-[a-zA-Z0-9-_]+$/;

// Session_id usually looks like "camera-7835d25d-b8ce-4824-a235-23637f778f83-39-50-13"
const validateSessionId = (sessionId) => {
  if (!SESSION_ID_REGEX.test(sessionId)) {
    throw new Error400('Invalid session id');
  }
};

const AUTHORIZED_FILENAMES = ['index.m3u8', 'index.m3u8.key', 'key_info_file.txt'];
const HLS_CHUNK_REGEX = /index[0-9]+.ts/;

const validateFilename = (filename) => {
  if (AUTHORIZED_FILENAMES.includes(filename)) {
    return;
  }

  if (!HLS_CHUNK_REGEX.test(filename)) {
    throw new Error400('Invalid filename');
  }
};

module.exports = {
  validateSessionId,
  validateFilename,
};
  it('should get index.m3u8 file', async () => {
  it('should get index1.ts file', async () => {
    const rtspCameraController = RtspCameraController(gladys, rtspCameraService);
    const req = {
      params: {
        folder: 'camera-1',
        file: 'index1.ts',
      },
    };
    await fse.ensureDir(path.join(gladys.config.tempFolder, 'camera-1'));
    await fse.writeFile(path.join(gladys.config.tempFolder, 'camera-1', 'index1.ts'), 'test-toto-content');
… (생략)
```

### [VALID] test #3 — CVE-2023-51665 (패치된 CWE: CWE-918, JavaScript)
- 분석기 주장: **CWE-918** — The server fetches attacker-controlled issuerUrl without validating against internal hosts/IPs, allowing SSRF to internal network resources or metadata endpoints.
- 심판 근거: The code only validates URL pathname format but never checks issuerUrl's host/IP against internal ranges before `axios.get(configUrl)`, so an admin-supplied URL like http://169.254.169.254/... still reaches internal/metadata endpoints (SSRF).
- [ ] 심판 판정에 동의  /  [ ] 비동의 (메모: ______)

```JavaScript
(Database.serverSettings.authOpenIDMobileRedirectURIs.length === 1 && Database.serverSettings.authOpenIDMobileRedirectURIs[0] === '*')) {

     * Helper route used to auto-populate the openid URLs in config/authentication
     * Takes an issuer URL as a query param and requests the config data at "/.well-known/openid-configuration"
     * 
     * @example /auth/openid/config?issuer=http://192.168.1.66:9000/application/o/audiobookshelf/
    router.get('/auth/openid/config', this.isAuthenticated, async (req, res) => {
      if (!req.user.isAdminOrUp) {
        Logger.error(`[Auth] Non-admin user "${req.user.username}" attempted to get issuer config`)
        return res.sendStatus(403)
      }


      // Strip trailing slash
      // Append config pathname and validate URL
      let configUrl = null
      try {
        configUrl = new URL(`${issuerUrl}/.well-known/openid-configuration`)
        if (!configUrl.pathname.endsWith('/.well-known/openid-configuration')) {
          throw new Error('Invalid pathname')
        }
      } catch (error) {
        Logger.error(`[Auth] Failed to get openid configuration. Invalid URL "${configUrl}"`, error)
        return res.status(400).send('Invalid request. Query param \'issuer\' is invalid')
      }

      axios.get(configUrl.toString()).then(({ data }) => {
```

### [VALID] test #880 — CVE-2023-2848 (패치된 CWE: CWE-346, PHP)
- 분석기 주장: **CWE-346** — Trusting client-supplied Sec-Fetch-Site header for same-origin validation is unreliable as it can be spoofed or omitted by non-browser clients, allowing bypass of the trusted connection check.
- 심판 근거: `isTrustedConnection` accepts any client sending `Sec-Fetch-Site: same-origin`, a header trivially spoofable by non-browser clients (curl, scripts), so the same-origin check can be bypassed without the daemon key.
- [ ] 심판 판정에 동의  /  [ ] 비동의 (메모: ______)

```PHP
* Add a same-origin check for non-internal connected Websockets
            echo colorize("Generate and store the Push Notification VAPID keys", 'green') . "\n";
        "\n" .
            "--- " . colorize("Server Configuration - Apache", 'purple') . " ---" .
        echo colorize("Enable the Secure WebSocket to WebSocket tunneling", 'yellow') . "\n# a2enmod proxy_wstunnel \n";
        echo colorize("Add this in your configuration file (default-ssl.conf)", 'yellow') . "\nProxyPass /ws/ ws://127.0.0.1:{$port}/\n";
        "\n" .
            "--- " . colorize("Server Configuration - nginx", 'purple') . " ---" .
        echo colorize("Add this in your configuration file", 'yellow') . "\n";
        "\n" .
            "--- " . colorize("Server Configuration - Caddy", 'purple') . " ---" .
        echo colorize("Add this in your configuration file", 'yellow') . "\nhandle /ws/* {
        if (!$this->isTrustedConnection($conn)) $conn->close();


                if (
                    array_key_exists($sid, $this->singlelocks)
                    && array_key_exists($path, $this->singlelocks[$sid])
                ) {
                if (
                    array_key_exists($sid, $this->singlelocks)
                    && array_key_exists($path, $this->singlelocks[$sid])
                ) {
                if (
                    $session->countClients() == 0
                    && $session->registered == null
                ) {
            ->where('created_at', '<', date(MOVIM_S
… (생략)
```

### [VALID] test #1196 — CVE-2023-48715 (패치된 CWE: CWE-79, PHP)
- 분석기 주장: **CWE-79** — purify() may not properly encode data for HTML attribute context, risking XSS if it fails to escape quotes/special chars in $name, $package_name, or $id.
- 심판 근거: `purify()` (HTML body sanitizer) does not encode double-quotes, so values placed inside `"..."` attributes (name/label/value) allow attribute-breakout XSS distinct from the body-context CVE fix.
- [ ] 심판 판정에 동의  /  [ ] 비동의 (메모: ______)

```PHP
$select = '<select name="' . $hp->purify($name) . '">';
            $select .= '<optgroup label="' . $hp->purify($package_name) . '">';
                $select .= '<option value="' . $hp->purify($id) . '" ' . ($id == $checked_val ? 'selected="selected"' : '') . '>' . $hp->purify($name) . '</option>';
```

### [VALID] test #774 — CVE-2023-4977 (패치된 CWE: CWE-94, PHP)
- 분석기 주장: **CWE-79** — Output is passed through htmlspecialchars, mitigating XSS, but context (inside JS string) may still allow breakout via quotes/backslashes.
- 심판 근거: `htmlspecialchars` default (ENT_QUOTES not set) does not encode single quotes, so `$_POST['interface']`/`$_POST['address']` inside single-quoted JS strings can break out via `'` and inject script.
- [ ] 심판 판정에 동의  /  [ ] 비동의 (메모: ______)

```PHP
echo report_this('Unknown search type ' . htmlspecialchars($search_type));
            interface: '<?php echo htmlspecialchars($_POST['interface']); ?>',
            address: '<?php echo htmlspecialchars($_POST['address']); ?>'
```

### [VALID] test #60 — CVE-2023-4006 (패치된 CWE: CWE-1236, PHP)
- 분석기 주장: **CWE-1236** — Sanitize only wraps values containing risky leading characters in quotes but doesn't prefix/escape the formula trigger itself, so quoted formulas like "=SUM(A1:A10)" can still execute in some spreadsheet applications.
- 심판 근거: `sanitize` only wraps risky values in CSV quotes (`'"' . ... . '"'`) instead of prefixing/escaping the formula trigger, so `=SUM(A1:A10)` still parses as a formula in spreadsheet apps—a real CWE-1236 formula injection.
- [ ] 심판 판정에 동의  /  [ ] 비동의 (메모: ______)

```PHP
$csvRow = array_map(['phpMyFAQ\Report', 'sanitize'], $row);
        $content .= implode(';', $csvRow);
    private Configuration $config;

    /**
     * Sanitizes input to avoid CSV injection.
     * @param string|int $value
     * @return string
     */
    public static function sanitize($value): string
    {
        if (preg_match('/[=\+\-\@\|]/', $value)) {
            $value = '"' . str_replace('"', '""', $value) . '"';
        }

        return $value;
    }
<?php

namespace phpMyFAQ;

use PHPUnit\Framework\TestCase;

class ReportTest extends TestCase
{

    public function testSanitize(): void
    {
        $data = [
            ['John Doe', 'john.doe@example.com', '12345'],
            ['Jane Smith', 'jane.smith@example.com', '=SUM(A1:A10)'],
        ];

        $actual = [];

        $expected = [
            'John Doe,"john.doe@example.com",12345',
            'Jane Smith,"jane.smith@example.com","=SUM(A1:A10)"'
        ];

        foreach ($data as $row) {
            $csvRow = array_map(['phpMyFAQ\Report', 'sanitize'], $row);
            $actual[] = implode(',', $csvRow);
        }

        $this->assertEquals($expected, $actual);
    }
}
```

### [VALID] test #131 — CVE-2023-4321 (패치된 CWE: CWE-79, PHP)
- 분석기 주장: **CWE-434** — Blacklist-based extension/MIME filtering is incomplete (e.g., missing .pht, .php5, .shtml, case variations) allowing bypass and malicious file upload.
- 심판 근거: The blacklist omits `.pht`, `.php5`, `.php7`, `.phtm` and there's no evidence of case-normalization, so a file like `shell.PHP5` or `shell.pht` bypasses the filter enabling malicious upload (CWE-434).
- [ ] 심판 판정에 동의  /  [ ] 비동의 (메모: ______)

```PHP
- Prevent uploading .phps + .(x)html files in assets manager
        $forbiddenExtension = ['php', 'phar', 'phtml', 'phps', 'htm', 'html', 'xhtml', 'htaccess'];
        $forbiddenMime = [
            'application/x-httpd-php', 'application/x-php', 'text/x-php',
            'text/html', 'application/xhtml+xml'
        ];
```

### [VALID] test #298 — CVE-2023-41908 (패치된 CWE: CWE-862, PHP)
- 분석기 주장: **CWE-352** — Session cookie lacks 'session.cookie_samesite' setting, leaving it vulnerable to CSRF/cross-site cookie leakage despite httponly/secure flags being set.
- 심판 근거: The Session ini config sets cookie_httponly and cookie_secure but omits session.cookie_samesite, matching the scanner's concrete claim in this visible code.
- [ ] 심판 판정에 동의  /  [ ] 비동의 (메모: ______)

```PHP
Configure::write('Session', [
    'defaults' => 'php',
    'ini' => [
        'session.cookie_httponly' => true,
        'session.cookie_secure' => true,
    ]
]);

        'secure' => true,
```

### [VALID] test #414 — CVE-2023-40168 (패치된 CWE: CWE-863, JavaScript)
- 분석기 주장: **CWE-183** — file: path check uses startsWith(__dirname) without separator/normalization, allowing sibling directory traversal (e.g., __dirname+"-evil") to bypass the intended restriction.
- 심판 근거: `url.pathname.startsWith(__dirname)` lacks a trailing-separator/normalization check, so a sibling path like `__dirname + "-evil"` passes the prefix test — a real CWE-183 flaw distinct from the CORS/CWE-863 fix.
- [ ] 심판 판정에 동의  /  [ ] 비동의 (메모: ______)

```JavaScript
import './protocols';
import './request-security';
  app.whenReady().then(() => {
import {protocol} from 'electron';

protocol.registerSchemesAsPrivileged([
  {
    scheme: 'tw-extensions',
    privileges: {
      supportFetchAPI: true
    }
  },
  {
    scheme: 'tw-library-files',
    privileges: {
      supportFetchAPI: true
    }
  }
]);
import {app} from 'electron';

const isRequestAllowed = (details) => {
  const url = new URL(details.url);
  if (url.protocol === 'file:') {
    // Requests to files must be inside the application
    return url.pathname.startsWith(__dirname);
  }

  if (details.resourceType !== 'xhr') {
    // Immune to CORS even in standard browsers
    return true;
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    // Special protocols are immune to CORS
    return true;
  }

  const allowOriginHeader = details.responseHeaders['access-control-allow-origin'];
  if (!Array.isArray(allowOriginHeader)) {
    // No header, not allowed
    return false;
  }

  // Header must be set to "*"
  // We don't have a real Origin that we can check
  return allowOriginHeader.join(',') === '*';
};

app.on('session-created', (session) => {
  session.webRequest.onHeadersReceived((details, callback) => {
    callback({
      cancel: !isRequestAllowed(details)
    });
  });
});
```


## ours — 수동 재확인 10건 (심판 판정에 동의하는지 체크)

### [VALID] test #1114 — CVE-2024-3153 (패치된 CWE: CWE-400, JavaScript)
- 분석기 주장: **CWE-434** — The product allows the upload or transfer of dangerous file types that are automatically processed within its environment.
- 심판 근거: `handleFileUpload`/`handleAssetUpload` write files to disk using attacker-controlled `file.originalname` with no extension/MIME whitelist, and the `hotdir` destination is auto-processed by the collector—matching CWE-434.
- [ ] 심판 판정에 동의  /  [ ] 비동의 (메모: ______)

```JavaScript
const { handleFileUpload } = require("../../../utils/files/multer");
    [validApiKey, handleFileUpload],
const { handleAssetUpload, handlePfpUpload } = require("../utils/files/multer");
    [validatedRequest, flexUserRoleValid([ROLES.all]), handlePfpUpload],
    [
      validatedRequest,
      flexUserRoleValid([ROLES.admin, ROLES.manager]),
      handleAssetUpload,
    ],
      if (!request?.file || !request?.file.originalname) {
const path = require("path");
const fs = require("fs");
const { normalizePath } = require("../utils/files");
const { handleFileUpload, handlePfpUpload } = require("../utils/files/multer");
    [
      validatedRequest,
      flexUserRoleValid([ROLES.admin, ROLES.manager]),
      handleFileUpload,
    ],
    [
      validatedRequest,
      flexUserRoleValid([ROLES.admin, ROLES.manager]),
      handlePfpUpload,
    ],
// Handle File uploads for auto-uploading.
const fileUploadStorage = multer.diskStorage({
  destination: function (_, __, cb) {
    const uploadOutput =
      process.env.NODE_ENV === "development"
        ? path.resolve(__dirname, `../../../collector/hotdir`)
        : path.resolve(process.env.STORAGE_DIR, `../../collector/hotdir`);
    cb(null, uploadOutput);
  },
  filename: function (_, file, cb) {
    file.originalname = Buffer.from(file.originalname, "latin1").toString(
      "utf8"
    );
    cb(null, file.originalname);
  },
});
// Asset storage for logos
const assetUploadStorage = multer.diskStorage({
  destination: function (_
… (생략)
```

### [VALID] test #396 — CVE-2011-10004 (패치된 CWE: CWE-434, PHP)
- 분석기 주장: **CWE-434** — The manipulation leads to unrestricted upload.
- 심판 근거: File type validation relies solely on client-supplied `$_FILES[...]['type']`, which is trivially spoofed, allowing upload of a PHP file with a forged `image/*` MIME type to the web-accessible plugins/reciply/images/ directory.
- [ ] 심판 판정에 동의  /  [ ] 비동의 (메모: ______)

```PHP
version : "1.1.8"
Version: 1.1.8
//add_action('plugins_loaded','pluginInit');
if ( !function_exists( 'add_action' ) ) {
	echo "<strong>404.1 Error</strong>";
	exit;
pluginInit();
function pluginInit()
{
	// File version 1.1.7
	$ref = $_SERVER['HTTP_REFERER'];
	
	// Taille maximum 
	$MAX_FILE_SIZE = 400000;
	$error = 0;
	
	// Dossier de destination du fichier
	$serverpath = ABSPATH . 'wp-content/plugins/reciply/images/';
	//$serverpath = "images/";// Path to where images should be uploaded to on the server.
	
	foreach ($_FILES as $file) {
	$allowed_types = array("image/bmp", "image/gif", "image/pjpeg", "image/jpeg", "image/jpg", "image/png");
	$fname = $file['name'];
	$ftype = $file['type'];
	$fsize = $file['size'];
	$ftmp =$file['tmp_name'];
	$path = "$serverpath$fname";
	
	// Diverses test afin de savoir si :
	// Le format de fichier correspond à notre tableau array
	if(!in_array($ftype, $allowed_types)){$error = 1;}
	
	// La taille du fichier n'est pas dépassée
	if($fize > $MAX_FILE_SIZE){$error = 2;}
	
	
	// Le fichier n'existe pas déjà
	if(file_exists($serverpath."m_".$fname)){$error = 3;}
	if ( $error != 0 ) {
		echo "<strong>404.2 Error Code = ".$error."</strong>";
		exit(0);
	}
	
	
	// Si tout va bien, c'est bien déroulé
	if(move_uploaded_file($ftmp,''.$serverpath.''.$fname.'')) {$error = 4;}
	
	if($fname!="") {
					header('refresh: 0; url='.$ref.'&img='.$path.'&f='.$fname.'&target="_blank"');
					}
	else {
			header
… (생략)
```

### [VALID] test #882 — CVE-2023-5835 (패치된 CWE: CWE-79, PHP)
- 분석기 주장: **CWE-1333** — The product uses a regular expression with an inefficient, possibly exponential worst-case computational complexity that consumes excessive CPU cycles.
- 심판 근거: `(?:\s*\n)*` and `.*?(?:\s*\n){2,}` have overlapping matches (`\s` includes `\n`) creating ambiguous quantifiers that cause catastrophic backtracking on whitespace-heavy non-matching input — a real ReDoS distinct from the patched XSS.
- [ ] 심판 판정에 동의  /  [ ] 비동의 (메모: ______)

```PHP
// 注意如果代码块前面有任何内容，就必须至少有一个空行隔开，否则Parsedown不认为它是代码块
            '!^(^(?:\s*\n)*|.*?(?:\s*\n){2,})((?:\t|    )[^\n]*(?:\n+(?:\t|    )[^\n]*)*)(\n+.*|$)$!is' => array(array(1, 3), 'mdpre', array(2)),
```

### [UNCERTAIN] test #1081 — CVE-2024-0404 (패치된 CWE: CWE-915, JavaScript)
- 분석기 주장: **CWE-521** — The product does not require that users should have strong passwords, which makes it easier for attackers to compromise user accounts.
- 심판 근거: Password validation likely occurs inside User.create, which is not shown, so this fragment cannot confirm the absence of strong-password enforcement.
- [ ] 심판 판정에 동의  /  [ ] 비동의 (메모: ______)

```JavaScript
const { username, password } = reqBody(request);
      const { user, error } = await User.create(({
        username,
        password,
        role: "default",
      }));
```

### [UNCERTAIN] test #948 — CVE-2024-1739 (패치된 CWE: CWE-821, TypeScript)
- 분석기 주장: **CWE-89** — The manipulation leads to sql injection.
- 심판 근거: The `${email}` syntax could be a safe parameterized placeholder or an unsafe string interpolation, but the fragment lacks context (e.g., tagged template vs raw string concatenation) to confirm a real injection path.
- [ ] 심판 판정에 동의  /  [ ] 비동의 (메모: ______)

```TypeScript
select * from account where lower(email) = lower(${email})
```

### [UNCERTAIN] test #283 — CVE-2023-42799 (패치된 CWE: CWE-120, C)
- 분석기 주장: **CWE-787** — The product writes data past the end, or before the beginning, of the intended buffer.
- 심판 근거: Buffer size of `destination`/`urlAddr` is not shown and the fragment has mismatched braces, so no concrete distinct out-of-bounds write can be confirmed or ruled out.
- [ ] 심판 판정에 동의  /  [ ] 비동의 (메모: ______)

```C
err = performRtspHandshake(serverInfo);
int performRtspHandshake(PSERVER_INFORMATION serverInfo);
static bool parseUrlAddrFromRtspUrlString(const char* rtspUrlString, char* destination) {
    char* rtspUrlScratchBuffer;
    char* portSeparator;
    char* v6EscapeEndChar;
    char* urlPathSeparator;
    int prefixLen;

    // Create a copy that we can modify
    rtspUrlScratchBuffer = strdup(rtspUrlString);
    if (rtspUrlScratchBuffer == NULL) {
        return false;
    }
    // If we have a v6 address, we want to stop one character after the closing ]
    // If we have a v4 address, we want to stop at the port separator
    portSeparator = strrchr(rtspUrlScratchBuffer, ':');
    v6EscapeEndChar = strchr(rtspUrlScratchBuffer, ']');

    // Count the prefix length to skip past the initial rtsp:// or rtspru:// part
    for (prefixLen = 2; rtspUrlScratchBuffer[prefixLen - 2] != 0 && (rtspUrlScratchBuffer[prefixLen - 2] != '/' || rtspUrlScratchBuffer[prefixLen - 1] != '/'); prefixLen++);

    // If we hit the end of the string prior to parsing the prefix, we cannot proceed
    if (rtspUrlScratchBuffer[prefixLen - 2] == 0) {
        free(rtspUrlScratchBuffer);
        return false;

    // Look for a slash at the end of the host portion of the URL (may not be present)
    urlPathSeparator = strchr(rtspUrlScratchBuffer + prefixLen, '/');

    // Check for a v6 address first since they also have colons
    if (v6EscapeEndChar) {
        // Terminate the string at the next character
… (생략)
```

### [UNCERTAIN] test #246 — CVE-2023-5686 (패치된 CWE: CWE-787, C)
- 분석기 주장: **CWE-125** — The product reads data past the end, or before the beginning, of the intended buffer.
- 심판 근거: `USHORT(bytes, 1)` reads bytes[1] and bytes[2], but the shown check only validates `len > 3` without exposing the actual size/bounds of the `bytes` buffer, so a genuine over-read cannot be confirmed or ruled out from this fragment.
- [ ] 심판 판정에 동의  /  [ ] 비동의 (메모: ______)

```C
if (len > 3) {
			const short delta = USHORT (bytes, 1);
			snprintf (output, outlen, "%s 0x%04"PFMT64x, JAVA_OPS[idx].name, addr + delta);
```

### [UNCERTAIN] test #1077 — CVE-2023-5832 (패치된 CWE: CWE-20, Python)
- 분석기 주장: **CWE-22** — The product uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the product does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory.
- 심판 근거: The normpath+lstrip combination neutralizes leading traversal and absolute paths for all inputs I can construct, but the base-directory join is not shown, so a concrete escape cannot be confirmed or ruled out.
- [ ] 심판 판정에 동의  /  [ ] 비동의 (메모: ______)

```Python
import os
  target_filename = os.path.normpath(content.get('filename')).lstrip(os.pardir + os.sep)
```

### [UNCERTAIN] test #1015 — CVE-2023-6546 (패치된 CWE: CWE-362, C)
- 분석기 주장: **CWE-476** — The product dereferences a pointer that it expects to be valid but is NULL.
- 심판 근거: The two-line fragment shows an assignment from gsm->dlci[0] but provides no surrounding context (allocation, null-check, or subsequent dereference), so no concrete NULL-dereference path is visible in THIS code.
- [ ] 심판 판정에 동의  /  [ ] 비동의 (메모: ______)

```C
struct gsm_dlci *dlci;
	dlci = gsm->dlci[0];
```

### [INVALID] test #1060 — CVE-2023-38699 (패치된 CWE: CWE-311, Python)
- 분석기 주장: **CWE-352** — The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request.
- 심판 근거: This is a client-side outbound POST request (requests.post), not a server-side request handler, so CSRF (CWE-352) is inapplicable—there is no server endpoint accepting user requests here.
- [ ] 심판 판정에 동의  /  [ ] 비동의 (메모: ______)

```Python
response = requests.post(self.base_url + '/apiv2/login', headers=headers, data=data)
)
```
