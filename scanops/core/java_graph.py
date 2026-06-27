"""
Java 정적 taint 분석기 — OWASP Benchmark(Java 서블릿) 안전/취약 판정
================================================================
기존 code_graph.py는 JS/TS 전용이라 OWASP(Java)에 적용 불가했다. 이 모듈은
Java 서블릿에 대해 source→(helper)→sink 데이터 흐름을 추적하고, OWASP가
안전/취약을 가르는 핵심 트릭(항진명제로 사용자입력을 상수로 치환)을
constant-folding으로 풀어낸다. 또 약한 암호/해시/난수/쿠키 같은 API-패턴
취약점도 변수값을 추적해 판정한다.

LLM은 OWASP에서 안전/취약을 구별 못했지만(재현율≈오탐률), taint 분석은
"실제 사용자 입력이 sink에 도달하는가"를 결정적으로 판정한다 — 이것이
하이브리드(LLM 탐지 + 그래프 오탐억제) 아키텍처의 핵심.

판정: analyze_java(code) -> {"verdict": "vuln"|"safe"|"unknown", "category", "reason"}
"""
from __future__ import annotations

import re

# ── 1. 사용자 입력 source ─────────────────────────────────────────────────
USER_INPUT = re.compile(
    r"request\.getParameter\(|request\.getHeader\(|request\.getHeaders\(|"
    r"request\.getQueryString\(|request\.getCookies\(|\.getValue\(\)|"
    r"getParameterValues\(|getParameterNames\(|getParameterMap\(|"
    r"SeparateClassRequest\(|getReader\(|getInputStream\("
)

# ── 카테고리별 약한/안전 API (taint 무관, 값 패턴) ────────────────────────
WEAK_CRYPTO = ("des", "desede", "rc2", "rc4", "blowfish", "/ecb/", "aes/ecb")
WEAK_HASH = ("md5", "md2", "sha1", "sha-1", "sha 1")
STRONG_HASH = ("sha-256", "sha256", "sha-384", "sha384", "sha-512", "sha512", "sha-3")


def _int_vars(code: str) -> dict[str, int]:
    """int 변수 할당 수집 (constant folding용). 예: int num = 106;"""
    out = {}
    for m in re.finditer(r"\bint\s+(\w+)\s*=\s*(-?\d+)\s*;", code):
        out[m.group(1)] = int(m.group(2))
    return out


def _eval_const_cond(cond: str, ivars: dict[str, int]) -> bool | None:
    """(7 * 18) + num > 200 같은 상수 산술 조건을 평가. 변수는 ivars로 치환.
    평가 불가면 None."""
    expr = cond.strip()
    # 변수명을 숫자로 치환 (긴 이름부터)
    for name in sorted(ivars, key=len, reverse=True):
        expr = re.sub(rf"\b{name}\b", str(ivars[name]), expr)
    # 숫자/연산자/비교만 남았는지 확인 (안전 eval)
    if not re.fullmatch(r"[\d\s()+\-*/%<>=!]+", expr):
        return None
    expr = expr.replace("=>", ">=").replace("=<", "<=")
    try:
        return bool(eval(expr, {"__builtins__": {}}, {}))  # noqa: S307 (숫자식만)
    except Exception:
        return None


def _method_body(code: str, name: str) -> str | None:
    """중괄호 매칭으로 메서드 본문 추출 (정규식 anchor보다 견고)."""
    m = re.search(rf"\b{name}\s*\([^)]*\)\s*(?:throws[^{{]*)?\{{", code)
    if not m:
        return None
    i = code.index("{", m.end() - 1)
    depth = 0
    for j in range(i, len(code)):
        if code[j] == "{":
            depth += 1
        elif code[j] == "}":
            depth -= 1
            if depth == 0:
                return code[i + 1:j]
    return None


def _extract_if_bar(body: str) -> tuple[str, str, str | None] | None:
    """본문에서 `if (COND) bar = A; [else bar = B;]` 패턴을 균형 괄호로 추출.
    OWASP는 삼항 대신 if/else 문으로도 사용자입력 분기를 숨긴다(예: 02032).
    반환: (cond, a, b) 또는 None."""
    for m in re.finditer(r"if\s*\(", body):
        i = m.end() - 1  # '(' 위치
        depth, j = 0, m.end() - 1
        while j < len(body):
            if body[j] == "(":
                depth += 1
            elif body[j] == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        cond = body[i + 1:j]
        rest = body[j + 1:]
        am = re.match(r"\s*bar\s*=\s*(.+?);", rest, re.DOTALL)
        if not am:
            continue
        a = am.group(1)
        after = rest[am.end():]
        bm = re.match(r"\s*else\s+bar\s*=\s*(.+?);", after, re.DOTALL)
        b = bm.group(1) if bm else None
        return cond, a, b
    return None


def _balanced(code: str, open_idx: int, oc: str, cc: str) -> int:
    """open_idx의 여는 괄호/중괄호에 대응하는 닫는 위치를 반환."""
    depth, j = 0, open_idx
    while j < len(code):
        if code[j] == oc:
            depth += 1
        elif code[j] == cc:
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return len(code)


def _resolve_selector(sel: str, body: str, ivars: dict[str, int]):
    """switch 선택자를 상수로 해석. char(문자) 또는 int. 불가시 None.
    OWASP 트릭: char switchTarget = "ABC".charAt(2)  →  'C'."""
    sel = sel.strip()
    # 변수면 본문에서 할당식 추적
    am = re.search(rf"(?:char|int|byte|short)\s+{re.escape(sel)}\s*=\s*(.+?);", body)
    rhs = am.group(1).strip() if am else sel
    # X.charAt(N)
    cm = re.match(r"(\w+)\.charAt\(\s*(\d+)\s*\)", rhs)
    if cm:
        s = _resolve_str_value(cm.group(1), body)
        idx = int(cm.group(2))
        if s is not None and 0 <= idx < len(s):
            return s[idx]            # 단일 char
        return None
    # 문자 리터럴 'C'
    if re.fullmatch(r"'.'", rhs):
        return rhs[1]
    # 정수
    if re.fullmatch(r"-?\d+", rhs):
        return int(rhs)
    if rhs in ivars:
        return ivars[rhs]
    return None


def _switch_taint(body: str, ivars: dict[str, int]) -> bool | None:
    """switch(selector){ case ...: bar = ...; } 의 선택된 분기 taint 평가.
    선택자를 상수로 풀 수 있으면 매칭 case의 bar 할당 오염 여부를 반환."""
    sm = re.search(r"switch\s*\(", body)
    if not sm:
        return None
    pi = body.index("(", sm.start())
    pe = _balanced(body, pi, "(", ")")
    selector = body[pi + 1:pe]
    bi = body.index("{", pe)
    be = _balanced(body, bi, "{", "}")
    block = body[bi + 1:be]

    selval = _resolve_selector(selector, body, ivars)
    if selval is None:
        return None

    labels = list(re.finditer(r"(?:case\s+([^:]+?)|default)\s*:", block))
    if not labels:
        return None
    segs = []
    for idx, lm in enumerate(labels):
        start = lm.end()
        end = labels[idx + 1].start() if idx + 1 < len(labels) else len(block)
        lab = lm.group(1).strip() if lm.group(1) else None  # None=default
        segs.append((lab, block[start:end]))

    def seg_bar_taint(start_idx):
        for s in range(start_idx, len(segs)):       # fall-through 처리
            bm = re.search(r"bar\s*=\s*(.+?);", segs[s][1])
            if bm:
                return _expr_is_tainted(bm.group(1).strip(), body, ivars)
        return None

    def matches(lab):
        if isinstance(selval, str):
            return lab.strip("'\"") == selval
        return lab.lstrip("'\"").rstrip("'\"").lstrip("-").isdigit() and int(lab) == selval

    for idx, (lab, _seg) in enumerate(segs):
        if lab is not None and matches(lab):
            return seg_bar_taint(idx)
    for idx, (lab, _seg) in enumerate(segs):       # default
        if lab is None:
            return seg_bar_taint(idx)
    return None


def _resolve_dosomething_taint(code: str) -> bool | None:
    """doSomething(또는 유사 helper)의 반환이 사용자입력(param)으로 오염됐는지.
    True=오염(취약 가능), False=상수치환(안전), None=helper 없음/판정불가."""
    body = _method_body(code, "doSomething")
    if body is None:
        return None
    ivars = _int_vars(body) or _int_vars(code)

    # switch 문 분기 — 선택자를 상수로 풀어 매칭 case의 bar 평가
    if "switch" in body:
        st = _switch_taint(body, ivars)
        if st is not None:
            return st

    # if/else 문 분기 (삼항과 별개) — 조건을 constant-fold로 평가
    ib = _extract_if_bar(body)
    if ib:
        cond, a, b = ib
        val = _eval_const_cond(cond, ivars)
        if val is True:
            return _expr_is_tainted(a, body, ivars)
        if val is False:
            return _expr_is_tainted(b, body, ivars) if b else False
        # 조건 평가 불가 → 한 분기라도 오염이면 보수적으로 오염
        ta = _expr_is_tainted(a, body, ivars)
        tb = _expr_is_tainted(b, body, ivars) if b else False
        if ta or tb:
            return True
        if ta is None or tb is None:
            return None
        return False

    # 여러 bar 할당이 오염/상수로 엇갈리고 제어흐름을 못 풀면 → unknown(LLM 위임).
    # (마지막 할당만 보면 OWASP switch/조건 트릭에서 false-safe가 난다.)
    assigns = [a.strip() for a in re.findall(r"\bbar\s*=\s*(.+?);", body, re.DOTALL)]
    if not assigns:
        rm = re.search(r"return\s+(.+?);", body)
        assigns = [rm.group(1).strip()] if rm else []
    if not assigns:
        return None
    taints = [_expr_is_tainted(a, body, ivars) for a in assigns]
    if any(t is True for t in taints) and any(t is False for t in taints):
        return None      # 분기 미해결 + 혼합 → 판정 불가
    if all(t is True for t in taints):
        return True
    if all(t is False for t in taints):
        return False
    return _expr_is_tainted(assigns[-1], body, ivars)


def _expr_is_tainted(expr: str, body: str, ivars: dict[str, int]) -> bool | None:
    expr = expr.strip()
    # 삼항: cond ? a : b
    tern = re.match(r"(.+?)\?\s*(.+?)\s*:\s*(.+)$", expr, re.DOTALL)
    if tern:
        cond, a, b = (x.strip() for x in tern.groups())
        val = _eval_const_cond(cond, ivars)
        if val is True:
            return _expr_is_tainted(a, body, ivars)
        if val is False:
            return _expr_is_tainted(b, body, ivars)
        # 조건 평가 불가 → 둘 중 하나라도 오염이면 보수적으로 오염
        return _expr_is_tainted(a, body, ivars) or _expr_is_tainted(b, body, ivars)
    # 문자열 리터럴 → 안전
    if expr.startswith('"'):
        return False
    # param 직접/가공 → 오염
    if re.search(r"\bparam\b", expr):
        return True
    # List/Map: valuesList.get(0) / map.get("keyA")
    gm = re.search(r"(\w+)\.get\(\s*(\d+|\"[^\"]+\")\s*\)", expr)
    if gm:
        coll, key = gm.group(1), gm.group(2).strip('"')
        # OWASP는 add 후 remove/set으로 순서를 바꾸는 트릭을 쓴다. 이런 변형이
        # 있으면 단순 add 순서로는 판정 불가 → None(LLM 위임)으로 보수 처리.
        if re.search(rf"{coll}\.(remove|set|clear)\(", body):
            return None
        return _collection_taint(coll, key, body)
    # 알 수 없음
    return None


def _collection_taint(coll: str, key: str, body: str) -> bool | None:
    """valuesList.add(param) 순서 / map.put(k, param) 키로 오염 여부 판정."""
    # add 순서
    adds = re.findall(rf"{coll}\.add\(\s*(.+?)\s*\)", body)
    if adds and key.isdigit():
        idx = int(key)
        if idx < len(adds):
            return "param" in adds[idx]
    # put(key, value)
    for pm in re.finditer(rf"{coll}\.put\(\s*\"([^\"]+)\"\s*,\s*(.+?)\)", body):
        if pm.group(1) == key:
            return "param" in pm.group(2)
    return None


def _resolve_str_value(var: str, code: str) -> str | None:
    """문자열 변수의 최종 리터럴 값을 constant-folding으로 해석 (algorithm 등)."""
    ivars = _int_vars(code)
    asgs = re.findall(rf"\b{var}\s*=\s*(.+?);", code, re.DOTALL)
    if not asgs:
        return None
    expr = asgs[-1].strip()
    # 삼항
    tern = re.match(r"(.+?)\?\s*(.+?)\s*:\s*(.+)$", expr, re.DOTALL)
    if tern:
        cond, a, b = (x.strip() for x in tern.groups())
        val = _eval_const_cond(cond, ivars)
        pick = a if val else b if val is False else a
        return pick.strip().strip('"') if pick.strip().startswith('"') else None
    if expr.startswith('"'):
        return expr.strip('"')
    return None


def _resolve_algo(arg: str, code: str) -> tuple[str | None, bool]:
    """getInstance 인자를 알고리즘 문자열로 해석.
    반환: (algo|None, external) — external=True면 getProperty 등 외부설정 유래라
    파일만으론 결정 불가(→ unknown으로 LLM 위임해야 false-safe 방지)."""
    arg = arg.strip()
    if arg.startswith('"'):
        return arg.strip('"'), False
    # 변수: 외부설정(getProperty/System.getenv/param) 유래인지 확인
    asg = re.search(rf"\b{re.escape(arg)}\s*=\s*(.+?);", code, re.DOTALL)
    if asg and re.search(r"getProperty\(|getenv\(|getParameter\(|getHeader\(", asg.group(1)):
        return None, True
    return _resolve_str_value(arg, code), False


def analyze_java(code: str) -> dict:
    """Java 코드의 안전/취약을 taint + API패턴으로 판정.

    설계 핵심(precision): OWASP 파일은 진짜 취약점을 가리려고 미끼 패턴을 심는다
    — injection 취약 파일에 setSecure(true) 쿠키를, crypto/path 파일 끝에
    response.getWriter()+ESAPI.encodeForHTML 출력을 둔다. 따라서 '실제 injection
    sink'(sqli/cmdi/path/ldap/xpath/trustbound)가 있으면 그게 config/xss 미끼보다
    우선한다. xss(getWriter)는 모든 파일에 있으므로 최후의 fallback으로만 본다.
    """
    has_user_input = bool(USER_INPUT.search(code))
    tainted = _resolve_dosomething_taint(code)  # helper 통과 후 오염 여부
    cat = _taint_category(code)

    # ── 1. 특정 config 마커(Cipher/MessageDigest/Random) 최우선 ───────────
    # 이 마커들은 injection 파일에 미끼로 등장하지 않는 카테고리 고유 신호다.
    # 반대로 crypto/hash 파일은 결과를 new File()로 출력하므로, File을 먼저 보면
    # pathtraver로 오라우팅된다 → 특정 마커를 generic sink(File)보다 먼저 본다.
    # 약한(취약) 패턴은 진짜 발견이지만, 강한(안전) 패턴이 외부설정 유래면
    # 파일만으론 단정 불가 → unknown(LLM 위임)로 false-safe를 막는다.
    cm = re.search(r"Cipher\.getInstance\(\s*([^),]+)", code)
    if cm:
        algo, external = _resolve_algo(cm.group(1), code)
        if algo:
            a = algo.lower()
            if any(w in a for w in WEAK_CRYPTO):
                return _v("crypto", f"약한 암호 알고리즘 사용: {algo}")
            return _s("crypto", f"안전한 암호 알고리즘: {algo}")
        if external:
            return {"verdict": "unknown", "category": "crypto",
                    "reason": "암호 알고리즘이 외부설정 유래 → LLM 위임"}
    hm = re.search(r"MessageDigest\.getInstance\(\s*([^),]+)", code)
    if hm:
        algo, external = _resolve_algo(hm.group(1), code)
        if algo:
            a = algo.lower()
            if any(w in a for w in WEAK_HASH):
                return _v("hash", f"약한 해시: {algo}")
            if any(w in a for w in STRONG_HASH):
                return _s("hash", f"강한 해시: {algo}")
        if external:
            return {"verdict": "unknown", "category": "hash",
                    "reason": "해시 알고리즘이 외부설정 유래 → LLM 위임"}
    if re.search(r"\bnew\s+java\.util\.Random\b|\bnew\s+Random\b|Math\.random\(", code):
        return _v("weakrand", "예측 가능한 난수(Random/Math.random)")
    if re.search(r"SecureRandom", code) and not re.search(r"new\s+Random\b", code):
        return _s("weakrand", "SecureRandom 사용")

    # ── 2. 실제 injection sink(sqli/cmdi/path/ldap/xpath) — cookie/xss 미끼보다 우선 ──
    if cat in ("sqli", "cmdi", "pathtraver", "ldapi", "xpathi"):
        return _judge_taint(code, cat, has_user_input, tainted)

    # ── 3. trustbound(setAttribute/putValue) — cookie 미끼보다 우선 ───────
    # trustbound 취약 파일도 setSecure(true) 쿠키 미끼를 달고 있으므로 먼저 본다.
    if cat == "trustbound":
        return _judge_taint(code, cat, has_user_input, tainted)

    # ── 4. securecookie ─────────────────────────────────────────────────
    if re.search(r"new\s+Cookie\(|addCookie\(", code):
        sm = re.search(r"setSecure\(\s*(\w+)\s*\)", code)
        if sm:
            val = sm.group(1)
            if val == "true":
                return _s("securecookie", "setSecure(true)")
            if val == "false":
                return _v("securecookie", "setSecure(false)")
            bm = re.search(rf"boolean\s+{val}\s*=\s*(.+?);", code)
            if bm and "true" in bm.group(1) and "false" not in bm.group(1):
                return _s("securecookie", "setSecure(true via var)")
            return _v("securecookie", "setSecure 불확실/조건부")
        return _v("securecookie", "쿠키에 setSecure 없음")

    # ── 5. xss(getWriter) — 최후 fallback ───────────────────────────────
    if cat == "xss":
        return _judge_taint(code, cat, has_user_input, tainted)

    return {"verdict": "unknown", "category": "?", "reason": "카테고리/판정 불가"}


def _judge_taint(code: str, cat: str, has_user_input: bool, tainted: bool | None) -> dict:
    """taint 흐름 기반 판정 — 확신할 때만 safe/vuln, 아니면 unknown(LLM 위임)."""
    # (a) 안전 sink API 사용 → 확신 safe
    if _has_safe_sink(code, cat):
        return _s(cat, "안전한 sink API(PreparedStatement/ESAPI/canonical 등)")
    # (b) helper가 상수 치환으로 사용자입력을 버림 → 확신 safe
    if tainted is False:
        return _s(cat, "사용자 입력이 상수로 치환되어 sink에 미도달")
    # (c) 사용자입력 자체가 없음 → 확신 safe
    if not has_user_input:
        return _s(cat, "사용자 입력 source 없음")
    # (d) helper가 사용자입력을 sink로 전달 → 확신 vuln
    if tainted is True:
        return _v(cat, "사용자 입력이 검증 없이 sink에 도달(taint 확인)")
    # (e) 사용자입력은 있으나 흐름 판정 불가 → unknown(LLM 판단에 위임)
    return {"verdict": "unknown", "category": cat, "reason": "taint 흐름 판정 불가 → LLM 위임"}


def _taint_category(code: str) -> str | None:
    if re.search(r"Statement\b|executeQuery\(|executeUpdate\(|executeBatch\(|addBatch\(|"
                 r"queryFor\w*\(|JDBCtemplate", code) \
       and re.search(r"SELECT|INSERT|UPDATE|DELETE", code, re.I):
        return "sqli"
    if re.search(r"Runtime\.getRuntime\(\)\.exec|ProcessBuilder|\.exec\(", code):
        return "cmdi"
    if re.search(r"new\s+(?:\w+\.)*File\(|FileInputStream|FileOutputStream|"
                 r"\.sendRedirect\(.*File|RandomAccessFile", code):
        return "pathtraver"
    if re.search(r"ctx\.search\(|DirContext|InitialDirContext|\.search\(", code) and "ldap" in code.lower():
        return "ldapi"
    if re.search(r"XPath|xpath\.|\.evaluate\(|compile\(", code) and "xpath" in code.lower():
        return "xpathi"
    # trustbound(setAttribute/putValue)을 xss(getWriter)보다 먼저 — 모든 파일에 getWriter가
    # 있어 xss가 catch-all이 되는 것을 방지.
    if re.search(r"\.putValue\(|session\.setAttribute\(|\.setAttribute\(", code):
        return "trustbound"
    if re.search(r"getWriter\(\)\.(print|write)|response\.getWriter|\.append\(", code):
        return "xss"
    return None


def _has_safe_sink(code: str, cat: str) -> bool:
    if cat == "sqli":
        # 키워드 존재만으론 불충분(OWASP는 PreparedStatement 변수에도 concat을 섞음).
        # 파라미터 바인딩(setString/setInt)을 쓰고 raw Statement 실행이 없을 때만 안전.
        binds = re.search(r"\.setString\(|\.setInt\(|\.setLong\(", code)
        raw = re.search(r"\bStatement\b[^;]*execute|addBatch\(|createStatement\(", code)
        return bool(binds and not raw)
    if cat == "xss":
        return bool(re.search(r"ESAPI\.encoder\(\)\.encodeFor|encodeForHTML|StringEscapeUtils|HtmlUtils", code))
    if cat == "pathtraver":
        return bool(re.search(r"getCanonicalPath|\.normalize\(\)|FilenameUtils|isInSecureDir", code))
    if cat == "ldapi":
        return bool(re.search(r"encodeForLDAP|escapeLDAP", code))
    if cat == "cmdi":
        return bool(re.search(r"ProcessBuilder\(\s*new\s+String\[\]|Arrays\.asList", code) and False)  # OWASP은 거의 항상 raw
    return False


def _v(cat, reason):
    return {"verdict": "vuln", "category": cat, "reason": reason}


def _s(cat, reason):
    return {"verdict": "safe", "category": cat, "reason": reason}
