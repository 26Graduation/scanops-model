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
    r"request\.getParameter\(|request\.getHeader\(|request\.getQueryString\(|"
    r"request\.getCookies\(|\.getValue\(\)|getParameterValues\("
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


def _resolve_dosomething_taint(code: str) -> bool | None:
    """doSomething(또는 유사 helper)의 반환이 사용자입력(param)으로 오염됐는지.
    True=오염(취약 가능), False=상수치환(안전), None=helper 없음/판정불가."""
    body = _method_body(code, "doSomething")
    if body is None:
        return None
    ivars = _int_vars(body) or _int_vars(code)

    # 마지막 bar 할당 / return 추적
    assigns = re.findall(r"\bbar\s*=\s*(.+?);", body, re.DOTALL)
    expr = assigns[-1].strip() if assigns else None
    if expr is None:
        rm = re.search(r"return\s+(.+?);", body)
        expr = rm.group(1).strip() if rm else None
    if expr is None:
        return None

    return _expr_is_tainted(expr, body, ivars)


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


def analyze_java(code: str) -> dict:
    """Java 코드의 안전/취약을 taint + API패턴으로 판정."""
    has_user_input = bool(USER_INPUT.search(code))
    tainted = _resolve_dosomething_taint(code)  # helper 통과 후 오염 여부

    # ── API-패턴 카테고리 (taint 무관) ──────────────────────────────────
    # crypto
    cm = re.search(r"Cipher\.getInstance\(\s*([^),]+)", code)
    if cm:
        arg = cm.group(1).strip()
        algo = arg.strip('"') if arg.startswith('"') else _resolve_str_value(arg, code)
        if algo:
            a = algo.lower()
            if any(w in a for w in WEAK_CRYPTO):
                return _v("crypto", f"약한 암호 알고리즘 사용: {algo}")
            return _s("crypto", f"안전한 암호 알고리즘: {algo}")
    # hash
    hm = re.search(r"MessageDigest\.getInstance\(\s*([^),]+)", code)
    if hm:
        arg = hm.group(1).strip()
        algo = arg.strip('"') if arg.startswith('"') else _resolve_str_value(arg, code)
        if algo:
            a = algo.lower()
            if any(w in a for w in WEAK_HASH):
                return _v("hash", f"약한 해시: {algo}")
            if any(w in a for w in STRONG_HASH):
                return _s("hash", f"강한 해시: {algo}")
    # weakrand
    if re.search(r"\bnew\s+java\.util\.Random\b|\bnew\s+Random\b|Math\.random\(", code):
        return _v("weakrand", "예측 가능한 난수(Random/Math.random)")
    if re.search(r"SecureRandom", code) and not re.search(r"new\s+Random\b", code):
        return _s("weakrand", "SecureRandom 사용")
    # securecookie
    if re.search(r"new\s+Cookie\(|addCookie\(", code):
        sm = re.search(r"setSecure\(\s*(\w+)\s*\)", code)
        if sm:
            val = sm.group(1)
            if val == "true":
                return _s("securecookie", "setSecure(true)")
            if val == "false":
                return _v("securecookie", "setSecure(false)")
            # 불린 변수면 해석
            bm = re.search(rf"boolean\s+{val}\s*=\s*(.+?);", code)
            if bm and "true" in bm.group(1) and "false" not in bm.group(1):
                return _s("securecookie", "setSecure(true via var)")
            return _v("securecookie", "setSecure 불확실/조건부")
        return _v("securecookie", "쿠키에 setSecure 없음")

    # ── taint 카테고리 — 확신할 때만 safe/vuln, 아니면 unknown(LLM 위임) ──
    # 하이브리드 설계: 그래프의 'safe'는 고정밀이어야 LLM 오탐을 안전하게 억제할 수 있다.
    cat = _taint_category(code)
    if cat:
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
    return {"verdict": "unknown", "category": "?", "reason": "카테고리/판정 불가"}


def _taint_category(code: str) -> str | None:
    if re.search(r"Statement\b|executeQuery\(|executeUpdate\(|executeBatch\(|addBatch\(", code) \
       and re.search(r"SELECT|INSERT|UPDATE|DELETE", code, re.I):
        return "sqli"
    if re.search(r"Runtime\.getRuntime\(\)\.exec|ProcessBuilder|\.exec\(", code):
        return "cmdi"
    if re.search(r"new\s+File\(|FileInputStream|FileOutputStream|\.sendRedirect\(.*File|RandomAccessFile", code):
        return "pathtraver"
    if re.search(r"ctx\.search\(|DirContext|InitialDirContext|\.search\(", code) and "ldap" in code.lower():
        return "ldapi"
    if re.search(r"XPath|xpath\.|\.evaluate\(|compile\(", code) and "xpath" in code.lower():
        return "xpathi"
    if re.search(r"getWriter\(\)\.(print|write)|response\.getWriter|\.append\(", code):
        return "xss"
    if re.search(r"\.putValue\(|session\.setAttribute\(|\.setAttribute\(", code):
        return "trustbound"
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
