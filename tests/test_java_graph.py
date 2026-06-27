"""java_graph decoy-aware taint 분석 회귀 테스트.
OWASP Benchmark의 미끼(decoy) 패턴과 분기 constant-folding을 검증한다."""
from scanops.core.java_graph import analyze_java


def _cookie_decoy(category_sink: str) -> str:
    """injection 파일에 흔히 박히는 setSecure(true) 안전 쿠키 미끼."""
    return f"""
        javax.servlet.http.Cookie userCookie = new javax.servlet.http.Cookie("X", "bar");
        userCookie.setSecure(true);
        userCookie.setHttpOnly(true);
        response.addCookie(userCookie);
        String param = request.getParameter("p");
        {category_sink}
    """


def test_securecookie_decoy_does_not_mask_sqli():
    # setSecure(true) 쿠키 미끼가 SQL injection을 'safe'로 가리면 안 된다.
    code = _cookie_decoy(
        'String sql = "SELECT * FROM u WHERE n=\'" + param + "\'";'
        " stmt.executeQuery(sql);")
    assert analyze_java(code)["verdict"] != "safe"


def test_strong_cipher_safe_even_with_output_writer():
    # crypto 파일은 결과를 getWriter로 출력하지만(xss 미끼) crypto로 판정돼야 한다.
    code = """
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        response.getWriter().write(org.owasp.esapi.ESAPI.encoder().encodeForHTML(out));
    """
    r = analyze_java(code)
    assert r["category"] == "crypto" and r["verdict"] == "safe"


def test_weak_cipher_vuln():
    code = 'javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("DES/ECB/PKCS5Padding");'
    r = analyze_java(code)
    assert r["category"] == "crypto" and r["verdict"] == "vuln"


def test_external_algorithm_is_unknown_not_safe():
    # getProperty 유래 알고리즘은 파일만으론 결정 불가 → unknown(LLM 위임).
    code = """
        String algorithm = props.getProperty("hashAlg1", "SHA512");
        java.security.MessageDigest md = java.security.MessageDigest.getInstance(algorithm);
    """
    assert analyze_java(code)["verdict"] == "unknown"


def test_switch_constant_fold_taint():
    # "ABC".charAt(2)=='C' → case 'C': bar=param → 사용자입력이 sink 도달(취약).
    code = """
        String param = request.getParameter("p");
        String bar = doSomething(request, param);
        java.io.File f = new java.io.File(bar);
        new java.io.FileInputStream(f);
    """
    helper = """
        private static String doSomething(HttpServletRequest request, String param) {
            String bar;
            String guess = "ABC";
            char switchTarget = guess.charAt(2);
            switch (switchTarget) {
                case 'A': bar = param; break;
                case 'B': bar = "safe"; break;
                case 'C': case 'D': bar = param; break;
                default: bar = "safe"; break;
            }
            return bar;
        }
    """
    assert analyze_java(code + helper)["verdict"] == "vuln"


def test_securerandom_with_setattribute_is_weakrand_safe_not_trustbound():
    # SecureRandom(안전) 파일의 setAttribute 미끼가 trustbound 오탐을 내면 안 된다.
    code = """
        String param = request.getParameter("p");
        int r = java.security.SecureRandom.getInstance("SHA1PRNG").nextInt(99);
        request.getSession().setAttribute("k", r);
    """
    r = analyze_java(code)
    assert r["category"] == "weakrand" and r["verdict"] == "safe"
