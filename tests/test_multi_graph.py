"""
multi_graph(다언어 taint) 회귀 테스트.
핵심 불변식:
  1. false-safe 0 — 취약 코드를 'safe'로 판정하지 않는다 (vuln 또는 unknown만 허용).
  2. 확신 케이스는 정확히 vuln/safe로 잡는다.
실행: pytest tests/test_multi_graph.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest
from scanops.core.multi_graph import analyze
from scripts.v12_cases import PAIRS

# ── 확신해야 하는 대표 케이스 (언어×CWE) ──────────────────────────────────────
CONFIDENT_VULN = [
    ("Python", 'os.system("ping -c1 " + request.args.get("host"))'),
    ("PHP", 'system("nslookup " . $_GET["domain"]);'),
    ("Python", 'data = pickle.loads(base64.b64decode(request.data))'),
    ("Node.js / Express", 'const out = eval(req.body.formula);'),
    ("Python", 'cipher = DES.new(key, DES.MODE_ECB)'),
    ("Go", 'const apiKey = "sk_live_51H8xQh2eZvKYlo3"'),
]
# sink + sanitizer가 같은 자리에 명시돼 'strong safe'로 잡혀야 하는 케이스만.
# (강한 원시형만 있는 코드는 일부러 unknown으로 위임 → false-safe veto 방지)
CONFIDENT_SAFE = [
    ("PHP", 'system("nslookup " . escapeshellarg($_GET["domain"]));'),
    ("Go", 'os.ReadFile(filepath.Join("uploads", filepath.Base(r.FormValue("name"))))'),
]


@pytest.mark.parametrize("lang,code", CONFIDENT_VULN)
def test_confident_vuln(lang, code):
    assert analyze(code, lang)["verdict"] == "vuln"


@pytest.mark.parametrize("lang,code", CONFIDENT_SAFE)
def test_confident_safe(lang, code):
    assert analyze(code, lang)["verdict"] == "safe"


def test_no_false_safe_across_bank():
    """paired 뱅크 전체에서 '취약 코드를 safe로' 오판이 한 건도 없어야 한다."""
    bad = []
    for p in PAIRS:
        r = analyze(p["vuln"], p["language"])
        if r["verdict"] == "safe":
            bad.append((p["language"], p["cwe"], r["reason"]))
    assert not bad, f"false-safe 발생: {bad}"


def test_no_false_vuln_across_bank():
    """안전 코드를 vuln으로 오판이 한 건도 없어야 한다 (unknown은 허용)."""
    bad = []
    for p in PAIRS:
        r = analyze(p["safe"], p["language"])
        if r["verdict"] == "vuln":
            bad.append((p["language"], p["cwe"], r["reason"]))
    assert not bad, f"false-vuln 발생: {bad}"
