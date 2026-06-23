from fastapi.testclient import TestClient

from scripts import api_server


XSS_MODEL_RESPONSE = """\
VULNERABILITY: Cross-Site Scripting (XSS, CWE-79)
SEVERITY: HIGH
CVSS: 7.5
ATTACK: 공격자가 악성 스크립트를 실행할 수 있습니다.
FIX: 입력값을 검증하고 안전하게 렌더링하세요.
"""


def _stub_model(monkeypatch):
    monkeypatch.delenv("NEO4J_URI", raising=False)
    monkeypatch.setattr(api_server, "search_cves", lambda *args, **kwargs: [])
    monkeypatch.setattr(api_server, "call_model", lambda *args, **kwargs: (XSS_MODEL_RESPONSE, 0.01))
    monkeypatch.setattr(api_server, "_sync_graph_for_demo", lambda *args, **kwargs: None)


def test_batch_api_suppresses_static_asset_xss_false_positive(monkeypatch):
    _stub_model(monkeypatch)
    client = TestClient(api_server.app)

    response = client.post("/analyze/batch", json={
        "files": [
            {
                "language": "React / Next.js",
                "file_path": "src/App.tsx",
                "code": """
import Header from './Header';
import HanLogo from './image/HanLogo.png';

export default function App() {
  return <Header logo={HanLogo} />;
}
""",
            },
            {
                "language": "React / Next.js",
                "file_path": "src/Header.tsx",
                "code": """
export default function Header({ logo }) {
  return <img src={logo} />;
}
""",
            },
        ],
    })

    assert response.status_code == 200
    header_result = response.json()["results"][1]
    assert header_result["suppressed_by_graph"] is True
    assert header_result["detected"] is False
    assert header_result["severity"] == "INFO"
    assert header_result["kg_risk_score"] == 0.0
    assert header_result["graph_evidence"][0]["verdict"] == "safe"


def test_batch_api_keeps_user_input_xss_finding(monkeypatch):
    _stub_model(monkeypatch)
    client = TestClient(api_server.app)

    response = client.post("/analyze/batch", json={
        "files": [
            {
                "language": "React / Next.js",
                "file_path": "src/App.tsx",
                "code": """
import Header from './Header';

export default function App() {
  const imageUrl = new URLSearchParams(location.search).get('img');
  return <Header logo={imageUrl} />;
}
""",
            },
            {
                "language": "React / Next.js",
                "file_path": "src/Header.tsx",
                "code": """
export default function Header({ logo }) {
  return <img src={logo} />;
}
""",
            },
        ],
    })

    assert response.status_code == 200
    header_result = response.json()["results"][1]
    assert header_result["suppressed_by_graph"] is False
    assert header_result["detected"] is True
    assert header_result["kg_risk_score"] == 8.4
    assert header_result["graph_evidence"][0]["verdict"] == "tainted"
