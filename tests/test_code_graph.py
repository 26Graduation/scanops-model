import importlib.util
import sys
from pathlib import Path


def _load_code_graph():
    path = Path(__file__).resolve().parents[1] / "scanops" / "core" / "code_graph.py"
    spec = importlib.util.spec_from_file_location("scanops_code_graph_for_tests", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


code_graph = _load_code_graph()


def test_static_asset_prop_flow_suppresses_xss_false_positive():
    graph = code_graph.build_code_graph([
        code_graph.CodeFile(
            filename="src/App.tsx",
            language="tsx",
            content="""
import Header from './Header';
import HanLogo from './image/HanLogo.png';

export default function App() {
  return <Header logo={HanLogo} />;
}
""",
        ),
        code_graph.CodeFile(
            filename="src/Header.tsx",
            language="tsx",
            content="""
export default function Header({ logo }) {
  return <img src={logo} />;
}
""",
        ),
    ])

    evidence = code_graph.evidence_for_finding(graph, "src/Header.tsx", "XSS")

    assert evidence
    assert evidence[0].verdict == "safe"
    assert "static import" in evidence[0].source
    assert code_graph.should_suppress_finding("XSS", evidence) is True
    assert code_graph.kg_risk_score(7.5, evidence) == 6.5


def test_url_param_prop_flow_keeps_xss_finding_tainted():
    graph = code_graph.build_code_graph([
        code_graph.CodeFile(
            filename="src/App.tsx",
            language="tsx",
            content="""
import Header from './Header';

export default function App() {
  const imageUrl = new URLSearchParams(location.search).get('img');
  return <Header logo={imageUrl} />;
}
""",
        ),
        code_graph.CodeFile(
            filename="src/Header.tsx",
            language="tsx",
            content="""
export default function Header({ logo }) {
  return <img src={logo} />;
}
""",
        ),
    ])

    evidence = code_graph.evidence_for_finding(graph, "src/Header.tsx", "XSS")

    assert evidence
    assert evidence[0].verdict == "tainted"
    assert "URLSearchParams.get('img')" in evidence[0].source
    assert code_graph.should_suppress_finding("XSS", evidence) is False
    assert code_graph.kg_risk_score(7.5, evidence) == 8.4


def test_url_param_to_fetch_is_ssrf_tainted():
    graph = code_graph.build_code_graph([
        code_graph.CodeFile(
            filename="src/Footer.tsx",
            language="tsx",
            content="""
export default function Footer() {
  const apiUrl = new URLSearchParams(location.search).get('api');
  fetch(apiUrl);
}
""",
        ),
    ])

    evidence = code_graph.evidence_for_finding(graph, "src/Footer.tsx", "SSRF")

    assert evidence
    assert evidence[0].category == "ssrf"
    assert evidence[0].verdict == "tainted"
    assert code_graph.should_suppress_finding("SSRF", evidence) is False
