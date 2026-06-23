"""
ScanOps 코드 그래프(Neo4j) 벤치마크 케이스 100개+
====================================================
scanops/core/code_graph.py 가 실제로 추출/판정할 수 있는 패턴 범위
(XSS sink: <img src>, innerHTML, dangerouslySetInnerHTML / SSRF sink: fetch,
axios.get·post·request / source: 정적 asset import vs 사용자 입력 / 0~2단계
prop 전달 / 별칭(alias) 체인)을 그대로 사용해, 여러 파일에 걸친 데이터 흐름을
가진 멀티파일 코드 스니펫을 생성한다.

구성 (총 100개):
  - GROUP A "cve_2026" 50개 — 2026년 5~6월 NVD에 실제 공개된 XSS(CWE-79)/
    SSRF(CWE-918) CVE 25개씩을 근거로, 각 CVE를 "사용자 입력이 그대로 sink에
    도달하는 취약 버전"과 "정적 자원이거나 안전하게 격리된 버전" 두 갈래로
    재구성. CVE는 코드 자체가 아니라 취약점 클래스의 출처로만 사용.
  - GROUP B "structural" 50개 — sink 종류 × prop-hop 깊이(0~2) × 별칭 체인
    여부 × 입력 소스 종류를 조합해 그래프 추적 로직 자체의 견고성을 검증.

각 케이스는 ScanOps 그래프 엔진이 결정해야 하는 정답(expected_vulnerable)이
명확하도록(정적 import로 완전히 추적 가능 = SAFE, 사용자 입력으로 완전히
추적 가능 = VULNERABLE) 설계했다 — 모호한 unknown 케이스는 포함하지 않는다.
"""
from __future__ import annotations

import json
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
CVE_SEED = json.loads((BASE / "data" / "cve_2026_xss_ssrf_seed.json").read_text())

XSS_SINKS = [
    ("img", "<img src={{{var}}} />"),
    ("innerHTML", "el.innerHTML = {var};"),
    ("dangerouslySetInnerHTML", "<div dangerouslySetInnerHTML={{{{ __html: {var} }}}} />"),
]
SSRF_SINKS = [
    ("fetch", "fetch({var});"),
    ("axios.get", "axios.get({var});"),
    ("axios.post", "axios.post({var}, payload);"),
    ("axios.request", "axios.request({var});"),
]

ASSET_EXTS = [".png", ".svg", ".css", ".jpg", ".webp"]

USER_INPUT_TEMPLATES = [
    ("urlparam", "const {var} = new URLSearchParams(location.search).get('{param}');"),
    ("reqquery", "const {var} = req.query.{param};"),
    ("location", "const {var} = window.location.search;"),
]


def _sink_line(sink_kind: str, var: str) -> str:
    for kind, tmpl in XSS_SINKS + SSRF_SINKS:
        if kind == sink_kind:
            return tmpl.format(var=var)
    raise ValueError(sink_kind)


def _category_of(sink_kind: str) -> str:
    return "xss" if sink_kind in {k for k, _ in XSS_SINKS} else "ssrf"


def _leaf_body(sink_kind: str, prop_name: str) -> str:
    line = _sink_line(sink_kind, prop_name)
    if sink_kind in ("img", "dangerouslySetInnerHTML"):
        return f"export default function Leaf({{ {prop_name} }}) {{\n  return {line}\n}}\n"
    return f"export default function Leaf({{ {prop_name} }}) {{\n  {line}\n  return null;\n}}\n"


def _wrapper_body(name: str, child_name: str, prop_name: str) -> str:
    return (
        f"import {child_name} from './{child_name}';\n\n"
        f"export default function {name}({{ {prop_name} }}) {{\n"
        f"  return <{child_name} {prop_name}={{{prop_name}}} />;\n"
        f"}}\n"
    )


def build_case(
    case_id: str,
    title: str,
    sink_kind: str,
    expected_vulnerable: bool,
    hop: int,
    alias: bool,
    input_kind: str | None = None,
    param: str = "v",
    asset_ext: str = ".png",
    cve: str | None = None,
) -> dict:
    """expected_vulnerable=True  -> source는 추적 가능한 사용자 입력
       expected_vulnerable=False -> source는 추적 가능한 정적 asset import
    """
    category = _category_of(sink_kind)
    var = "val"

    if expected_vulnerable:
        kind, tmpl = next(t for t in USER_INPUT_TEMPLATES if t[0] == input_kind)
        source_lines = [tmpl.format(var=var, param=param)]
    else:
        source_lines = [f"import {var.capitalize()}Asset from './assets/asset{asset_ext}';"]
        var = f"{var.capitalize()}Asset" if hop == 0 else var
        # 정적 import 변수명을 그대로 prop/sink에 사용하기 위해 alias로 통일
        if hop == 0:
            pass
        else:
            source_lines = [f"import RawAsset from './assets/asset{asset_ext}';"]
            var = "RawAsset"

    if alias:
        source_lines.append(f"const aliased = {var};")
        var = "aliased"

    # import 문은 파일 최상단에, const/alias 대입문은 함수 본문 안에 와야
    # 문법적으로 유효한 코드가 된다 (hop>=1일 때 import를 함수 안에 잘못
    # 넣으면 안 됨).
    header_lines = [l for l in source_lines if l.startswith("import ")]
    body_source_lines = [l for l in source_lines if not l.startswith("import ")]

    if hop == 0:
        # 같은 파일에서 source -> sink 직결 (prop 전달 없음)
        sink_line = _sink_line(sink_kind, var)
        body_lines = (
            header_lines
            + ["", "export default function Root() {"]
            + [f"  {l}" for l in body_source_lines]
        )
        if sink_kind in ("img", "dangerouslySetInnerHTML"):
            body_lines.append(f"  return {sink_line}")
        else:
            body_lines.append(f"  {sink_line}")
            body_lines.append("  return null;")
        body_lines.append("}")
        files = {"src/Root.tsx": "\n".join(body_lines) + "\n"}
        target_file = "src/Root.tsx"

    elif hop == 1:
        root_lines = (
            ["import Leaf from './Leaf';"]
            + header_lines
            + ["", "export default function Root() {"]
            + [f"  {l}" for l in body_source_lines]
            + [f"  return <Leaf val={{{var}}} />;", "}", ""]
        )
        files = {
            "src/Leaf.tsx": _leaf_body(sink_kind, "val"),
            "src/Root.tsx": "\n".join(root_lines),
        }
        target_file = "src/Leaf.tsx"

    else:  # hop == 2
        root_lines = (
            ["import Mid from './Mid';"]
            + header_lines
            + ["", "export default function Root() {"]
            + [f"  {l}" for l in body_source_lines]
            + [f"  return <Mid val={{{var}}} />;", "}", ""]
        )
        files = {
            "src/Leaf.tsx": _leaf_body(sink_kind, "val"),
            "src/Mid.tsx": _wrapper_body("Mid", "Leaf", "val"),
            "src/Root.tsx": "\n".join(root_lines),
        }
        target_file = "src/Leaf.tsx"

    return {
        "id": case_id,
        "title": title,
        "category": category,
        "sink": sink_kind,
        "hop": hop,
        "alias": alias,
        "expected_vulnerable": expected_vulnerable,
        "cve": cve,
        "files": files,
        "target_file": target_file,
    }


def _group_cve_2026() -> list[dict]:
    cases = []
    xss_cves = CVE_SEED["xss"][:25]
    ssrf_cves = CVE_SEED["ssrf"][:25]

    for i, (cve_id, desc) in enumerate(xss_cves):
        vulnerable = i % 2 == 0
        sink_kind = XSS_SINKS[i % len(XSS_SINKS)][0]
        hop = i % 3
        alias = (i % 4 == 0)
        cases.append(build_case(
            case_id=f"cve26-xss-{i+1:02d}",
            title=f"{cve_id} 패턴 ({sink_kind}, hop={hop}) — {desc[:60]}",
            sink_kind=sink_kind,
            expected_vulnerable=vulnerable,
            hop=hop,
            alias=alias,
            input_kind=USER_INPUT_TEMPLATES[i % 3][0] if vulnerable else None,
            param="q",
            asset_ext=ASSET_EXTS[i % len(ASSET_EXTS)],
            cve=cve_id,
        ))

    for i, (cve_id, desc) in enumerate(ssrf_cves):
        vulnerable = i % 2 == 0
        sink_kind = SSRF_SINKS[i % len(SSRF_SINKS)][0]
        hop = i % 3
        alias = (i % 4 == 1)
        cases.append(build_case(
            case_id=f"cve26-ssrf-{i+1:02d}",
            title=f"{cve_id} 패턴 ({sink_kind}, hop={hop}) — {desc[:60]}",
            sink_kind=sink_kind,
            expected_vulnerable=vulnerable,
            hop=hop,
            alias=alias,
            input_kind=USER_INPUT_TEMPLATES[(i + 1) % 3][0] if vulnerable else None,
            param="target",
            asset_ext=ASSET_EXTS[(i + 2) % len(ASSET_EXTS)],
            cve=cve_id,
        ))
    return cases


def _group_structural() -> list[dict]:
    cases = []
    n = 0
    combos = []
    for sink_kind, _ in XSS_SINKS + SSRF_SINKS:
        for hop in (0, 1, 2):
            for alias in (False, True):
                combos.append((sink_kind, hop, alias))
    # 50개로 자르되 vulnerable/safe 번갈아 배정해 균형 유지
    # (sink x hop x alias 조합이 42개뿐이라 일부는 다른 input/asset 조합으로 재사용해 채움)
    if len(combos) < 50:
        combos = combos + combos[: 50 - len(combos)]
    combos = combos[:50]
    for i, (sink_kind, hop, alias) in enumerate(combos):
        vulnerable = i % 2 == 0
        input_kind = USER_INPUT_TEMPLATES[i % 3][0] if vulnerable else None
        n += 1
        cases.append(build_case(
            case_id=f"struct-{n:02d}",
            title=f"구조 케이스: {sink_kind}, hop={hop}, alias={alias}, {'사용자입력' if vulnerable else '정적import'}",
            sink_kind=sink_kind,
            expected_vulnerable=vulnerable,
            hop=hop,
            alias=alias,
            input_kind=input_kind,
            param=f"p{i}",
            asset_ext=ASSET_EXTS[i % len(ASSET_EXTS)],
            cve=None,
        ))
    return cases


def build_all_cases() -> list[dict]:
    return _group_cve_2026() + _group_structural()


CASES = build_all_cases()


if __name__ == "__main__":
    v = sum(1 for c in CASES if c["expected_vulnerable"])
    s = len(CASES) - v
    print(f"총 {len(CASES)}개 | VULNERABLE(정답) {v} | SAFE(정답) {s}")
    by_cat = {}
    for c in CASES:
        by_cat[c["category"]] = by_cat.get(c["category"], 0) + 1
    print(by_cat)
    print("\n예시 케이스 (struct-01):")
    sample = next(c for c in CASES if c["id"] == "struct-01")
    for fn, content in sample["files"].items():
        print(f"--- {fn} ---\n{content}")
