"""Codebase graph and lightweight taint analysis for ScanOps.

This module builds a small code knowledge graph from the files submitted to
ScanOps. It is intentionally conservative: it only suppresses a finding when it
can explain that the suspicious value is a static import, and it only boosts a
finding when user-controlled data reaches a dangerous sink.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


STATIC_ASSET_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".avif",
    ".css", ".scss", ".sass", ".module.css",
}

CODE_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx"}


@dataclass
class CodeFile:
    filename: str
    language: str
    content: str


@dataclass
class GraphEvidence:
    category: str
    verdict: str
    filename: str
    variable: str
    sink: str
    source: str
    path: list[str]
    summary: str
    confidence: float

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "verdict": self.verdict,
            "filename": self.filename,
            "variable": self.variable,
            "sink": self.sink,
            "source": self.source,
            "path": self.path,
            "summary": self.summary,
            "confidence": self.confidence,
        }


@dataclass
class CodeGraph:
    files: dict[str, CodeFile] = field(default_factory=dict)
    imports: dict[tuple[str, str], str] = field(default_factory=dict)
    component_imports: dict[tuple[str, str], str] = field(default_factory=dict)
    component_props: dict[tuple[str, str], set[str]] = field(default_factory=dict)
    prop_flows: dict[tuple[str, str], tuple[str, str, str]] = field(default_factory=dict)
    user_inputs: dict[tuple[str, str], str] = field(default_factory=dict)
    aliases: dict[tuple[str, str], str] = field(default_factory=dict)
    sinks: list[dict] = field(default_factory=list)

    def evidence(self) -> list[GraphEvidence]:
        rows: list[GraphEvidence] = []
        for sink in self.sinks:
            filename = sink["filename"]
            variable = sink["variable"]
            category = sink["category"]
            source, path = self.resolve_source(filename, variable)

            if source.startswith("static import"):
                rows.append(GraphEvidence(
                    category=category,
                    verdict="safe",
                    filename=filename,
                    variable=variable,
                    sink=sink["sink"],
                    source=source,
                    path=path,
                    summary=(
                        f"{variable} is resolved to {source}; no user-controlled "
                        f"flow reaches {sink['sink']}."
                    ),
                    confidence=0.92,
                ))
            elif source.startswith("user input"):
                rows.append(GraphEvidence(
                    category=category,
                    verdict="tainted",
                    filename=filename,
                    variable=variable,
                    sink=sink["sink"],
                    source=source,
                    path=path,
                    summary=(
                        f"User-controlled value {variable} flows into {sink['sink']} "
                        f"via {' -> '.join(path)}."
                    ),
                    confidence=0.9,
                ))
            else:
                rows.append(GraphEvidence(
                    category=category,
                    verdict="unknown",
                    filename=filename,
                    variable=variable,
                    sink=sink["sink"],
                    source=source,
                    path=path,
                    summary=(
                        f"Could not prove whether {variable} is user-controlled before "
                        f"it reaches {sink['sink']}."
                    ),
                    confidence=0.45,
                ))
        return rows

    def resolve_source(self, filename: str, variable: str) -> tuple[str, list[str]]:
        seen: set[tuple[str, str]] = set()
        current = variable
        path = [variable]

        for _ in range(8):
            key = (filename, current)
            if key in seen:
                return "cycle in local data flow", path
            seen.add(key)

            if key in self.user_inputs:
                return f"user input: {self.user_inputs[key]}", path

            if key in self.imports:
                return f"static import: {self.imports[key]}", path

            if key in self.prop_flows:
                source_file, source_var, component = self.prop_flows[key]
                path.append(f"{component}.{current} <- {Path(source_file).name}:{source_var}")
                filename = source_file
                current = source_var
                continue

            alias = self.aliases.get(key)
            if not alias:
                return "unknown source", path
            current = alias
            path.append(current)

        return "unknown source", path


def build_code_graph(files: Iterable[CodeFile]) -> CodeGraph:
    graph = CodeGraph()
    for file in files:
        if Path(file.filename).suffix.lower() not in CODE_EXTENSIONS:
            continue
        graph.files[file.filename] = file
    for file in graph.files.values():
        _extract_imports(graph, file)
        _extract_user_inputs(graph, file)
        _extract_aliases(graph, file)
        _extract_component_props(graph, file)
        _extract_sinks(graph, file)
    for file in graph.files.values():
        _extract_prop_flows(graph, file)
    return graph


def evidence_for_finding(
    graph: CodeGraph,
    filename: str | None,
    vulnerability: str,
) -> list[GraphEvidence]:
    category = _vuln_category(vulnerability)
    rows = [e for e in graph.evidence() if e.category == category]
    if filename:
        scoped = [e for e in rows if e.filename == filename]
        if scoped:
            return scoped
    return rows


def evidence_from_neo4j(
    analysis_id: str,
    filename: str | None,
    vulnerability: str,
) -> list[GraphEvidence]:
    """Read graph evidence from Neo4j using Cypher.

    This is the Neo4j-backed path: Python extracts and syncs the graph, then
    Cypher checks whether a dangerous sink is reached from a static import or a
    user-controlled source. If Neo4j is not configured, callers can fall back to
    the in-memory graph.
    """
    uri = os.getenv("NEO4J_URI")
    if not uri:
        return []

    try:
        from neo4j import GraphDatabase
    except ImportError:
        return []

    category = _vuln_category(vulnerability)
    if category == "other":
        return []

    user = os.getenv("NEO4J_USER", "neo4j")
    password = os.getenv("NEO4J_PASSWORD", "scanops-password")
    database = os.getenv("NEO4J_DATABASE", "neo4j")

    with GraphDatabase.driver(uri, auth=(user, password)) as driver:
        with driver.session(database=database) as session:
            rows = session.run(
                """
                MATCH (:Analysis {id: $analysis_id})-[:CONTAINS_FILE]->(file:File)
                MATCH (target:Variable)-[:FLOWS_TO]->(sink:DangerousSink {category: $category})
                WHERE target.file = file.path
                  AND ($filename IS NULL OR target.file = $filename)
                OPTIONAL MATCH staticPath=(source:Variable)-[:PASSED_AS_PROP*0..6]->(target)
                OPTIONAL MATCH (source)-[:RESOLVES_TO]->(asset:StaticImport)
                OPTIONAL MATCH taintPath=(input:UserInput)-[:FLOWS_TO]->(userVar:Variable)
                  -[:PASSED_AS_PROP*0..6]->(target)
                WITH target, sink, asset, input, staticPath, taintPath
                RETURN target.file AS filename,
                       target.name AS variable,
                       sink.kind AS sink,
                       sink.category AS category,
                       asset.path AS static_source,
                       input.source AS user_source,
                       [n IN nodes(staticPath) | coalesce(n.name, n.path, n.source)] AS static_path,
                       [n IN nodes(taintPath) | coalesce(n.name, n.path, n.source)] AS taint_path
                """,
                analysis_id=analysis_id,
                filename=filename,
                category=category,
            )
            evidence = [_row_to_evidence(row) for row in rows]

    # Prefer proven evidence over unknown rows produced by variable-length paths.
    if any(e.verdict == "tainted" for e in evidence):
        return [e for e in evidence if e.verdict == "tainted"]
    if any(e.verdict == "safe" for e in evidence):
        return [e for e in evidence if e.verdict == "safe"]
    return evidence


def should_suppress_finding(vulnerability: str, evidence: list[GraphEvidence]) -> bool:
    """Return True only for high-confidence false-positive patterns."""
    category = _vuln_category(vulnerability)
    if category != "xss" or not evidence:
        return False
    has_tainted = any(e.verdict == "tainted" for e in evidence)
    has_static_safe = any(e.verdict == "safe" and "static import" in e.source for e in evidence)
    return has_static_safe and not has_tainted


def kg_risk_score(cvss_score: float | None, evidence: list[GraphEvidence]) -> float | None:
    if cvss_score is None and not evidence:
        return None
    score = cvss_score if cvss_score is not None else 5.0
    if any(e.verdict == "tainted" for e in evidence):
        score += 0.9
    if any(e.verdict == "safe" for e in evidence):
        score -= 1.0
    if any(e.verdict == "unknown" for e in evidence):
        score -= 0.2
    return round(max(0.0, min(10.0, score)), 1)


def _extract_imports(graph: CodeGraph, file: CodeFile) -> None:
    for match in re.finditer(
        r"import\s+([A-Za-z_$][\w$]*)\s+from\s+['\"]([^'\"]+)['\"]",
        file.content,
    ):
        name, source = match.groups()
        if _is_static_asset(source):
            graph.imports[(file.filename, name)] = source
        elif source.startswith("."):
            target = _resolve_import_path(graph, file.filename, source)
            if target:
                graph.component_imports[(file.filename, name)] = target


def _extract_user_inputs(graph: CodeGraph, file: CodeFile) -> None:
    patterns = [
        (
            r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
            r"(?:new\s+URLSearchParams\([^)]*\)|searchParams|params)\.get\(['\"]([^'\"]+)['\"]\)",
            "URLSearchParams.get('{param}')",
        ),
        (
            r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
            r"(?:req\.query|request\.query)\.([A-Za-z_$][\w$]*)",
            "request query '{param}'",
        ),
        (
            r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
            r"(?:location|window\.location)\.(?:search|href)",
            "window.location",
        ),
    ]
    for pattern, label in patterns:
        for match in re.finditer(pattern, file.content):
            var = match.group(1)
            param = match.group(2) if match.lastindex and match.lastindex >= 2 else "value"
            graph.user_inputs[(file.filename, var)] = label.format(param=param)


def _extract_aliases(graph: CodeGraph, file: CodeFile) -> None:
    for match in re.finditer(
        r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\b",
        file.content,
    ):
        target, source = match.groups()
        if target != source:
            graph.aliases[(file.filename, target)] = source


def _extract_component_props(graph: CodeGraph, file: CodeFile) -> None:
    patterns = [
        r"function\s+([A-Z][A-Za-z0-9_$]*)\s*\(\s*\{([^}]*)\}",
        r"(?:const|let|var)\s+([A-Z][A-Za-z0-9_$]*)\s*=\s*\(\s*\{([^}]*)\}",
        r"(?:const|let|var)\s+([A-Z][A-Za-z0-9_$]*)\s*=\s*\{\s*([^}]*)\}\s*=>",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, file.content):
            component, raw_props = match.groups()
            props = _parse_destructured_props(raw_props)
            if props:
                graph.component_props[(file.filename, component)] = props


def _extract_prop_flows(graph: CodeGraph, file: CodeFile) -> None:
    jsx_pattern = re.compile(r"<([A-Z][A-Za-z0-9_$]*)\b([^>]*)>")
    prop_pattern = re.compile(r"([A-Za-z_$][\w$]*)=\{([A-Za-z_$][\w$]*)\}")

    for jsx in jsx_pattern.finditer(file.content):
        component, attrs = jsx.groups()
        target_file = graph.component_imports.get((file.filename, component))
        if not target_file:
            continue
        declared_props = graph.component_props.get((target_file, component), set())
        for prop_match in prop_pattern.finditer(attrs):
            prop_name, source_var = prop_match.groups()
            if declared_props and prop_name not in declared_props:
                continue
            graph.prop_flows[(target_file, prop_name)] = (file.filename, source_var, component)


def _extract_sinks(graph: CodeGraph, file: CodeFile) -> None:
    sink_patterns = [
        ("xss", "img src", r"<img\b[^>]*\bsrc=\{([A-Za-z_$][\w$]*)\}"),
        (
            "xss",
            "dangerouslySetInnerHTML",
            r"dangerouslySetInnerHTML=\{\{\s*__html\s*:\s*([A-Za-z_$][\w$]*)\s*\}\}",
        ),
        ("xss", "innerHTML", r"\.innerHTML\s*=\s*([A-Za-z_$][\w$]*)"),
        ("ssrf", "fetch", r"\bfetch\s*\(\s*([A-Za-z_$][\w$]*)"),
        ("ssrf", "axios request", r"axios\.(?:get|post|request)\s*\(\s*([A-Za-z_$][\w$]*)"),
    ]
    for category, sink, pattern in sink_patterns:
        for match in re.finditer(pattern, file.content):
            graph.sinks.append({
                "category": category,
                "sink": sink,
                "variable": match.group(1),
                "filename": file.filename,
            })


def _is_static_asset(source: str) -> bool:
    suffix = Path(source.split("?", 1)[0]).suffix.lower()
    return suffix in STATIC_ASSET_EXTENSIONS


def _row_to_evidence(row) -> GraphEvidence:
    filename = row["filename"]
    variable = row["variable"]
    sink = row["sink"]
    category = row["category"]

    if row["user_source"]:
        path = [p for p in (row["taint_path"] or []) if p]
        return GraphEvidence(
            category=category,
            verdict="tainted",
            filename=filename,
            variable=variable,
            sink=sink,
            source=f"user input: {row['user_source']}",
            path=path or [variable],
            summary=f"Neo4j found user-controlled data flowing into {sink}: {' -> '.join(path)}.",
            confidence=0.93,
        )

    if row["static_source"]:
        path = [p for p in (row["static_path"] or []) if p]
        return GraphEvidence(
            category=category,
            verdict="safe",
            filename=filename,
            variable=variable,
            sink=sink,
            source=f"static import: {row['static_source']}",
            path=path or [variable],
            summary=f"Neo4j resolved {variable} to static import {row['static_source']}; no user input path was found.",
            confidence=0.94,
        )

    return GraphEvidence(
        category=category,
        verdict="unknown",
        filename=filename,
        variable=variable,
        sink=sink,
        source="unknown source",
        path=[variable],
        summary=f"Neo4j found {variable} reaching {sink}, but no trusted or tainted source was proven.",
        confidence=0.5,
    )


def _parse_destructured_props(raw_props: str) -> set[str]:
    props = set()
    for chunk in raw_props.split(","):
        name = chunk.strip().split(":", 1)[0].split("=", 1)[0].strip()
        if re.fullmatch(r"[A-Za-z_$][\w$]*", name):
            props.add(name)
    return props


def _resolve_import_path(graph: CodeGraph, filename: str, source: str) -> str | None:
    base = Path(filename).parent
    candidate = (base / source).as_posix()
    possible = [candidate]
    possible.extend(candidate + ext for ext in (".tsx", ".jsx", ".ts", ".js"))
    possible.extend((Path(candidate) / f"index{ext}").as_posix() for ext in (".tsx", ".jsx", ".ts", ".js"))

    normalized_files = {_normalize_path(name): name for name in graph.files}
    for item in possible:
        found = normalized_files.get(_normalize_path(item))
        if found:
            return found
    return None


def _normalize_path(value: str) -> str:
    return Path(value).as_posix().lstrip("./")


def _vuln_category(name: str) -> str:
    low = (name or "").lower()
    if "ssrf" in low or "request forgery" in low:
        return "ssrf"
    if "xss" in low or "cross-site script" in low or "cross site script" in low:
        return "xss"
    return "other"


def neo4j_enabled() -> bool:
    return os.getenv("NEO4J_URI", "") != ""


def sync_to_neo4j(graph: CodeGraph, analysis_id: str = "latest") -> bool:
    """Persist the extracted code graph to Neo4j when the driver is available.

    The API still works without Neo4j. When NEO4J_URI is configured, this stores
    the latest analysis graph so Neo4j Browser can visualize File -> Variable ->
    Source/Sink relationships during demos.
    """
    uri = os.getenv("NEO4J_URI")
    if not uri:
        return False

    try:
        from neo4j import GraphDatabase
    except ImportError:
        return False

    user = os.getenv("NEO4J_USER", "neo4j")
    password = os.getenv("NEO4J_PASSWORD", "scanops-password")
    database = os.getenv("NEO4J_DATABASE", "neo4j")

    with GraphDatabase.driver(uri, auth=(user, password)) as driver:
        with driver.session(database=database) as session:
            session.run(
                """
                MERGE (a:Analysis {id: $analysis_id})
                SET a.updatedAt = datetime()
                """,
                analysis_id=analysis_id,
            ).consume()

            for file in graph.files.values():
                session.run(
                    """
                    MERGE (a:Analysis {id: $analysis_id})
                    MERGE (f:File {path: $filename})
                    SET f.language = $language
                    MERGE (a)-[:CONTAINS_FILE]->(f)
                    """,
                    analysis_id=analysis_id,
                    filename=file.filename,
                    language=file.language,
                ).consume()

            for (filename, variable), source in graph.imports.items():
                session.run(
                    """
                    MERGE (f:File {path: $filename})
                    MERGE (v:Variable {file: $filename, name: $variable})
                    MERGE (s:StaticImport {path: $source})
                    MERGE (f)-[:DECLARES]->(v)
                    MERGE (v)-[:RESOLVES_TO]->(s)
                    """,
                    filename=filename,
                    variable=variable,
                    source=source,
                ).consume()

            for (filename, variable), source in graph.user_inputs.items():
                session.run(
                    """
                    MERGE (f:File {path: $filename})
                    MERGE (v:Variable {file: $filename, name: $variable})
                    MERGE (u:UserInput {source: $source})
                    MERGE (f)-[:DECLARES]->(v)
                    MERGE (u)-[:FLOWS_TO]->(v)
                    """,
                    filename=filename,
                    variable=variable,
                    source=source,
                ).consume()

            for sink in graph.sinks:
                session.run(
                    """
                    MERGE (f:File {path: $filename})
                    MERGE (v:Variable {file: $filename, name: $variable})
                    MERGE (s:DangerousSink {file: $filename, kind: $sink, category: $category})
                    MERGE (f)-[:DECLARES]->(v)
                    MERGE (v)-[:FLOWS_TO]->(s)
                    """,
                    filename=sink["filename"],
                    variable=sink["variable"],
                    sink=sink["sink"],
                    category=sink["category"],
                ).consume()

            for (filename, component), props in graph.component_props.items():
                for prop in props:
                    session.run(
                        """
                        MERGE (f:File {path: $filename})
                        MERGE (c:Component {file: $filename, name: $component})
                        MERGE (p:Prop {file: $filename, component: $component, name: $prop})
                        MERGE (f)-[:DECLARES_COMPONENT]->(c)
                        MERGE (c)-[:DECLARES_PROP]->(p)
                        """,
                        filename=filename,
                        component=component,
                        prop=prop,
                    ).consume()

            for (target_file, prop), (source_file, source_var, component) in graph.prop_flows.items():
                session.run(
                    """
                    MERGE (source:Variable {file: $source_file, name: $source_var})
                    MERGE (target:Variable {file: $target_file, name: $prop})
                    MERGE (component:Component {file: $target_file, name: $component})
                    MERGE (source)-[:PASSED_AS_PROP {name: $prop}]->(target)
                    MERGE (target)-[:BELONGS_TO_COMPONENT]->(component)
                    """,
                    source_file=source_file,
                    source_var=source_var,
                    target_file=target_file,
                    prop=prop,
                    component=component,
                ).consume()

    return True
