#!/usr/bin/env python3
"""Reproducible local Java CPG worker smoke: candidates, cross-file taint, sanitizer."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
os.environ.setdefault("JOERN_BIN", str(ROOT / "joern" / "joern_docker.sh"))
os.environ.setdefault("JOERN_WORK_ROOT", "/tmp")
os.environ.setdefault("JOERN_REPO_ROOT", str(ROOT))
sys.path.insert(0, str(ROOT))

from joern.handler_joern import run_repo_script  # noqa: E402

FILES = [
    {"path": "demo/Input.java", "content": """package demo;
import javax.servlet.http.HttpServletRequest;
class Input { static String read(HttpServletRequest req) { return req.getParameter("q"); } }
"""},
    {"path": "demo/App.java", "content": """package demo;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
class App { void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
  String value = Input.read(req);
  resp.getWriter().println(value);
} }
"""},
    {"path": "demo/Safe.java", "content": """package demo;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.util.HtmlUtils;
class Safe { void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
  String value = req.getParameter("q");
  String escaped = HtmlUtils.htmlEscape(value);
  resp.getWriter().println(escaped);
} }
"""},
    {"path": "demo/Library.java", "content": """package demo;
import java.io.IOException;
public class Library {
  public void run(String command) throws IOException { Runtime.getRuntime().exec(command); }
}
"""},
    {"path": "demo/Stateful.java", "content": """package demo;
import java.io.IOException;
public class Stateful {
  private final String command;
  public Stateful(String command) { this.command = command; }
  public void run() throws IOException { Runtime.getRuntime().exec(this.command); }
}
"""},
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    candidates = run_repo_script("java-smoke-candidates", "candidates", "Java", FILES, timeout=300)
    spec = "source\t-\t-\tname\t^getParameter$\n" \
           "sink\txss\tCWE-79\tname\t^println$\n" \
           "sink\tcmdi\tCWE-78\tname\t^exec$\n"
    sanitizers = "JAVASRC.xss\txss\tHtmlUtils\\.htmlEscape\\s*\\(\n"
    taint = run_repo_script(
        "java-smoke-taint", "taint", "Java", FILES,
        spec_text=spec, san_text=sanitizers, src_mode="java", arm="S2C", timeout=300)

    cdata = candidates.get("data") or {}
    findings = (taint.get("data") or {}).get("findings") or []
    vulnerable = [x for x in findings if not x.get("sanitized")]
    safe = [x for x in findings if x.get("sanitized")]
    cross_file = [x for x in vulnerable if x.get("source_file") != x.get("file")]
    checks = {
        "candidate_frontend_java": cdata.get("lang") == "JAVASRC",
        "candidate_getParameter": any(x.get("name") == "getParameter" for x in cdata.get("calls", [])),
        "candidate_println": any(x.get("name") == "println" for x in cdata.get("calls", [])),
        "vulnerable_sink_line": any(x.get("file") == "demo/App.java" and x.get("line") == 7
                                    for x in vulnerable),
        "cross_file_path": bool(cross_file),
        "public_data_boundary": any(
            x.get("file") == "demo/Library.java" and "String command" in x.get("source", "")
            for x in vulnerable),
        "java_state_boundary": any(
            x.get("file") == "demo/Stateful.java" and "this.command" in x.get("source", "")
            for x in vulnerable),
        "response_context_not_source": not any(
            "HttpServletResponse" in x.get("source", "") for x in findings),
        "sanitizer_hit": any(x.get("file") == "demo/Safe.java" for x in safe),
        "no_rule_errors": not (taint.get("data") or {}).get("rule_errors"),
    }
    result = {"pass": all(checks.values()), "checks": checks,
              "candidates": candidates, "taint": taint}
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered)
    print(json.dumps({"pass": result["pass"], "checks": checks}, ensure_ascii=False, indent=2))
    if not result["pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
