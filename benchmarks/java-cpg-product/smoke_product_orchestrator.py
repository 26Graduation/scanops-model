#!/usr/bin/env python3
"""Exercise analyze_repo end to end with local Joern Docker and live Qwen3.8-Max."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for line in (ROOT / ".env").read_text().splitlines():
    if "=" in line and not line.lstrip().startswith("#"):
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
os.environ.setdefault("JOERN_BIN", str(ROOT / "joern" / "joern_docker.sh"))
os.environ.setdefault("JOERN_WORK_ROOT", "/tmp")
os.environ.setdefault("JOERN_REPO_ROOT", str(ROOT))
os.environ["GRAPH_SPEC_LLM_MODEL"] = "qwen3.8-max"
os.environ["GRAPH_SPEC_CRITIC_ENABLED"] = "off"
sys.path.insert(0, str(ROOT))

from joern.handler_joern import run_repo_script  # noqa: E402
from scanops.core import graph_spec_prod as graph  # noqa: E402
from smoke_product_cpg import FILES  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--seed-cache", type=Path)
    args = parser.parse_args()
    if args.out.exists() or args.cache.exists():
        raise SystemExit("refusing to overwrite an existing run artifact")
    if args.seed_cache:
        args.cache.parent.mkdir(parents=True, exist_ok=True)
        args.cache.write_text(args.seed_cache.read_text())
    graph.API_CACHE_PATH = args.cache
    # Satisfy analyze_repo's configured-worker readiness check; calls are replaced by the
    # in-process Docker adapter below rather than sent to this sentinel URL.
    graph.JOERN_HTTP_URL = "local://joern"

    def local_joern(mode: str, language: str, files: list[dict], **kwargs) -> dict:
        return run_repo_script(f"orchestrator-{mode}", mode, language, files,
                               timeout=300, **kwargs)

    graph.call_joern_repo = local_joern
    findings = graph.analyze_repo(FILES, "Java Spring Boot", repo_tag="g0-product-smoke")
    checks = {
        "model_is_qwen38_max": graph.LLM_MODEL == "qwen3.8-max",
        "critic_default_off": not graph.CRITIC_ENABLED,
        "java_prompt_and_frontend": graph.language_context("Java Spring Boot") == ("JAVASRC", "Java"),
        "cross_file_vulnerability": any(
            x.get("file") == "demo/App.java" and x.get("source_file") == "demo/Input.java"
            for x in findings),
        "safe_file_filtered": not any(x.get("file") == "demo/Safe.java" for x in findings),
        "sink_line_present": bool(findings) and all(
            isinstance(x.get("line"), int) and x["line"] > 0 for x in findings),
        "path_present": bool(findings) and all(x.get("path") for x in findings),
        "frontend_cache": args.cache.exists() and all(
            key.startswith("JAVASRC:") for key in json.loads(args.cache.read_text())),
    }
    result = {"pass": all(checks.values()), "checks": checks, "findings": findings,
              "cache_path": str(args.cache), "model": graph.LLM_MODEL}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2))
    print(json.dumps({"pass": result["pass"], "checks": checks,
                      "finding_count": len(findings)}, ensure_ascii=False, indent=2))
    if not result["pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
