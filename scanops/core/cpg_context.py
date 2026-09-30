"""Attach real Joern context without promoting AI candidates into proven taint flows."""
def attach(files, results, call_worker):
    paths = {f["path"] for f in files}
    pending = [(r.file_path, f) for r in results if r.file_path in paths
               for f in r.findings if f.get("source", "").startswith("qwen-")
               and not f.get("cpg_graph") and type(f.get("line")) is int]
    for start in range(0, len(pending), 128):
        batch = pending[start:start + 128]
        targets = [{"id": str(i), "file": path, "line": f["line"]}
                   for i, (path, f) in enumerate(batch)]
        try:
            response = call_worker("context", "Java", files, targets=targets)
            data = response.get("data") or {}
            contexts = {x["id"]: x.get("graph") for x in data.get("contexts", [])}
            for i, (_, finding) in enumerate(batch):
                graph = contexts.get(str(i))
                if (isinstance(graph, dict) and graph.get("origin") == "joern"
                        and graph.get("evidence") == "code-context" and graph.get("nodes")):
                    finding["cpg_graph"] = graph
                else:
                    finding["cpg_graph_status"] = "no-matching-code"
        except Exception:
            for _, finding in batch:
                finding["cpg_graph_status"] = "export-unavailable"
