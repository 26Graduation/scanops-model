__all__ = [
    "ScanResult", "scan_code", "scan_file", "scan_directory",
    "search_cves", "run_rag",
    "get_embedder",
]


def __getattr__(name):
    if name in {"ScanResult", "scan_code", "scan_file", "scan_directory"}:
        from . import scanner
        return getattr(scanner, name)
    if name in {"search_cves", "run_rag"}:
        from . import rag
        return getattr(rag, name)
    if name == "get_embedder":
        from .embedder import get_embedder
        return get_embedder
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
