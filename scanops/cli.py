"""ScanOps CLI — 보안 취약점 스캐너."""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich import box

from scanops.core.rag import LLM_MODEL, OLLAMA_URL, QDRANT_URL, run_rag, stream_llm, build_prompt, search_cves
from scanops.core.scanner import scan_code, scan_file, scan_directory, ScanResult, Vulnerability

app = typer.Typer(name="scanops", help="ScanOps — 보안 취약점 분석 도구", add_completion=False)
console = Console()

SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange1",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold green",
    "UNKNOWN":  "dim",
}


# ── 공통 헬퍼 ───────────────────────────────────────────────────────────────────

def _severity_badge(sev: str) -> Text:
    style = SEVERITY_STYLE.get(sev.upper(), "dim")
    return Text(f"[{sev}]", style=style)


def _print_vuln(idx: int, v: Vulnerability, show_fix: bool = True) -> None:
    sev_style = SEVERITY_STYLE.get(v.severity, "dim")
    console.print(f"\n  [bold]{_severity_badge(v.severity)}[/bold]  취약점 #{idx}")
    console.print(f"   이름: [bold]{v.name}[/bold]")
    console.print(f"   CVE : {v.cve_id}")
    console.print(f"   CWE : {v.cwe_id}")
    score_str = f"{v.cvss_score}" if v.cvss_score else "N/A"
    console.print(f"   CVSS: [{sev_style}]{score_str} ({v.severity})[/{sev_style}]")
    console.print(f"   위치: {v.location}")
    if v.attack:
        console.print(f"   공격: {v.attack}")
    if show_fix and v.fix:
        console.print(f"   수정:")
        fix_lines = v.fix.splitlines()
        for line in fix_lines[:15]:
            console.print(f"     {line}")
        if len(fix_lines) > 15:
            console.print(f"     [dim]... ({len(fix_lines)-15}줄 더)[/dim]")

    if v.cve_references:
        ref_ids = [r["cve_id"] for r in v.cve_references[:3] if r.get("cve_id")]
        if ref_ids:
            console.print(f"   참조 CVE: {', '.join(ref_ids)}")


def _print_scan_result(result: ScanResult) -> None:
    title = Text()
    title.append("🔍 ScanOps 보안 취약점 분석\n", style="bold cyan")
    title.append(f"파일: {result.file_path} | 모델: {result.model} | {result.elapsed:.1f}s")
    console.print(Panel(title, border_style="cyan", padding=(0, 1)))

    if not result.vulnerabilities:
        console.print("\n  [green]취약점이 발견되지 않았습니다.[/green]")
        return

    total = len(result.vulnerabilities)
    crit = result.critical_count
    high = result.high_count
    console.print(
        f"\n  [bold]총 {total}개 취약점[/bold] "
        f"([bold red]CRITICAL {crit}[/bold red] / "
        f"[bold orange1]HIGH {high}[/bold orange1])"
    )

    for i, v in enumerate(result.vulnerabilities, 1):
        _print_vuln(i, v)

    console.print()


def _save_json(result: ScanResult, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = Path(result.file_path).stem
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = output_dir / f"scan_{stem}_{ts}.json"
    out_path.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    return out_path


# ── scan 명령 ──────────────────────────────────────────────────────────────────

@app.command()
def scan(
    target: str = typer.Argument(None, help="스캔할 파일 또는 디렉터리 경로"),
    code: str = typer.Option(None, "--code", "-c", help="직접 입력할 코드 스니펫"),
    language: str = typer.Option("Unknown", "--lang", "-l", help="코드 언어"),
    no_rag: bool = typer.Option(False, "--no-rag", help="CVE RAG 검색 비활성화"),
    model: str = typer.Option(LLM_MODEL, "--model", "-m", help="Ollama 모델명"),
    output: Path = typer.Option(None, "--output", "-o", help="JSON 결과 저장 디렉터리"),
) -> None:
    """파일/디렉터리 또는 코드 스니펫을 스캔합니다."""
    use_rag = not no_rag

    if code:
        result = scan_code(code, language=language, file_path="<stdin>", use_rag=use_rag, model=model)
        _print_scan_result(result)
        if output:
            p = _save_json(result, output)
            console.print(f"[dim]JSON 저장: {p}[/dim]")
        return

    if not target:
        console.print("[red]파일/디렉터리 경로 또는 --code 옵션이 필요합니다.[/red]")
        raise typer.Exit(1)

    path = Path(target)
    if not path.exists():
        console.print(f"[red]경로를 찾을 수 없습니다: {path}[/red]")
        raise typer.Exit(1)

    if path.is_file():
        with console.status("[cyan]스캔 중...[/cyan]"):
            result = scan_file(path, use_rag=use_rag, model=model)
        _print_scan_result(result)
        if output:
            p = _save_json(result, output)
            console.print(f"[dim]JSON 저장: {p}[/dim]")

    elif path.is_dir():
        with console.status("[cyan]디렉터리 스캔 중...[/cyan]"):
            results = scan_directory(path, use_rag=use_rag, model=model)
        if not results:
            console.print("[yellow]지원 파일이 없습니다.[/yellow]")
            return
        for r in results:
            _print_scan_result(r)
            if output:
                _save_json(r, output)
        total_vulns = sum(len(r.vulnerabilities) for r in results)
        console.print(Rule(f"[dim]{len(results)}개 파일, 총 {total_vulns}개 취약점[/dim]"))


# ── chat 명령 ──────────────────────────────────────────────────────────────────

@app.command()
def chat(
    model: str = typer.Option(LLM_MODEL, "--model", "-m"),
    top_k: int = typer.Option(5, "--top-k", "-k"),
) -> None:
    """CVE RAG 기반 대화형 취약점 분석 모드."""
    try:
        from qdrant_client import QdrantClient
        client = QdrantClient(url=QDRANT_URL)
        info = client.get_collection("cve_vulnerabilities")
        total = info.points_count
    except Exception as e:
        console.print(f"[bold red]Qdrant 연결 실패: {e}[/bold red]")
        console.print(f"[dim]docker run -d --name qdrant -p 6333:6333 qdrant/qdrant[/dim]")
        raise typer.Exit(1)

    banner = Text()
    banner.append("  ScanOps CVE Chat\n", style="bold cyan")
    banner.append(f"  DB: {total:,}개 CVE | 모델: {model} | /exit 종료\n", style="dim")
    console.print(Panel(banner, border_style="cyan"))

    severity_filter: str | None = None
    history: list[tuple[str, str]] = []

    while True:
        hint = f"[{severity_filter}] " if severity_filter else ""
        try:
            user_input = Prompt.ask(f"\n[bold cyan]▶[/bold cyan] {hint}").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[cyan]종료합니다.[/cyan]")
            break

        if not user_input:
            continue

        if user_input.startswith("/"):
            parts = user_input.split()
            cmd = parts[0].lower()
            if cmd == "/exit":
                break
            elif cmd == "/filter" and len(parts) >= 2:
                val = parts[1].upper()
                severity_filter = None if val == "OFF" else val
                console.print(f"[green]필터: {severity_filter or '전체'}[/green]")
            elif cmd == "/top" and len(parts) >= 2:
                try:
                    top_k = max(1, min(20, int(parts[1])))
                    console.print(f"[green]top-k: {top_k}[/green]")
                except ValueError:
                    pass
            continue

        try:
            with console.status("[cyan]Qdrant 검색 중...[/cyan]"):
                cves = search_cves(user_input, top_k=top_k, severity_filter=severity_filter)

            if not cves:
                console.print("[yellow]관련 CVE를 찾지 못했습니다.[/yellow]")
                continue

            _print_cve_table(cves, severity_filter)

            console.print(Rule("[dim]AI 분석[/dim]", style="dim"))
            prompt = build_prompt(user_input, cves)
            full = ""
            for token in stream_llm(prompt, model=model):
                console.print(token, end="", markup=False, highlight=False)
                full += token
            console.print()
            console.print(Rule(style="dim"))
            history.append((user_input, full))

        except Exception as e:
            console.print(f"[bold red]오류: {e}[/bold red]")


def _print_cve_table(cves: list[dict], severity_filter: str | None) -> None:
    table = Table(
        box=box.SIMPLE_HEAVY,
        border_style="dim",
        show_header=True,
        header_style="bold white",
        title=f"[dim]검색된 CVE ({len(cves)}개"
              + (f" | filter: {severity_filter}" if severity_filter else "") + ")[/dim]",
        title_justify="left",
    )
    table.add_column("#",     width=3,  justify="right")
    table.add_column("CVE",   width=20)
    table.add_column("Sev",   width=10)
    table.add_column("Score", width=6,  justify="right")
    table.add_column("Attack",width=10)
    table.add_column("CWE",   width=10)
    table.add_column("유사도",width=7,  justify="right")
    for i, c in enumerate(cves, 1):
        sev = c["severity"] or "N/A"
        table.add_row(
            str(i),
            c["cve_id"],
            Text(sev, style=SEVERITY_STYLE.get(sev, "white")),
            str(c["base_score"]),
            c["attack_vector"] or "N/A",
            c["cwe_id"] or "N/A",
            f"{c['score']:.3f}",
        )
    console.print(table)


# ── benchmark 명령 ─────────────────────────────────────────────────────────────

@app.command()
def benchmark(
    base_model: str = typer.Option("gemma:2b", "--base"),
    qwen_model: str = typer.Option("qwen2.5-coder:1.5b", "--qwen"),
    output: Path = typer.Option(Path("reports/benchmark_compare.json"), "--output", "-o"),
) -> None:
    """모델 벤치마크 — base vs Gemma-2 LoRA vs Qwen QLoRA 비교."""
    import subprocess, sys
    subprocess.run(
        [
            sys.executable, "-m", "scanops.models.benchmark",
            "--base-model", base_model,
            "--qwen-model", qwen_model,
            "--output", str(output),
        ],
        check=True,
    )


# ── db-prepare 명령 ────────────────────────────────────────────────────────────

@app.command(name="db-prepare")
def db_prepare(
    input_file: Path = typer.Argument(..., help="NVD JSON 파일"),
    collection: str = typer.Option("cve_vulnerabilities", "--collection"),
    recreate: bool = typer.Option(False, "--recreate"),
    raw: bool = typer.Option(False, "--raw", help="원본 NVD 피드 전처리 포함"),
) -> None:
    """NVD CVE 데이터를 Qdrant에 적재합니다."""
    import subprocess, sys
    args = [sys.executable, "-m", "scanops.data.prepare", "--input", str(input_file),
            "--collection", collection]
    if recreate:
        args.append("--recreate")
    if raw:
        args.append("--raw")
    subprocess.run(args, check=True)


# ── 진입점 ──────────────────────────────────────────────────────────────────────

def main() -> None:
    app()


if __name__ == "__main__":
    main()
