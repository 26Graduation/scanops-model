"""
CVE RAG CLI — 인터랙티브 취약점 분석 도구

실행:
  python3 src/cli.py

사용 가능한 명령어:
  /help              명령어 목록 출력
  /filter <severity> 심각도 필터 설정 (CRITICAL | HIGH | MEDIUM | LOW | off)
  /top <숫자>        검색 결과 수 변경 (기본 5)
  /history           이번 세션 질문 기록 출력
  /clear             화면 초기화
  /exit              종료
"""

import os
import sys
import json
import requests
from datetime import datetime
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.models import Filter, FieldCondition, MatchValue
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich.prompt import Prompt
from rich import box

# ── 설정 ───────────────────────────────────────────────────
EMBED_MODEL     = "BAAI/bge-small-en-v1.5"
QDRANT_URL      = "http://localhost:6333"
COLLECTION_NAME = "cve_vulnerabilities"
OLLAMA_URL      = "http://localhost:11434/api/generate"
LLM_MODEL       = "gemma2:2b"

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange1",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold green",
}

SYSTEM_PERSONA = """You are a cybersecurity vulnerability expert with deep knowledge of CVE databases.

Rules:
- Always present AT LEAST 3 vulnerabilities
- For each CVE: provide ID, severity, attack vector, and risk explanation
- Prioritize CRITICAL and HIGH severity
- Give practical remediation advice
- Be concise but thorough
- Always answer in Korean (한국어로 답변)"""

console = Console()


# ════════════════════════════════════════════════════════════
# 초기화
# ════════════════════════════════════════════════════════════
def init_clients():
    """임베딩 모델 + Qdrant 클라이언트를 한 번만 로드 (세션 내 재사용)."""
    with console.status("[bold cyan]임베딩 모델 로드 중...", spinner="dots"):
        model = SentenceTransformer(EMBED_MODEL)

    with console.status("[bold cyan]Qdrant 연결 중...", spinner="dots"):
        client = QdrantClient(url=QDRANT_URL)
        info = client.get_collection(COLLECTION_NAME)

    return model, client, info.points_count


# ════════════════════════════════════════════════════════════
# RAG 핵심 함수
# ════════════════════════════════════════════════════════════
def search_cves(model, client, query, top_k, severity_filter):
    vec = model.encode([query], normalize_embeddings=True, convert_to_numpy=True)[0].tolist()

    q_filter = None
    if severity_filter:
        q_filter = Filter(must=[FieldCondition(
            key="severity", match=MatchValue(value=severity_filter)
        )])

    results = client.query_points(
        collection_name=COLLECTION_NAME,
        query=vec,
        query_filter=q_filter,
        limit=top_k,
        with_payload=True,
    ).points

    return [
        {
            "score":            r.score,
            "cve_id":           r.payload.get("cve_id"),
            "severity":         r.payload.get("severity"),
            "base_score":       r.payload.get("base_score"),
            "attack_vector":    r.payload.get("attack_vector"),
            "cwe_id":           r.payload.get("cwe_id"),
            "affected_products": r.payload.get("affected_products", []),
            "cvss_vector":      r.payload.get("cvss_vector"),
            "description":      r.payload.get("description", ""),
        }
        for r in results
    ]


def build_prompt(query, cves):
    context_blocks = []
    for i, c in enumerate(cves, 1):
        products = ", ".join(c["affected_products"]) or "N/A"
        context_blocks.append(
            f"[CVE #{i}]\n"
            f"  ID: {c['cve_id']} | Severity: {c['severity']} (CVSS {c['base_score']})\n"
            f"  Attack Vector: {c['attack_vector']} | CWE: {c['cwe_id']}\n"
            f"  Products: {products}\n"
            f"  Description: {c['description']}"
        )
    context = "\n\n".join(context_blocks)

    return (
        f"### SYSTEM\n{SYSTEM_PERSONA}\n\n"
        f"### RETRIEVED CVE DATA\n{context}\n\n"
        f"### USER QUESTION\n{query}\n\n"
        f"### INSTRUCTIONS\n"
        f"Based on the retrieved CVE data, provide:\n"
        f"1. Brief summary of the vulnerability type\n"
        f"2. Each CVE with risk explanation\n"
        f"3. Remediation steps"
    )


def stream_llm(prompt):
    """Ollama 스트리밍 응답을 토큰 단위로 출력하고 전체 텍스트 반환."""
    payload = {
        "model":   LLM_MODEL,
        "prompt":  prompt,
        "stream":  True,
        "options": {"temperature": 0.3, "top_p": 0.9, "num_predict": 1024},
    }
    resp = requests.post(OLLAMA_URL, json=payload, stream=True, timeout=120)
    resp.raise_for_status()

    full = ""
    for line in resp.iter_lines():
        if line:
            chunk = json.loads(line)
            token = chunk.get("response", "")
            console.print(token, end="", markup=False, highlight=False)
            full += token
            if chunk.get("done"):
                console.print()
                break
    return full


# ════════════════════════════════════════════════════════════
# UI 출력 함수
# ════════════════════════════════════════════════════════════
def print_banner(total_cves):
    banner = Text()
    banner.append("  ScanOps CVE Analyst\n", style="bold cyan")
    banner.append(f"  Model: {LLM_MODEL}  |  ", style="dim")
    banner.append(f"DB: {total_cves:,}개 CVE 로드됨\n", style="dim")
    banner.append("  /help 로 명령어 확인\n", style="dim")
    console.print(Panel(banner, border_style="cyan", padding=(0, 1)))


def print_help():
    table = Table(box=box.ROUNDED, border_style="dim", show_header=True, header_style="bold cyan")
    table.add_column("명령어", style="bold yellow", width=22)
    table.add_column("설명")

    table.add_row("/filter CRITICAL", "CRITICAL 심각도 CVE만 검색")
    table.add_row("/filter HIGH",     "HIGH 심각도 CVE만 검색")
    table.add_row("/filter MEDIUM",   "MEDIUM 심각도 CVE만 검색")
    table.add_row("/filter LOW",      "LOW 심각도 CVE만 검색")
    table.add_row("/filter off",      "필터 해제 (전체 검색)")
    table.add_row("/top <숫자>",      "검색 결과 수 변경  예) /top 10")
    table.add_row("/history",         "이번 세션 질문 기록 출력")
    table.add_row("/clear",           "화면 초기화")
    table.add_row("/exit",            "종료")

    console.print(table)


def print_cve_table(cves, severity_filter):
    table = Table(
        box=box.SIMPLE_HEAVY,
        border_style="dim",
        show_header=True,
        header_style="bold white",
        title=f"[dim]검색된 CVE ({len(cves)}개"
              + (f"  |  filter: {severity_filter}" if severity_filter else "") + ")[/dim]",
        title_justify="left",
    )
    table.add_column("#",            width=3,  justify="right")
    table.add_column("CVE ID",       width=20)
    table.add_column("Severity",     width=10)
    table.add_column("Score",        width=6,  justify="right")
    table.add_column("Attack",       width=10)
    table.add_column("CWE",          width=10)
    table.add_column("유사도",       width=7,  justify="right")

    for i, c in enumerate(cves, 1):
        sev   = c["severity"] or "N/A"
        color = SEVERITY_COLORS.get(sev, "white")
        table.add_row(
            str(i),
            c["cve_id"],
            Text(sev, style=color),
            str(c["base_score"]),
            c["attack_vector"] or "N/A",
            c["cwe_id"] or "N/A",
            f"{c['score']:.3f}",
        )

    console.print(table)


def print_history(history):
    if not history:
        console.print("[dim]이번 세션에서 질문한 내용이 없습니다.[/dim]")
        return

    table = Table(box=box.SIMPLE, border_style="dim", show_header=True, header_style="bold white")
    table.add_column("#",    width=4, justify="right")
    table.add_column("시각", width=10)
    table.add_column("질문")

    for i, (ts, q) in enumerate(history, 1):
        table.add_row(str(i), ts, q)

    console.print(table)


# ════════════════════════════════════════════════════════════
# 명령어 처리
# ════════════════════════════════════════════════════════════
def handle_command(cmd, state):
    """
    /로 시작하는 명령어 처리.
    state 딕셔너리를 수정해 세션 상태를 업데이트.
    반환값: True(계속) | False(종료)
    """
    parts = cmd.strip().split()
    command = parts[0].lower()

    if command == "/exit":
        console.print("\n[bold cyan]세션을 종료합니다. 안녕히 가세요![/bold cyan]\n")
        return False

    elif command == "/help":
        print_help()

    elif command == "/clear":
        console.clear()
        print_banner(state["total_cves"])

    elif command == "/history":
        print_history(state["history"])

    elif command == "/filter":
        if len(parts) < 2:
            console.print("[red]사용법: /filter CRITICAL | HIGH | MEDIUM | LOW | off[/red]")
        else:
            val = parts[1].upper()
            if val == "OFF":
                state["severity_filter"] = None
                console.print("[green]필터 해제됨  →  전체 severity 검색[/green]")
            elif val in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                state["severity_filter"] = val
                color = SEVERITY_COLORS.get(val, "white")
                console.print(f"필터 설정: [{color}]{val}[/{color}]")
            else:
                console.print("[red]올바른 값: CRITICAL | HIGH | MEDIUM | LOW | off[/red]")

    elif command == "/top":
        if len(parts) < 2 or not parts[1].isdigit():
            console.print("[red]사용법: /top <숫자>  예) /top 10[/red]")
        else:
            n = int(parts[1])
            if 1 <= n <= 20:
                state["top_k"] = n
                console.print(f"[green]검색 결과 수 변경: {n}개[/green]")
            else:
                console.print("[red]1~20 사이 숫자를 입력하세요.[/red]")

    else:
        console.print(f"[red]알 수 없는 명령어: {command}  (/help 로 목록 확인)[/red]")

    return True


# ════════════════════════════════════════════════════════════
# 메인 루프
# ════════════════════════════════════════════════════════════
def main():
    # 서비스 연결
    try:
        model, qdrant, total_cves = init_clients()
    except Exception as e:
        console.print(f"[bold red]초기화 실패: {e}[/bold red]")
        console.print("[dim]Qdrant(6333)와 Ollama(11434)가 실행 중인지 확인하세요.[/dim]")
        sys.exit(1)

    # 세션 상태
    state = {
        "total_cves":     total_cves,
        "severity_filter": None,
        "top_k":          5,
        "history":        [],   # [(시각, 질문), ...]
    }

    console.clear()
    print_banner(total_cves)

    # ── 인터랙티브 루프 ────────────────────────────────────
    while True:
        # 프롬프트 표시
        filter_hint = f"[{state['severity_filter']}] " if state["severity_filter"] else ""
        try:
            user_input = Prompt.ask(
                f"\n[bold cyan]▶[/bold cyan] {filter_hint}"
            ).strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[bold cyan]종료합니다.[/bold cyan]")
            break

        if not user_input:
            continue

        # 명령어 분기
        if user_input.startswith("/"):
            if not handle_command(user_input, state):
                break
            continue

        # 일반 질문 → RAG 실행
        state["history"].append((datetime.now().strftime("%H:%M:%S"), user_input))

        try:
            # ① + ② 검색
            with console.status("[cyan]Qdrant 검색 중...[/cyan]", spinner="dots"):
                cves = search_cves(
                    model, qdrant,
                    user_input,
                    state["top_k"],
                    state["severity_filter"],
                )

            if not cves:
                console.print("[yellow]관련 CVE를 찾지 못했습니다. 필터를 확인하세요.[/yellow]")
                continue

            # 검색 결과 테이블 출력
            console.print()
            print_cve_table(cves, state["severity_filter"])

            # ③④⑤ 프롬프트 조립 + LLM 응답
            console.print(Rule("[dim]AI 분석[/dim]", style="dim"))
            prompt = build_prompt(user_input, cves)
            stream_llm(prompt)
            console.print(Rule(style="dim"))

        except requests.exceptions.ConnectionError:
            console.print("[bold red]Ollama 연결 실패. `brew services start ollama` 확인[/bold red]")
        except Exception as e:
            console.print(f"[bold red]오류: {e}[/bold red]")


if __name__ == "__main__":
    main()
