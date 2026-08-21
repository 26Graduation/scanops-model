"""ScanOps v2 — 프롬프트/포맷 SINGLE SOURCE OF TRUTH (V2_RUN_SPEC.md rev.6 §7·§8-2·§11).

이 파일 하나가 v2의 프롬프트 조립·줄번호 표시·4096 토큰 예산 처리를 전부 가진다.
`collect_files_v2.py` / `build_dataset_v2.py` / `bench_v2.py` / `scripts/api_rebuild.py`(v2 분기)
는 **전부 이 파일을 import 해서 쓴다.** 같은 로직을 두 번 구현하지 않는다 (§11).

왜 단일 소스인가: CLAUDE.md "프롬프트 템플릿 불변식" 항목 자체가 과거에 학습/평가/서빙 세 곳의
프롬프트가 어긋나 실패한 적이 있다는 뜻이다. "바이트 단위로 같다"를 사람이 매번 대조하는 대신
**코드 구조가 보장**하게 한다.

v1(`build_dataset.py`, FROZEN) 대비 바뀐 것은 정확히 두 가지뿐이다:
  1. `{code}` 자리에 **줄번호가 붙은** 소스가 들어간다 (§7, `"{line_no:>4} | {source}"`)
  2. 출력 형식에 **`LINE:` 한 줄이 2번째 줄로** 추가된다 (§1)

주의: `build_dataset.py` 는 v1 FROZEN 이므로 **import 만 하고 수정하지 않는다** (§11·§12).
그 파일의 모듈 docstring 이 "completion 로직만 재사용할 때 datasets 미설치로 막히지 않도록"
지연 import 를 해뒀다고 명시하고 있으므로, 여기서 import 하는 것은 의도된 사용이다.
"""
from __future__ import annotations

import re

# v1 FROZEN 파일에서 등급/REASON 산출 로직만 그대로 가져온다 (§7 "새 규칙 만들지 말 것").
from build_dataset import derive_severity, extract_reason  # noqa: F401  (재수출)

# ── §8-2 토큰 예산 상수 ──────────────────────────────────────────────────────
# MAX_SEQ_LEN 의 실제 출처는 `rebuild/train_qlora.py:36` 이다.
#   (V2_RUN_SPEC §8-2 는 `rebuild/config.py` 라고 적었지만 그 파일은 존재하지 않는다 —
#    PHASE 0 에서 확인. 값 4096 자체는 train_qlora.py 에서 확인된 그대로다.)
# 2026-08-21 사용자 결정: v2 는 **파일 단위 입력**인데 4096 은 v1 이 *함수 조각* 용으로 고른
# 값이라 설계가 어긋나 있었다. 실측(vuln 500건 표본)으로 정답 LINE 가시율이
#   4k 68.4% / 8k 81.0% / 16k 90.2% / 32k 96.4%
# 이고 특히 C/C++ 는 4k 에서 41.1% 밖에 못 본다 → 16k 로 올린다.
# `V2_MAX_SEQ_LEN` 환경변수로 덮어쓸 수 있게 해서 4k 재현도 가능하게 남긴다.
MAX_SEQ_LEN = int(__import__("os").environ.get("V2_MAX_SEQ_LEN", "16384"))
# 고정 상수. 파일럿에서 실제 completion 길이를 "측정"만 하고 이 값 자체는 바꾸지 않는다
# (§8-2·§13 사전등록 원칙). 128 을 넘는 completion 은 format_overflow 로 집계한다.
COMPLETION_RESERVE_TOKENS = 128

# ── §7 line-numbering 표시 포맷 (학습·평가·서빙 어디서도 다른 포맷을 쓰지 않는다) ──
LINE_NUMBERING_FORMAT = "{line_no:>4} | {source}"


def format_source_with_line_numbers(source: str) -> str:
    """소스 전문 → 줄번호가 붙은 텍스트 (§7).

    `LINE` 라벨은 **이 numbering 의 1-based 번호**를 뜻한다. 그리고 그 번호는
    pre-fix 파일(`git show <hash>~1:<path>`)의 1-based 줄 번호와 동일하다 —
    git diff 의 라인 번호 체계(수정 전 기준)와 pre-fix 파일 자체의 줄 번호 체계가
    같기 때문이다. 이 사실은 암묵적으로 가정하지 않고 여기에 명시해 둔다 (§7 원문 요구).
    """
    lines = source.split("\n")
    return "\n".join(
        LINE_NUMBERING_FORMAT.format(line_no=i, source=ln)
        for i, ln in enumerate(lines, start=1)
    )


# ── 프롬프트 템플릿 ──────────────────────────────────────────────────────────
# v1 `build_dataset.py:115` PROMPT_TMPL 을 베이스로, 출력 형식에 LINE 한 줄만 추가했다.
# 그 외 문구는 한 글자도 바꾸지 않는다 (v1 대비 변수를 늘리지 않기 위해 — §12 "한 번에 한 변수").
PROMPT_TMPL_V2 = """Analyze the following {language} code for security vulnerabilities.

```{language}
{code}
```

Respond in exactly this format:
VULNERABILITY: <CWE-id (CWE name)> or NONE
LINE: <line number> or 0
SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN> or NONE
CVSS: <score 0.0-10.0> or 0.0
REASON: <one-line explanation> or NONE"""

# §7-1: negative 샘플의 정답. VULNERABILITY=NONE 이면 LINE=0 이 정답이다.
SAFE_COMPLETION_V2 = (
    "VULNERABILITY: NONE\nLINE: 0\nSEVERITY: NONE\nCVSS: 0.0\nREASON: NONE"
)


def vuln_completion_v2(cwe_id: str, cwe_name: str, line: int,
                       sev: str, cvss: str, reason: str) -> str:
    """positive 샘플의 정답 5줄 (§1). LINE 은 반드시 1 이상 (§7-1 / §10-1 fail-fast)."""
    cwe_id = (cwe_id or "").strip()
    cwe_name = (cwe_name or "").strip()
    head = f"{cwe_id} ({cwe_name})" if cwe_name else cwe_id
    return (f"VULNERABILITY: {head}\n"
            f"LINE: {line}\n"
            f"SEVERITY: {sev}\n"
            f"CVSS: {cvss}\n"
            f"REASON: {reason}")


def build_prompt_v2(numbered_source: str, language: str) -> str:
    """줄번호가 이미 붙은 소스 + 언어 → 최종 user 메시지 문자열."""
    return PROMPT_TMPL_V2.format(language=language, code=numbered_source)


# ── §8-2 토큰 실측 유틸 ──────────────────────────────────────────────────────
def _chat_wrap(prompt: str, tokenizer) -> str:
    """§8-2 ③ — messages 를 chat template 으로 감싼다.

    `train_qlora.py:76` 이 학습 때 하는 것과 동일한 호출이다. 4096 은 raw prompt 토큰 수가
    아니라 **Qwen 채팅 특수 토큰까지 포함한, 모델이 실제로 받는 시퀀스 길이**다 (§8-2 rev.5).
    """
    return tokenizer.apply_chat_template(
        [{"role": "user", "content": prompt}], tokenize=False
    )


def _n_tokens(text: str, tokenizer) -> int:
    """실측. 추정하지 않는다 (§8-2 ④)."""
    return len(tokenizer(text, add_special_tokens=False)["input_ids"])


def build_generation_prompt(prompt: str, tokenizer) -> str:
    """추론(bench·서빙)에서 모델에 실제로 먹일 전체 텍스트.

    **학습 텍스트의 접두사와 바이트 단위로 같아야 한다.** 실측해서 확인한 형태:

        학습(user+assistant) :
            <|im_start|>user\\n{p}<|im_end|>\\n<|im_start|>assistant\\n<think>\\n\\n</think>\\n\\n{답}<|im_end|>\\n
        추론 프리필           :
            <|im_start|>user\\n{p}<|im_end|>\\n<|im_start|>assistant\\n<think>\\n\\n</think>\\n\\n
                              = apply_chat_template(..., add_generation_prompt=True, enable_thinking=False)

    즉 `enable_thinking=False` 를 주어야 `<think>\\n\\n</think>\\n\\n` 까지 붙어 학습 접두사와 일치한다.

    ⚠ v1 은 이게 어긋나 있었다: `rebuild/repo_bench_scan.py:40` / `scripts/api_rebuild.py:190` 의
      `CHATML_TMPL = "<|im_start|>user\\n{p}<|im_end|>\\n<|im_start|>assistant\\n"` 는 `<think>` 블록이
      빠져 있어 학습 텍스트와 바이트 동일이 아니었다. v1 은 FROZEN(§11·§12)이라 이번 라운드에
      고치지 않고 V2_RESULTS.md 의 `후속 개선사항` 에 남긴다. v2 는 처음부터 맞춰 간다.
      (참고: `rebuild/score_logprob.py` 는 이미 add_generation_prompt=True, enable_thinking=False
       를 쓰고 있어서 §9-1 의 "score_logprob.py 를 수정 없이 재사용" 전제는 그대로 유효하다.)
    """
    return tokenizer.apply_chat_template(
        [{"role": "user", "content": prompt}],
        tokenize=False, add_generation_prompt=True, enable_thinking=False,
    )


# 모델 출력 5줄 파서 — bench_v2 / api_rebuild(v2) 가 공유한다 (§11 단일 소스).
_LINE_PAT = {
    "vulnerability": re.compile(r"^\s*VULNERABILITY:\s*(.+?)\s*$", re.M),
    "line":          re.compile(r"^\s*LINE:\s*(-?\d+)", re.M),
    "severity":      re.compile(r"^\s*SEVERITY:\s*(.+?)\s*$", re.M),
    "cvss":          re.compile(r"^\s*CVSS:\s*(.+?)\s*$", re.M),
    "reason":        re.compile(r"^\s*REASON:\s*(.+?)\s*$", re.M),
}


def parse_output_v2(raw: str) -> dict:
    """5줄 출력 → 구조화. 형식이 깨지면 label='parse_fail'.

    §7-1 의 형식 일관성 규칙도 여기서 판정한다:
      VULNERABILITY=NONE 인데 LINE≠0, 또는 VULNERABILITY≠NONE 인데 LINE=0 → format_inconsistent.
      이런 출력은 exact-line 정오답 계산에 넣지 않고 별도 집계한다.
    """
    got = {k: (m.group(1) if (m := p.search(raw)) else None) for k, p in _LINE_PAT.items()}
    v = got["vulnerability"]
    if v is None:
        return {"label": "parse_fail", "cwe": "", "line": None,
                "severity": "", "cvss": "", "format_inconsistent": False}
    is_none = v.strip().upper().startswith("NONE")
    try:
        line = int(got["line"]) if got["line"] is not None else None
    except ValueError:
        line = None
    inconsistent = (line is not None) and ((is_none and line != 0) or (not is_none and line == 0))
    return {
        "label": "safe" if is_none else "vuln",
        "cwe": "" if is_none else v.strip(),
        "line": line,
        "severity": (got["severity"] or "").strip(),
        "cvss": (got["cvss"] or "").strip(),
        "reason": (got["reason"] or "").strip(),
        "format_inconsistent": inconsistent,
    }


def count_input_tokens(numbered_source: str, language: str, tokenizer) -> int:
    """§8-2 ②~④ 를 한 번 수행해 input_tokens 를 실측한다."""
    return _n_tokens(_chat_wrap(build_prompt_v2(numbered_source, language), tokenizer),
                     tokenizer)


def count_completion_tokens(completion: str, tokenizer) -> int:
    """completion 이 시퀀스에서 실제로 차지하는 토큰 수를 실측한다.

    학습 텍스트는 `apply_chat_template([user, assistant])` 로 만들어지고, 이때 user 부분은
    `apply_chat_template([user])` 의 결과가 **그대로 접두사**가 된다(PHASE 2 에서 실측 확인).
    따라서 completion 이 차지하는 몫 = 전체 − user 부분 이며, Qwen 이 assistant 턴에 넣는
    `<|im_start|>assistant\\n<think>\\n\\n</think>\\n\\n` 와 `<|im_end|>\\n` 까지 포함된다.
    COMPLETION_RESERVE_TOKENS(128) 가 진짜 상한이 되려면 이 몫으로 재야 한다.
    """
    user_only = tokenizer.apply_chat_template(
        [{"role": "user", "content": "X"}], tokenize=False)
    full = tokenizer.apply_chat_template(
        [{"role": "user", "content": "X"}, {"role": "assistant", "content": completion}],
        tokenize=False)
    return _n_tokens(full, tokenizer) - _n_tokens(user_only, tokenizer)


def build_input_within_budget(source: str, language: str, tokenizer,
                              line: int | None = None) -> dict:
    """§8-2 확정 정책 — 최종 조립 후 직접 tokenize 해서 실측하고, 넘으면 뒤에서 잘라 반복.

    절차 (매 샘플마다, §8-2 ①~⑥):
      ① format_source_with_line_numbers() 로 줄번호 붙은 소스 전체를 만든다
      ② PROMPT_TMPL_V2 에 끼워 최종 user 메시지를 조립한다
      ③ apply_chat_template() 으로 감싼다
      ④ 실제 tokenizer 로 tokenize 해서 input_tokens 를 얻는다 (추정 금지)
      ⑤ input_tokens + 128 > 4096 이면 소스 **뒷부분(파일 뒤쪽)** 을 줄 경계에서 잘라내고 ②~④ 재계산
         — **LINE 위치를 보고 자르지 않는다.** 정답과 무관하게 결정론적으로 뒤에서부터 자른다.
           (정답이 보이도록 창을 고르면 학습만 쉬워지는 누수가 된다 — §8-2 rev.3)
      ⑥ 만족할 때까지 반복. 만족하면 truncated / line_in_visible_context 를 계산해 리턴.

    `line` 은 **계산 결과를 보고**하기 위해서만 쓰인다 — 자르는 위치 결정에는 절대 쓰지 않는다.

    반복 횟수를 줄이려고 이분 탐색을 쓰지만, 이는 §8-2 가 허용한 "최적화용 첫 추정치"일 뿐이고
    **최종 확정은 항상 ④의 실측값**이다 (리턴 직전에 불변식을 실측으로 재검증한다).

    리턴: §7 스키마의 토큰/절단 관련 필드들.
    """
    budget = MAX_SEQ_LEN - COMPLETION_RESERVE_TOKENS
    all_lines = source.split("\n")
    total_lines = len(all_lines)

    def numbered(n_keep: int) -> str:
        return "\n".join(
            LINE_NUMBERING_FORMAT.format(line_no=i, source=ln)
            for i, ln in enumerate(all_lines[:n_keep], start=1)
        )

    def toks(n_keep: int) -> int:
        return count_input_tokens(numbered(n_keep), language, tokenizer)

    full_tokens = toks(total_lines)
    if full_tokens <= budget:
        n_keep, input_tokens, truncated = total_lines, full_tokens, False
    else:
        # 이분 탐색으로 예산에 맞는 최대 줄 수를 찾는다 (전부 실측 호출).
        lo, hi, best = 0, total_lines, 0
        best_tok = toks(0)
        while lo <= hi:
            mid = (lo + hi) // 2
            t = toks(mid)
            if t <= budget:
                best, best_tok, lo = mid, t, mid + 1
            else:
                hi = mid - 1
        n_keep, input_tokens, truncated = best, best_tok, True

    numbered_source = numbered(n_keep)
    prompt = build_prompt_v2(numbered_source, language)

    # ⑥ 불변식 실측 재검증 — 이분 탐색 결과를 믿지 않고 다시 잰다.
    final_tokens = count_input_tokens(numbered_source, language, tokenizer)
    assert final_tokens == input_tokens, "실측 불일치 — 토큰화가 비결정적이다"
    assert final_tokens + COMPLETION_RESERVE_TOKENS <= MAX_SEQ_LEN, (
        f"불변식 위반: {final_tokens} + {COMPLETION_RESERVE_TOKENS} > {MAX_SEQ_LEN}")

    # 줄 경계에서만 자르므로 한 줄이 반으로 잘리는 일이 없다 → 정답 줄은 온전히 있거나 아예 없다.
    # (§8-2 의 "한 글자라도 잘렸으면 false" 라는 엄격 기준을 구조적으로 만족시킨다.)
    if line is None or line == 0:
        line_visible = True          # negative 샘플(LINE=0)은 볼 것이 없으므로 항상 True
    else:
        line_visible = bool(1 <= line <= n_keep)

    # 참고용 분해값. prompt_tokens = 코드가 비어 있을 때의 틀 비용, code_tokens = 나머지.
    prompt_tokens = toks(0)
    return {
        "prompt": prompt,
        "numbered_source": numbered_source,
        "language": language,
        "file_lines_total": total_lines,
        "lines_kept": n_keep,
        "prompt_tokens": prompt_tokens,
        "code_tokens": final_tokens - prompt_tokens,
        "input_tokens": final_tokens,
        "completion_reserve_tokens": COMPLETION_RESERVE_TOKENS,
        "max_sequence_tokens": MAX_SEQ_LEN,
        "truncated": truncated,
        "line_in_visible_context": line_visible,
        "line_numbering_format": LINE_NUMBERING_FORMAT,
    }
