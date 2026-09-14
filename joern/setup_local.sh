#!/usr/bin/env bash
# ScanOps — 로컬(macOS) Joern 에서 JavaScript 분석을 쓰기 위한 astgen 연결
#
# 왜 필요한가 (실측):
#   Homebrew 로 설치한 joern 4.0.570 은 JS 프론트엔드(jssrc2cpg)가 쓰는 astgen 바이너리를
#   `<joern>/bin/astgen/astgen-macos-arm` 고정 경로에서 찾는데, 그 디렉토리가 없다.
#   그래서 JS 파일이 전부 parse_fail 이 된다(2026-08-16 실측: 102/102).
#   ASTGEN_BIN 환경변수는 무시된다(실측).
#
# 컨테이너에는 이 문제가 없다:
#   공식 이미지 ghcr.io/joernio/joern:master 에는
#   /opt/joern/joern-cli/frontends/jssrc2cpg/bin/astgen/astgen-linux 가 이미 들어 있고
#   JS 파싱이 그대로 동작한다(2026-08-17 컨테이너 안에서 CPG 생성 확인).
#   → **Dockerfile 은 손댈 필요가 없다.** 이 스크립트는 로컬 개발용이다.
#
# astgen 공식 배포: https://github.com/joernio/astgen/releases (플랫폼별 바이너리)
#   현재 최신 v3.42.0 — astgen-linux / astgen-linux-arm / astgen-macos /
#   astgen-macos-arm / astgen-win.exe
#
# 사용:
#   ./joern/setup_local.sh install   # 링크 생성
#   ./joern/setup_local.sh remove    # 링크 제거
#   ./joern/setup_local.sh status    # 현재 상태
set -euo pipefail

joern_bin="$(command -v joern || true)"
if [[ -z "$joern_bin" ]]; then
  echo "joern 이 PATH 에 없다. brew install joern 후 다시 실행." >&2
  exit 1
fi

# Homebrew 래퍼 → 실제 설치 디렉토리
real="$(readlink -f "$joern_bin" 2>/dev/null || echo "$joern_bin")"
prefix="$(dirname "$(dirname "$real")")"      # .../joern/<ver>
astgen_dir="$prefix/bin/astgen"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) want="astgen-macos-arm" ;;
  Darwin-x86_64) want="astgen-macos" ;;
  Linux-aarch64) want="astgen-linux-arm" ;;
  Linux-x86_64) want="astgen-linux" ;;
  *) echo "지원하지 않는 플랫폼: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

case "${1:-status}" in
  install)
    src="$(command -v astgen || true)"
    if [[ -z "$src" ]]; then
      echo "astgen 이 PATH 에 없다. 아래 중 하나로 설치한 뒤 다시 실행:" >&2
      echo "  brew install astgen" >&2
      echo "  또는 https://github.com/joernio/astgen/releases 에서 $want 내려받아 PATH 에" >&2
      exit 1
    fi
    mkdir -p "$astgen_dir"
    ln -sf "$src" "$astgen_dir/$want"
    echo "생성: $astgen_dir/$want -> $src"
    ;;
  remove)
    rm -rf "$astgen_dir"
    echo "제거: $astgen_dir"
    ;;
  status)
    if [[ -e "$astgen_dir/$want" ]]; then
      ls -la "$astgen_dir/$want"
    else
      echo "링크 없음: $astgen_dir/$want (JS 분석이 parse_fail 이 된다)"
    fi
    ;;
  *)
    echo "사용법: $0 {install|remove|status}" >&2; exit 1 ;;
esac
