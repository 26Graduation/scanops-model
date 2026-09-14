#!/usr/bin/env bash
# ScanOps — 온프레미스 모델 파일 확보 (편의 스크립트)
#
# ⚠️ 망분리(에어갭) 환경에서는 이 스크립트를 쓰지 않는다.
#    기본 공급 방식은 **오프라인 번들**이다 — models/ 에 파일을 두고 SHA256 을 검증한다.
#    (scanops-infra/README_onprem.md "모델 공급" 절)
#
# 사용:
#   MODEL_URL=https://.../Qwen3.5-9B-Q4_K_M.gguf \
#   MODEL_SHA256=03b747... \
#   ./scripts/fetch_model.sh models/
#
# 인증이 필요하면:
#   MODEL_AUTH_HEADER="Authorization: Bearer <token>" ./scripts/fetch_model.sh models/
set -euo pipefail

dest_dir="${1:-models}"
url="${MODEL_URL:-}"
want_sha="${MODEL_SHA256:-}"

if [[ -z "$url" ]]; then
  echo "MODEL_URL 이 필요하다. 오프라인 번들을 쓰려면 이 스크립트 대신" >&2
  echo "파일을 $dest_dir 에 직접 두고 verify_models.sh 로 검증하라." >&2
  exit 2
fi

mkdir -p "$dest_dir"
fname="$(basename "${url%%\?*}")"
out="$dest_dir/$fname"

echo "다운로드: $url → $out"
if [[ -n "${MODEL_AUTH_HEADER:-}" ]]; then
  curl -fL --retry 3 -H "$MODEL_AUTH_HEADER" -o "$out" "$url"
else
  curl -fL --retry 3 -o "$out" "$url"
fi

if [[ -n "$want_sha" ]]; then
  got="$(shasum -a 256 "$out" | awk '{print $1}')"
  if [[ "$got" != "$want_sha" ]]; then
    echo "SHA256 불일치!" >&2
    echo "  기대: $want_sha" >&2
    echo "  실제: $got" >&2
    exit 1
  fi
  echo "SHA256 검증 통과: $got"
else
  echo "경고: MODEL_SHA256 미지정 — 무결성 검증을 건너뛴다." >&2
fi
