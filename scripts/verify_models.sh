#!/usr/bin/env bash
# 오프라인 번들 검증 — models/ 의 파일이 MODELS.sha256 과 일치하는지 확인한다.
# 사용: ./scripts/verify_models.sh [models_dir]
set -euo pipefail
dir="${1:-models}"
manifest="$dir/MODELS.sha256"
[[ -f "$manifest" ]] || { echo "체크섬 파일이 없다: $manifest" >&2; exit 2; }
cd "$dir"
if shasum -a 256 -c "$(basename "$manifest")"; then
  echo "모든 모델 파일 검증 통과."
else
  echo "검증 실패 — 파일이 손상됐거나 다른 버전이다." >&2
  exit 1
fi
