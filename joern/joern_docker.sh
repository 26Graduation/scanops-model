#!/usr/bin/env bash
# handler_joern.py 가 JOERN_BIN 으로 호출하는 래퍼 — joern 을 docker 컨테이너에서 실행한다.
#
# 핵심 제약: handler 가 넘기는 --param inDir/outFile/스크립트 경로는 **호스트 절대경로**다.
# 컨테이너 안에서 같은 경로로 보여야 하므로, 작업 루트와 레포를 **동일 경로로 마운트**한다.
#
# 환경변수:
#   JOERN_IMAGE      기본 ghcr.io/joernio/joern:master
#   JOERN_WORK_ROOT  작업 루트 (handler 와 동일해야 함)
#   JOERN_REPO_ROOT  스크립트(.sc)가 있는 레포 루트
#   JOERN_XMX        JVM 힙 상한 (기본 4g)
set -euo pipefail

IMAGE="${JOERN_IMAGE:-ghcr.io/joernio/joern:master}"
WORK_ROOT="${JOERN_WORK_ROOT:-/tmp}"
REPO_ROOT="${JOERN_REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
XMX="${JOERN_XMX:-4g}"
# Bash 3 + `set -u` errors when expanding an empty array. Keep the no-cidfile
# path explicit instead of relying on an optional empty array.
if [[ -n "${JOERN_CIDFILE:-}" ]]; then
  exec docker run --rm --cidfile "${JOERN_CIDFILE}" \
    --memory="${JOERN_DOCKER_MEM:-8g}" \
    -e JAVA_OPTS="-Xmx${XMX}" \
    -e _JAVA_OPTIONS="-Xmx${XMX}" \
    -v "${WORK_ROOT}:${WORK_ROOT}" \
    -v "${REPO_ROOT}:${REPO_ROOT}:ro" \
    -w "${WORK_ROOT}" \
    "${IMAGE}" \
    joern "$@"
fi

exec docker run --rm \
  --memory="${JOERN_DOCKER_MEM:-8g}" \
  -e JAVA_OPTS="-Xmx${XMX}" \
  -e _JAVA_OPTIONS="-Xmx${XMX}" \
  -v "${WORK_ROOT}:${WORK_ROOT}" \
  -v "${REPO_ROOT}:${REPO_ROOT}:ro" \
  -w "${WORK_ROOT}" \
  "${IMAGE}" \
  joern "$@"
