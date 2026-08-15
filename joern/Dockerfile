# ScanOps Joern 워커 — RunPod serverless / 온프레미스 HTTP 공용 이미지
#
# 베이스는 Joern 공식 이미지(Apache-2.0). JDK·joern 배포본이 이미 들어 있어
# 우리 쪽은 python 런타임과 핸들러만 얹는다.
#
# 빌드:
#   docker buildx build --platform linux/amd64 -f joern/Dockerfile \
#     -t hansekim31/scanops-joern-worker:latest --push .
# 로컬:
#   docker build -f joern/Dockerfile -t scanops-joern-worker:local .
FROM ghcr.io/joernio/joern:master

# JVM 힙 상한 — 컨테이너 메모리의 절반 수준으로 잡는다. CPG는 스니펫 단위라
# 4g 면 청크 25건에 충분(실측치는 JOERN_HYBRID_REPORT.md §2 RSS 곡선 참조).
ENV JOERN_XMX=4g \
    JAVA_OPTS="-Xmx4g" \
    _JAVA_OPTIONS="-Xmx4g" \
    JOERN_WORK_ROOT=/tmp \
    JOERN_CHUNK=25 \
    JOERN_CASE_TIMEOUT=90 \
    PYTHONUNBUFFERED=1

USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pip python3-venv \
 && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"
RUN pip install --no-cache-dir runpod fastapi "uvicorn[standard]" pydantic requests

WORKDIR /app
COPY joern/ /app/joern/
ENV JOERN_SCRIPT=/app/joern/queries/taint.sc \
    PYTHONPATH=/app

# 서버리스: RUNPOD_MODE=1 → runpod.serverless.start
# 온프레미스: 아래 CMD 를 덮어써서 uvicorn 으로 기동 (docker-compose.onprem.yml 참조)
ENV RUNPOD_MODE=1
CMD ["python3", "-m", "joern.handler_joern"]
