# ScanOps V17 RunPod Serverless 워커 — Ollama + v13/v16.1 어댑터 베이크
# 빌드(레포 루트에서):
#   docker build --platform linux/amd64 -t hansekim31/scanops-v17-worker:latest -f runpod/Dockerfile .
#   docker push hansekim31/scanops-v17-worker:latest
# 레이어 순서 주의: 모델 베이크(무거움)를 먼저, handler.py(자주 바뀜)를 마지막에 —
# handler 수정 시 모델 레이어 캐시가 유지돼 재빌드·재푸시가 수 초/수 MB로 끝남.
FROM ollama/ollama:latest

RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install --no-cache-dir --break-system-packages runpod requests

WORKDIR /app
COPY deploy_v17/v13_7b_lora.gguf deploy_v17/v16_1_7b_lora.gguf ./
COPY deploy_v17/Modelfile.v13 deploy_v17/Modelfile.v16_1 ./

# 빌드 타임에 모델 등록 (ollama serve를 잠깐 띄워서) — 베이스 4.7GB + 어댑터 2개
RUN ollama serve & \
    sleep 5 && \
    ollama pull qwen2.5-coder:7b-instruct && \
    ollama create qwen2.5-coder-security-v13-7b -f Modelfile.v13 && \
    ollama create qwen2.5-coder-security-v16-1-7b -f Modelfile.v16_1 && \
    pkill ollama || true

# GGUF 원본은 ollama 레이어로 들어갔으니 중복 제거
RUN rm -f v13_7b_lora.gguf v16_1_7b_lora.gguf

# ── 자주 바뀌는 것들은 여기 아래에만 ──────────────────────────────
COPY runpod/handler.py ./

ENV WARM_MODEL=qwen2.5-coder-security-v13-7b
ENTRYPOINT []
CMD ["python3", "-u", "handler.py"]
