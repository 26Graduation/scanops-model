FROM python:3.11-slim

WORKDIR /app

# 시스템 의존성
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Python 의존성 설치 (캐시 레이어)
COPY requirements.txt .
RUN pip install --no-cache-dir \
    fastapi>=0.100 \
    uvicorn[standard]>=0.23 \
    pydantic>=2.0 \
    requests>=2.31 \
    httpx>=0.27 \
    python-dotenv>=1.0 \
    qdrant-client>=1.9 \
    sentence-transformers>=2.7 \
    rich>=13

# 소스 복사
COPY scripts/ ./scripts/
COPY src/ ./src/
COPY scanops/ ./scanops/

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

EXPOSE 8100

CMD ["sh", "-c", "uvicorn scripts.api_server:app --host 0.0.0.0 --port ${PORT:-8100}"]
