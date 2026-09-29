#!/usr/bin/env bash
set -e
echo "[1/3] 베이스 모델 pull (공개, ~4.7GB, 1회)"
ollama pull qwen2.5-coder:7b-instruct
echo "[2/3] v13 어댑터 등록"
ollama create qwen2.5-coder-security-v13-7b -f Modelfile.v13
echo "[3/3] v16.1 어댑터 등록"
ollama create qwen2.5-coder-security-v16-1-7b -f Modelfile.v16_1
echo "완료. 등록된 모델:"
ollama list | grep security-v1 || true
