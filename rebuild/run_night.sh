#!/bin/bash
# 야간 자동 실행: 병합 대기 → (커널 경로 빠르면 그걸로) → llama.cpp 빌드 → GGUF 변환·양자화 → 채점
cd /workspace/rebuild

echo "NIGHT_START $(date)"

# 1. 병합 완료 대기 (최대 40분)
for i in $(seq 1 120); do grep -q MERGED_OK merge.log 2>/dev/null && break; sleep 20; done
grep -q MERGED_OK merge.log || { echo "NIGHT_FAIL_MERGE"; exit 1; }
echo "NIGHT_MERGE_DONE $(date)"

# 2. 커널 경로가 살아났는지 확인 — 1건 생성이 30초 미만이면 transformers로 채점
FAST=""
if grep -q "ELAPSED_GEN" timing3.log 2>/dev/null; then
  SECS=$(grep -oE "ELAPSED_GEN: [0-9]+" timing3.log | grep -oE "[0-9]+$" | head -1)
  [ -n "$SECS" ] && [ "$SECS" -lt 30 ] && FAST=1
fi
pkill -9 -f "time, [e]val_test" 2>/dev/null
sleep 3
if [ -n "$FAST" ]; then
  echo "NIGHT_PATH_TRANSFORMERS"
  HF_HOME=/workspace/hf python eval_test.py > eval.log 2>&1 \
    && { echo "NIGHT_EVAL_DONE"; exit 0; } \
    || echo "NIGHT_TRANSFORMERS_FAILED_FALLBACK_GGUF"
fi

# 3. llama.cpp 빌드 (CUDA)
echo "NIGHT_PATH_GGUF"
if [ ! -x /workspace/llama.cpp/build/bin/llama-server ]; then
  apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq cmake build-essential libcurl4-openssl-dev >/dev/null 2>&1
  [ -d /workspace/llama.cpp ] || git clone --depth 1 https://github.com/ggml-org/llama.cpp /workspace/llama.cpp >/dev/null 2>&1
  cd /workspace/llama.cpp
  cmake -B build -DGGML_CUDA=ON -DLLAMA_CURL=OFF > cmake_cfg.log 2>&1 || { echo "NIGHT_FAIL_CMAKE"; exit 1; }
  cmake --build build -j 12 --target llama-quantize llama-server > cmake_build.log 2>&1 || { echo "NIGHT_FAIL_BUILD"; exit 1; }
fi
echo "NIGHT_BUILD_DONE $(date)"

# 4. GGUF 변환 + Q4_K_M 양자화
pip install -q --break-system-packages gguf sentencepiece >/dev/null 2>&1
cd /workspace/llama.cpp
if [ ! -f /workspace/rebuild/out/model-q4km.gguf ]; then
  python3 convert_hf_to_gguf.py /workspace/rebuild/out/merged \
    --outfile /workspace/rebuild/out/model-bf16.gguf --outtype bf16 > /workspace/rebuild/convert.log 2>&1 \
    || { echo "NIGHT_FAIL_CONVERT"; exit 1; }
  echo "NIGHT_CONVERT_DONE $(date)"
  ./build/bin/llama-quantize /workspace/rebuild/out/model-bf16.gguf \
    /workspace/rebuild/out/model-q4km.gguf Q4_K_M >> /workspace/rebuild/convert.log 2>&1 \
    || { echo "NIGHT_FAIL_QUANT"; exit 1; }
  rm -f /workspace/rebuild/out/model-bf16.gguf
fi
echo "NIGHT_QUANT_DONE $(date)"

# 5. 서버 기동 → 채점
./build/bin/llama-server -m /workspace/rebuild/out/model-q4km.gguf \
  -ngl 99 -c 4608 --parallel 4 --port 8080 > /workspace/rebuild/server.log 2>&1 &
SRV=$!
UP=""
for i in $(seq 1 60); do
  curl -s http://127.0.0.1:8080/health 2>/dev/null | grep -q '"ok"\|ok' && { UP=1; break; }; sleep 5
done
[ -n "$UP" ] || { echo "NIGHT_FAIL_SERVER"; kill $SRV 2>/dev/null; exit 1; }
echo "NIGHT_SERVER_UP $(date)"

cd /workspace/rebuild
python3 eval_gguf.py > eval_gguf.log 2>&1 && echo "NIGHT_EVAL_DONE $(date)" || echo "NIGHT_FAIL_EVAL"
kill $SRV 2>/dev/null
