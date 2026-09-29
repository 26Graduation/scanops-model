#!/bin/bash
# ScanOps v2(line) — RunPod QLoRA 학습 런북 (V2_RUN_SPEC.md rev.6 §10-8, §12)
#
# ━━ 원칙 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  · `train_qlora.py` 는 **파일 자체를 수정하지 않는다** (v1 FROZEN, §11/§13).
#    데이터 경로는 그 파일이 이미 지원하는 TRAIN_SPLIT/VAL_SPLIT 환경변수로만 주입한다
#    (`train_qlora.py:81` — 확인 완료). 그래서 별도 래퍼가 필요 없다.
#  · 하이퍼파라미터는 `train_qlora.py:35-43` 값을 **그대로** 쓴다. 단 하나의 예외가
#    MAX_SEQ_LEN 이다 — 4096 은 v1 이 *함수 조각* 입력용으로 고른 값인데 v2 는 파일 단위라
#    설계가 어긋나 있었다(실측: 정답 LINE 가시율 4k 68.4% vs 16k 90.2%, C/C++ 41%→75%).
#    2026-08-21 사용자 결정으로 **16384** 로 올린다. 치환은 `run_train_v2line_16k.py` 래퍼가
#    메모리에서만 수행하고 train_qlora.py 원본은 바이트 그대로 둔다.
#      MODEL_ID=unsloth/Qwen3.5-9B  MAX_SEQ_LEN=16384(변경)  LORA_RANK=16  LORA_ALPHA=32
#      LEARNING_RATE=2e-4  MAX_EPOCHS=3  EARLY_STOP_PATIENCE=3
#      BATCH_PER_DEVICE=2  GRAD_ACCUM=8  SEED=42
#  · **스윕 금지** (§12). 1회만 학습한다.
#  · v1 어댑터를 이어받지 않는다 — 새로 학습한다 (§1).
#
# ━━ 사전 준비 (로컬에서) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#   tar czf v2line_bundle.tgz \
#     rebuild/train_qlora.py rebuild/score_logprob.py rebuild/build_dataset.py \
#     rebuild/prompt_v2.py \
#     rebuild/data/train_v2line_all.jsonl rebuild/data/val_v2line_all.jsonl rebuild/data/test_v2line_all.jsonl
#   scp -P <PORT> v2line_bundle.tgz root@<POD_IP>:/workspace/
#   ssh -p <PORT> root@<POD_IP> 'cd /workspace && tar xzf v2line_bundle.tgz'
#
# ━━ 실행 (파드 안에서) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#   nohup bash rebuild/run_train_v2line_all.sh > run_v2line.log 2>&1 &
set -u
cd /workspace/rebuild
export HF_HOME=/workspace/hf
PIP="pip install -q --break-system-packages"

TAG=${TAG:-v2line_16k_r16_s42}
STAG=${STAG:-v2line}

echo "V2LINE_START $(date)"
nvidia-smi --query-gpu=name,memory.total --format=csv,noheader

# ── 환경 (v1과 동일 스택) ────────────────────────────────────────────────────
$PIP unsloth            || { echo "V2LINE_FAIL_UNSLOTH"; exit 1; }
$PIP flash-linear-attention || { echo "V2LINE_FAIL_FLA"; exit 1; }
# causal-conv1d 는 Mamba 계열 커널이라 Qwen3.5 QLoRA 에는 필요 없다.
# RunPod 이미지(CUDA 12.4)와 unsloth 가 끌어오는 torch(cu130)의 버전이 어긋나 빌드가 실패하는데,
# 실측으로 unsloth/FastLanguageModel/trl 은 이것 없이도 전부 정상 import 되고 CUDA 도 잡힌다.
# 그래서 **치명적 실패로 취급하지 않는다**(v1 run_v*.sh 는 exit 1 이었다 — 그 스크립트는 안 건드린다).
$PIP ninja packaging
$PIP --no-build-isolation causal-conv1d || echo "V2LINE_SKIP_CAUSALCONV1D (불필요 — 계속 진행)"
echo "V2LINE_INSTALL_DONE $(date)"

# ── 학습 전 자기검증: 데이터가 실제로 v2(line) 인지 확인하고 아니면 멈춘다 ──
python - <<'PY' || { echo "V2LINE_FAIL_PRECHECK"; exit 1; }
import json, sys
for sp in ("train_v2line_all", "val_v2line_all"):
    rows = [json.loads(l) for l in open(f"data/{sp}.jsonl")]
    assert rows, f"{sp} 비어 있음"
    bad = [r for r in rows if "\nLINE: " not in r["completion"]]
    assert not bad, f"{sp}: completion 에 LINE 줄이 없는 샘플 {len(bad)}건 — v1 데이터가 섞였다"
    assert all(" | " in r["prompt"] for r in rows), f"{sp}: 줄번호 표시가 없는 프롬프트가 있다"
    print(f"  {sp}: {len(rows)}건 · 5줄 포맷 OK · 줄번호 표시 OK")
print("PRECHECK_OK")
PY

# ── 학습: v1 어댑터를 덮어쓰지 않도록 출력 디렉터리를 분리한다 ──────────────
[ -d out/adapter ] && [ ! -d out/adapter_v1_backup ] && cp -r out/adapter out/adapter_v1_backup
# PYTHONPATH 로 sitecustomize.py 를 태워 cuDNN SDP 백엔드를 끈다 (train_qlora.py 무수정).
PYTHONPATH=/workspace/rebuild \
TRAIN_SPLIT=train_v2line_all VAL_SPLIT=val_v2line_all \
  V2_MAX_SEQ_LEN=${V2_MAX_SEQ_LEN:-16384} python run_train_v2line_16k.py > train_$TAG.log 2>&1 \
  && echo "V2LINE_TRAIN_DONE $(date)" || { echo "V2LINE_FAIL_TRAIN $(date)"; exit 1; }

ADP=out/adapter
[ -d "$ADP" ] || ADP=$(ls -d out/checkpoints/checkpoint-* 2>/dev/null | sort -t- -k2 -n | tail -1)
echo "USING_ADAPTER $ADP"
cp -r "$ADP" "out/adapter_$TAG" 2>/dev/null || true

# ── ③ 내부 test AUC 의 근거 — score_logprob.py 를 **수정 없이** 재사용 (§9-1) ──
#    prefix "VULNERABILITY:" / 후보 " CWE" vs " NONE" / score = logP(CWE) − logP(NONE)
#    v2 도 첫 줄이 VULNERABILITY 라 전제가 유지된다 (LINE 은 두 번째 줄).
PYTHONPATH=/workspace/rebuild SCORE_MAX_LEN=${V2_MAX_SEQ_LEN:-16384} SCORE_BATCH=2 \
  python score_logprob.py "$ADP" "$STAG" test_v2line_all \
  > logprob_$TAG.log 2>&1 && echo "V2LINE_LOGPROB_DONE $(date)" || echo "V2LINE_FAIL_LOGPROB"

# ── 회수 묶음 ────────────────────────────────────────────────────────────────
tar czf /workspace/${TAG}_out.tgz out/${STAG}_*.jsonl *_$TAG.log 2>/dev/null
tar czf /workspace/${TAG}_adapter.tgz "out/adapter_$TAG" 2>/dev/null
ls -la /workspace/${TAG}_*.tgz
echo "V2LINE_ALL_DONE $(date)"
echo "회수: scp -P <PORT> root@<IP>:/workspace/${TAG}_*.tgz ."
