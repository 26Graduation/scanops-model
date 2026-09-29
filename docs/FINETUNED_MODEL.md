# 기존 파인튜닝 모델 — Qwen3.5-9B QLoRA v1

**학습 코드와 실제 학습된 가중치를 모두 제공합니다.**
현재 Java CPG + LLM 엔진과 구분되는 기존 파인튜닝 라인입니다.
기존 비Java 서비스는 이 계열의 RunPod 서빙 경로를 유지합니다.
아래 파일은 로컬에 보관된 v1 학습 산출물이며, 운영 RunPod 볼륨과의 현재 바이트 일치까지 확인한 것은 아닙니다.

## 다운로드

[GitHub Release: finetuned-v1-20260914](https://github.com/26Graduation/scanops-model/releases/tag/finetuned-v1-20260914)

| 파일 | 용도 |
|---|---|
| `adapter_v1_fix.gguf` | llama.cpp용 학습 어댑터 (약 58MB); 베이스 GGUF와 함께 사용 |
| `scanops-qlora-v1-peft.tar.gz` | 원본 PEFT 어댑터, 설정, 토크나이저, 채팅 템플릿 |
| `SHA256SUMS` | 릴리스 파일 무결성 확인 |

베이스는 [고정 버전 Qwen3.5-9B-Q4_K_M.gguf](https://huggingface.co/unsloth/Qwen3.5-9B-GGUF/resolve/3885219b6810b007914f3a7950a8d1b469d598a5/Qwen3.5-9B-Q4_K_M.gguf)입니다 (5,680,522,464 bytes).
공개 원본의 SHA-256은 이 저장소의 [MODELS.sha256](../models/MODELS.sha256)과 일치합니다.
**베이스만 실행하면 ScanOps 파인튜닝 모델이 아닙니다.** 어댑터를 함께 적용해야 합니다.

## 설정과 코드

| 항목 | 값 / 위치 |
|---|---|
| 베이스 | `unsloth/Qwen3.5-9B` |
| 학습 | 4-bit QLoRA, rank 16, alpha 32, seed 42 |
| 학습 코드 | [rebuild/train_qlora.py](../rebuild/train_qlora.py) |
| 데이터 구성 | [rebuild/build_dataset.py](../rebuild/build_dataset.py) |
| 학습 데이터 | [rebuild/data/train.jsonl](../rebuild/data/train.jsonl), [val.jsonl](../rebuild/data/val.jsonl) |
| 어댑터 병합 | [rebuild/merge.py](../rebuild/merge.py) (기존 `/workspace` 경로를 환경에 맞게 조정) |
| 평가 | [rebuild/eval_gguf.py](../rebuild/eval_gguf.py) |
| API / GPU 워커 | [scripts/api_rebuild.py](../scripts/api_rebuild.py), [runpod/handler_rebuild.py](../runpod/handler_rebuild.py) |

학습 코드는 GPU·Unsloth 환경을 전제로 합니다. 현재 최신 패키지로 동일 가중치가 재생성된다고 보증하지 않으며,
기존 학습 산출물 보존과 사용을 위해 릴리스 파일을 제공합니다.

## 로컬 추론 연결

1. 베이스와 릴리스의 `adapter_v1_fix.gguf`를 `models/`에 둡니다.
2. 저장소 루트에서 `bash scripts/verify_models.sh models`로 체크섬을 검증합니다.
3. Qwen3.5를 지원하는 llama.cpp의 `llama-server`로 베이스와 어댑터를 함께 로드합니다.

```sh
llama-server -m models/Qwen3.5-9B-Q4_K_M.gguf \
  --lora models/adapter_v1_fix.gguf --host 127.0.0.1 --port 8080 -c 8192
```

별도 터미널에서 API 의존성 설치 후, 연구용 그래프 호출 없이 기존 파인튜닝 경로만 실행하려면:

```sh
export SCANOPS_API_KEY='replace-with-your-local-key'
export RUNPOD_ENDPOINT_ID=''
export RUNPOD_API_KEY=''
export LLAMA_SERVER_URL='http://127.0.0.1:8080'
export SCANOPS_JAVA_ENGINE='legacy'
export SCANOPS_JAVA_ONLY='off'
export GRAPH_SPEC_ENABLED='off'
export SCANOPS_META='off'
python -m uvicorn scripts.api_rebuild:app --host 127.0.0.1 --port 8100
```

실제 분석은 `X-API-Key` 헤더로 `/analyze`에 `language`, `code`, `file_path`, `use_rag:false`를 보냅니다.
위는 현재 소스 기준의 실행 예시이며 이번 정리에서 가중치를 로드한 추론은 재실행하지 않았습니다.

RunPod 워커의 기본 `MODEL_PATH`는 **병합된 단일 GGUF**를 가리킵니다.
어댑터 단독 파일을 이 경로에 넣으면 안 됩니다. 로컬의 `--lora` 방식과 구분하세요.

## 후속 연구 보존

`rebuild/train_qlora_v3.py`, `rebuild/run_train_v2line_16k.py`, `rebuild/V4_TRAIN_RUN_SPEC.md` 등은 후속 실험입니다.
초기 파이프라인은 `ml/`에 보존되어 있습니다. 이 릴리스는 v1이며 후속 실험의 성능을 대표하지 않습니다.
