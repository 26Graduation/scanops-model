# LoRA 어댑터를 베이스에 병합 → bf16 단일 모델 (vLLM/GGUF 공용)
# 실행 위치: RunPod (/workspace/rebuild). CPU에서 돌므로 GPU 작업과 병행 가능.
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch

# 1) 베이스 모델(bf16, 18GB)을 CPU 메모리에 로드
base = AutoModelForCausalLM.from_pretrained(
    "unsloth/Qwen3.5-9B", torch_dtype=torch.bfloat16, device_map="cpu")

# 2) 그 위에 학습된 LoRA 어댑터(116MB)를 부착
m = PeftModel.from_pretrained(base, "/workspace/rebuild/out/adapter")

# 3) 병합: 어댑터의 저랭크 행렬을 베이스 가중치에 더해 넣고 어댑터 제거
#    W_new = W_base + (lora_B @ lora_A) * (alpha/rank)  ← LoRA 수식 그대로
m = m.merge_and_unload()

# 4) 단일 모델로 저장 → 이후 GGUF 변환의 입력
m.save_pretrained("/workspace/rebuild/out/merged")
tok = AutoTokenizer.from_pretrained("/workspace/rebuild/out/adapter")
tok.save_pretrained("/workspace/rebuild/out/merged")
print("MERGED_OK")
