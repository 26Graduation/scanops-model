"""ScanOps v2(line) — RunPod 파드 생성/조회/종료 헬퍼 (V2_RUN_SPEC.md §10-8).

과금이 실제로 발생하므로 **최소 시간만 켠다**: 데이터가 준비된 뒤에 create → 학습 →
어댑터 회수 → 즉시 terminate.

API 키는 `scanops-model/.env` 의 `RUNPOD_API_KEY` 에서 읽는다 (인자로 받지 않는다 — 셸 히스토리에
남기지 않기 위해).

  .venv/bin/python rebuild/runpod_v2line.py gpus                 # 가용 GPU 조회 (읽기 전용)
  .venv/bin/python rebuild/runpod_v2line.py create --gpu "NVIDIA H100 80GB HBM3"
  .venv/bin/python rebuild/runpod_v2line.py status
  .venv/bin/python rebuild/runpod_v2line.py terminate --id <POD_ID>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENV = ROOT.parent / ".env"
API = "https://api.runpod.io/graphql"

# unsloth/torch 가 미리 깔린 공식 이미지. v1~v4 라운드가 쓰던 스택과 같은 계열.
IMAGE = "runpod/pytorch:2.4.0-py3.11-cuda12.4.1-devel-ubuntu22.04"


def key() -> str:
    for line in ENV.read_text().splitlines():
        if line.startswith("RUNPOD_API_KEY="):
            v = line.split("=", 1)[1].strip().strip('"').strip("'")
            if v:
                return v
    print(f"[BLOCKED] {ENV} 에 RUNPOD_API_KEY 가 비어 있다.")
    sys.exit(2)


def gql(q: str) -> dict:
    import requests
    # RunPod 는 기본 Python-urllib User-Agent 를 403 으로 막는다 (실측) → UA 를 지정한다.
    r = requests.post(f"{API}?api_key={key()}", json={"query": q}, timeout=90,
                      headers={"Content-Type": "application/json",
                               "User-Agent": "scanops-v2line/1.0"})
    r.raise_for_status()
    d = r.json()
    if "errors" in d:
        print("[ERROR]", json.dumps(d["errors"], ensure_ascii=False)[:600])
        sys.exit(1)
    return d["data"]


def cmd_gpus() -> None:
    d = gql("""query { gpuTypes { id displayName memoryInGb
                 lowestPrice(input:{gpuCount:1}) { uninterruptablePrice stockStatus } } }""")
    rows = []
    for g in d["gpuTypes"]:
        lp = g.get("lowestPrice") or {}
        if lp.get("stockStatus") and g["memoryInGb"] >= 24:
            rows.append((lp.get("uninterruptablePrice") or 0, g["memoryInGb"],
                         g["displayName"], g["id"], lp["stockStatus"]))
    rows.sort(reverse=True)
    print(f"{'$/hr':>7} {'VRAM':>5}  {'GPU':32s} {'stock':8s} id")
    for pr, mem, name, gid, st in rows:
        print(f"{pr:7.2f} {mem:5d}  {name[:32]:32s} {st:8s} {gid}")


def cmd_create(gpu_id: str, disk: int, name: str) -> None:
    q = f'''mutation {{
      podFindAndDeployOnDemand(input: {{
        cloudType: ALL, gpuCount: 1, volumeInGb: {disk}, containerDiskInGb: 60,
        minVcpuCount: 8, minMemoryInGb: 60,
        gpuTypeId: "{gpu_id}", name: "{name}",
        imageName: "{IMAGE}",
        dockerArgs: "", ports: "22/tcp", volumeMountPath: "/workspace",
        startSsh: true
      }}) {{ id imageName machineId costPerHr desiredStatus }}
    }}'''
    d = gql(q)
    p = d["podFindAndDeployOnDemand"]
    if not p:
        print("[BLOCKED] 파드 생성 실패 — 해당 GPU 재고가 없다. gpus 로 다시 확인해라.")
        sys.exit(1)
    print(json.dumps(p, ensure_ascii=False, indent=2))
    print(f"\n>>> POD_ID={p['id']}  ${p['costPerHr']}/hr  ← 지금부터 과금 시작")
    print(">>> status 로 SSH 접속 정보를 확인해라.")
    (ROOT / "out" / "v2line_pod.json").write_text(json.dumps(p, ensure_ascii=False, indent=2))


def cmd_status() -> None:
    d = gql("""query { myself { pods { id name desiredStatus costPerHr
                 runtime { uptimeInSeconds ports { ip publicPort privatePort type } }
                 machine { gpuDisplayName } } } }""")
    pods = (d.get("myself") or {}).get("pods") or []
    if not pods:
        print("실행 중인 파드 없음 (과금 없음)")
        return
    for p in pods:
        rt = p.get("runtime") or {}
        up = rt.get("uptimeInSeconds")
        print(f"{p['id']}  {p['name']}  {p['desiredStatus']}  "
              f"{(p.get('machine') or {}).get('gpuDisplayName')}  ${p['costPerHr']}/hr  "
              f"uptime={up}s  누적≈${(up or 0)/3600*(p['costPerHr'] or 0):.2f}")
        for prt in (rt.get("ports") or []):
            if prt["privatePort"] == 22:
                print(f"   ssh -p {prt['publicPort']} root@{prt['ip']}")


def cmd_terminate(pod_id: str) -> None:
    gql(f'mutation {{ podTerminate(input: {{podId: "{pod_id}"}}) }}')
    print(f"terminate 요청 보냄: {pod_id} — status 로 사라졌는지 확인해라 (과금 중단 확인용)")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["gpus", "create", "status", "terminate"])
    ap.add_argument("--gpu", default="NVIDIA H100 80GB HBM3")
    ap.add_argument("--disk", type=int, default=100)
    ap.add_argument("--name", default="scanops-v2line")
    ap.add_argument("--id", default="")
    a = ap.parse_args()
    if a.cmd == "gpus":
        cmd_gpus()
    elif a.cmd == "create":
        cmd_create(a.gpu, a.disk, a.name)
    elif a.cmd == "status":
        cmd_status()
    else:
        if not a.id:
            print("--id 필요"); sys.exit(2)
        cmd_terminate(a.id)


if __name__ == "__main__":
    main()
