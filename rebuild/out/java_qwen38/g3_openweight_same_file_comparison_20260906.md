# G3 Java same-file development comparison

This is a 15-file fail-fast development comparison, not the frozen held-out result.
All engines use both binary and exact-CWE file-level scoring on the identical six
positive and nine nominal-negative main-source files. Nominal negatives may contain
unlabeled issues.

## Binary vulnerability

| engine | TP | FP | FN | TN | precision | recall | F1 | F2 | parse failures |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ScanOps fixed Java CPG | 4 | 3 | 2 | 6 | 0.571 | 0.667 | 0.615 | 0.645 | 0 |
| Qwen/Qwen3.5-9B Q4_K_M base (Apache-2.0) | 0 | 1 | 6 | 8 | 0.000 | 0.000 | 0.000 | 0.000 | 1 |
| Qwen/Qwen3.5-9B Q4_K_M + ScanOps CVEfixes QLoRA | 4 | 7 | 2 | 2 | 0.364 | 0.667 | 0.471 | 0.571 | 0 |

## Exact CWE

| engine | TP | FP | FN | TN | precision | recall | F1 | F2 | parse failures |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ScanOps fixed Java CPG | 3 | 0 | 3 | 9 | 1.000 | 0.500 | 0.667 | 0.556 | 0 |
| Qwen/Qwen3.5-9B Q4_K_M base (Apache-2.0) | 0 | 0 | 6 | 9 | 0.000 | 0.000 | 0.000 | 0.000 | 1 |
| Qwen/Qwen3.5-9B Q4_K_M + ScanOps CVEfixes QLoRA | 3 | 0 | 3 | 9 | 1.000 | 0.500 | 0.667 | 0.556 | 0 |
