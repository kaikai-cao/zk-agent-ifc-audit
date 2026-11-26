# Phase 1B.1 实测结果（固定电路 / 独立验证者 / 盲化承诺）

一次性 setup 按 cap 生成；每个 cap/density 的 prove 与 verify 为两个独立进程。
verifier 只读取 setup.json、proof、public.json，不读取任何图或 witness 文件。

## Setup（每 cap 一次）

| cap | k | params_gen_ms | vk_gen_ms | pk_gen_ms | setup_peak_MB |
| --- | ---: | ---: | ---: | ---: | ---: |
| 50 | 15 | 6444 | 7980 | 2866 | 752.56 |
| 100 | 17 | 47050 | 55681 | 12123 | 2968.27 |
| 200 | 19 | 187477 | 227937 | 61425 | 11833.67 |

## Prove / Verify（每 case 独立进程）

| cap | density | active | proof_B | prove_ms | pure_verify_ms | vk_rebuild_ms | sig_verify_ms | prove_peak_MB | verify_peak_MB |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 50 | low | 25 | 7968 | 7707 | 48 | 2276 | 0 | 2184.25 | 146.43 |
| 50 | mid | 50 | 7968 | 7270 | 56 | 2478 | 0 | 2183.36 | 146.72 |
| 50 | high | 100 | 7968 | 6897 | 54 | 2242 | 0 | 2184.11 | 146.44 |
| 100 | low | 50 | 8096 | 20552 | 112 | 5435 | 0 | 8681.19 | 540.17 |
| 100 | mid | 100 | 8096 | 20253 | 157 | 5840 | 0 | 8684.75 | 540.12 |
| 100 | high | 200 | 8096 | 24336 | 166 | 7688 | 0 | 8678.24 | 540.02 |
| 200 | low | 100 | 8224 | 176828 | 577 | 24295 | 0 | 20066.77 | 2119.46 |
| 200 | mid | 200 | 8224 | 168555 | 563 | 25659 | 0 | 20700.79 | 2119.37 |
| 200 | high | 400 | 8224 | 161961 | 554 | 26007 | 0 | 21805.65 | 2119.44 |

说明：
- `pure_verify_ms` 只含 `verify_proof`，不含 VK 重建、签名验证或文件读取。
- `vk_rebuild_ms` 是验证者从公开固定模板重建 VK 的时间（halo2 0.4 无 VK 序列化 API）。
- `prove_ms` 只含 `create_proof`，不含 setup 与 witness 生成。
- 峰值内存为 Windows `PeakWorkingSetSize` 采样值。
- 验证者还会重新生成公开 Params（不计入 `pure_verify_ms`）；`verify_wall_ms` 含该项。
- cap=200 的 MockProver 自检因 2^19 域过大而跳过，由真实 prove/verify 覆盖。
- 与 1B 基线的 `verify_ms`（含 keygen_vk）不可直接比较；见 `docs/DECISION_GATE.md`。
