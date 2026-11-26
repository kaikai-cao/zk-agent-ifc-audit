# Phase 1B.1.2 cap=50 实测结果

仅运行 cap=50；Phase 1B / 1B.1 原始数据未改。
verifier 只读取 setup、独立 allowlist、proof、public；不读取图或 witness。
public.json 不含 blind、density、active_edges；这些字段只写入私有 meta.json。

## Setup（一次性）

- k=15，params=5410 ms，vk=6579 ms，pk=2280 ms，setup wall=14367 ms，peak=792.85 MB

## Prove / Verify

| density | active | proof_B | prove_ms | pure_verify_ms | vk_rebuild_ms | sig_verify_ms | prove_wall_ms | verify_wall_ms | prove_peak_MB | verify_peak_MB | accepted |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| low | 25 | 8096 | 4507 | 30 | 1330 | 0 | 13530 | 6706 | 2262.34 | 150.59 | True |
| mid | 50 | 8096 | 4556 | 30 | 1347 | 0 | 13626 | 6710 | 2262.66 | 150.47 | True |
| high | 100 | 8096 | 4547 | 30 | 1319 | 0 | 13651 | 7454 | 2262.31 | 150.82 | True |

- `pure_verify_ms` 只含 `verify_proof`；`verify_wall_ms` 含 Params 生成、VK 重建、验签与文件读取。
- `prove_ms` 只含 `create_proof`；`prove_wall_ms` 含进程启动、keygen 与 witness 生成。
- 当前 prove 仍调用 `keygen_with_k()`，setup 时间不可视为已缓存复用。

## 证明层负向测试

| case | create_proof_ok | verify_accepted | reason |
| --- | --- | --- | --- |
| illegal_ifc | True | False | verify_proof rejected |
| node_tl_mismatch | True | False | verify_proof rejected |
| edge_idx_mismatch | True | False | verify_proof rejected |
| crossbar_prev_dst | True | False | verify_proof rejected |

## 采集器身份负向测试

| case | accepted | reason |
| --- | --- | --- |
| wrong_nonce | False | verify_proof rejected |
| forged_public_key | False | collector signature rejected |
| wrong_collector_id | False | collector_id not in trusted allowlist |

## 攻击套件（MockProver）

共 16 例；逐例结果见 `raw/post_fix_attacks.json`，修复前见 `raw/pre_fix_attacks.json`。
