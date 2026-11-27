# 复现日志（Phase 1B.1.3）

## 1. 环境

来源：`raw/environment.json`、`raw/unittest.log`、`raw/pytest.log`、`halo2/Cargo.lock`。

| 项 | 值 |
| --- | --- |
| OS | Windows 11 10.0.26320-SP0 |
| Python | 3.13.14 (main, Jun 11 2026) [MSC v.1944 64 bit AMD64] |
| pytest | 9.2.0（pluggy 1.7.0） |
| cryptography | 50.0.2 |
| Rust 证明栈 | halo2_proofs 0.4.0、sha2 0.10.9、ed25519-dalek 2.1.1、rand 0.10.4；曲线 vesta/Pallas |
| 二进制 | `halo2/target/release/zk-agent-ifc-audit-halo2.exe`（本分支重新编译） |

## 2. 基线门禁

```
git status --short --branch                 # clean，phase1b1-2-soundness
git rev-parse HEAD                          # d3a14f34...（本地等价基线）
git rev-parse main                          # a5acdc5b...（未变）
git rev-parse d3a14f3^{tree}                # dfeda001...（与远端 1d44e4b tree 一致）
git rev-parse d3a14f3^                      # c25bf1ac...（与指定父提交一致）
git switch -c phase1b1-3-evidence-closure
```

指定基线 `1d44e4b4…` 是上轮 GitHub API 创建的远端 commit，本地无该对象，但 tree/parent 与本地 `d3a14f3` 一致，代码内容完全等价。详见 `README.md`。

## 3. A1 Python 测试（完整日志 = raw/unittest.log、raw/pytest.log）

```
python -m unittest discover -s tests -v        # EXIT_CODE=5，Ran 0 tests，NO TESTS RAN
python -m pytest -q tests -v                   # EXIT_CODE=0，collected 15 items，15 passed in 0.61s
```

**口径说明（必须如实）**：仓库测试是 pytest 风格函数（`def test_*`），不是 `unittest.TestCase` 子类。任务包指定的 `unittest discover` 实际发现 0 个测试（退出码 5），并非"通过"。 Python 全量测试的真实执行与通过依据是 `pytest`（15 passed）。两种命令的完整输出与退出码均保存在 raw 日志，不摘录改写。

## 4. A2/A3/A4 Halo2 复现（脚本 `scripts/run_phase1b1_3.py`）

```
PYTHONPATH=scripts python scripts/run_phase1b1_3.py
```

脚本对每个子进程用临时文件接收 stdout/stderr（不用 `subprocess.PIPE`），并把 `command / exit_code / wall_ms / peak_mb / stdout / stderr` 写入 `raw/*.log`。这一点很关键：1B.1.2 脚本的 attack 命令输出约 7 KB JSON 超过 Windows 管道缓冲、父进程不读管道而死锁；本阶段改用临时文件后，全流程 5m55s 完成。

### 逐子进程日志索引（均在 raw/）

| 阶段 | 命令（子命令） | 日志 | 结构化结果 |
| --- | --- | --- | --- |
| setup | `setup 50` | `setup50.log` | `setup50.json` |
| selftest | `selftest 50` | `selftest50.log` | `selftest50.json` |
| 攻击套件（MockProver） | `attack 50` | `attack50.log` | `attack50.json` |
| 正向 low | `prove 50 low …` / `verify …` | `prove50_low.log` / `verify50_low.log` | `cap50_low.json` |
| 正向 mid | `prove 50 mid …` / `verify …` | `prove50_mid.log` / `verify50_mid.log` | `cap50_mid.json` |
| 正向 high | `prove 50 high …` / `verify …` | `prove50_high.log` / `verify50_high.log` | `cap50_high.json` |
| 负向 illegal_ifc | `prove-attack` / `verify` | `neg_illegal_ifc_prove.log` / `neg_illegal_ifc_verify.log` | `proof_layer_negatives.json` |
| 负向 node_tl_mismatch | `prove-attack` / `verify` | `neg_node_tl_mismatch_prove.log` / `neg_node_tl_mismatch_verify.log` | 同上 |
| 负向 edge_idx_mismatch | `prove-attack` / `verify` | `neg_edge_idx_mismatch_prove.log` / `neg_edge_idx_mismatch_verify.log` | 同上 |
| 负向 crossbar_prev_dst | `prove-attack` / `verify` | `neg_crossbar_prev_dst_prove.log` / `neg_crossbar_prev_dst_verify.log` | 同上 |
| 采集器 5 例 | `verify …` | `collector_*_verify.log` | `collector_cases.json` |

所有 prove/verify 子进程的 `exit_code=0`（失败以字段/JSON 体现，不以进程异常退出体现）；具体 accepted/reason 见 `summary.json`。

## 5. C VK digest 稳定性（`scripts/vk_digest_stability.py`）

```
PYTHONPATH=scripts python scripts/vk_digest_stability.py
```

三次独立 `setup(50)` → `raw/vk_stability_run{1,2,3}.json`，汇总 `raw/vk_digest_stability.json`。结果见 `VK_DIGEST_AUDIT.md` 第 4 节。

## 6. 备注

- 所有原始字节（proof、public、meta、verify）与日志均保留在 `raw/`，未被后续运行覆盖。
- 性能毫秒值为单次原始值，不取平均、不删异常值；机器负载导致 `params_generation_ms` 在 8.1–12.0 s 波动，如实记录。
- 更复杂的复现细节（wall time 采集、峰值内存口径）见 `experiments/phase1b1/README.md`。
