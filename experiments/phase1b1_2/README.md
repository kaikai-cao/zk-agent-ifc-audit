# Phase 1B.1.2 — Circuit Soundness and Adversarial Witness Audit

本阶段只修正确性，不扩展谓词、不做递归、不接真实 Agent。基线为 `c25bf1ac3652237fec7ef49294839aeb2c37ee3b`，分支 `phase1b1-2-soundness`；`main` 与 Phase 1B / 1B.1 原始实验数据未改。

## 目录

- `raw/pre_fix_attacks.json`：修复前恶意 witness 复现；
- `raw/post_fix_attacks.json`：修复后回归；
- `raw/setup50.json` / `selftest50.json`：cap=50 setup 与自检；
- `raw/cap50_*.proof|public.json|meta.json|verify.json`：正向实测；
- `raw/proof_layer_negatives.json`：真实证明层负向测试；
- `raw/collector_attacks.json`：采集器身份与 nonce 负向测试；
- `RESULTS.md`：汇总；
- `ATTACK_CASES.md`：攻击语义与修复前后差异。

## 复现命令

```bash
cargo build --release --manifest-path halo2/Cargo.toml

# 恶意 witness 套件（MockProver）
halo2/target/release/zk-agent-ifc-audit-halo2.exe attack 50

# cap=50 setup / selftest / 正常 prove / 独立 verify
python scripts/run_phase1b1_2.py

# Python 全量测试
PYTHONPATH="src;tests" python -m pytest -q tests
```

`verify` 的调用形式为：

```bash
zk-agent-ifc-audit-halo2.exe verify \
  <setup.json> <config/trusted_collectors.test.json> \
  <proof.bin> <public.json> <verify.json>
```

`config/trusted_collectors.test.json` 只含公开确定性测试公钥，不是生产信任根。正式部署必须替换为独立治理的 allowlist。

## 修复摘要

1. `node_tl` 与 `node_type/label` 由同一 gate 约束；`node_index` 与固定行位置相等。
2. `edge_idx = src*cap+dst` 由固定 `cap` 列约束；`src/dst` 仍受 crossbar one-hot 与 copy constraint 范围约束。
3. 四类 Poseidon domain 和 empty leaf 零输入由固定列 / q_zero gate 固定。
4. 每个 crossbar block 首行六个 prev 累加器由 `q_first` 强制为零。
5. `without_witnesses()` 保留原 cap 和电路形状。
6. verifier 从独立 allowlist 取公钥；`collector_id` 由 SHA-256 公钥前缀规则在 Rust/Python 两侧统一派生。
7. 正式证明 blind 来自操作系统 CSPRNG；`public.json` 与 `GraphEncoding.as_dict()` 不输出 blind；图规模元数据只写私有 meta 文件。

## 边界

- 本阶段不声称形式化安全证明、承诺的统计隐藏性证明、采集器无漏记、标签来源真实或运行时执行真实。
- `pure_verify_ms` 不是端到端验证时间；`verify_wall_ms` 另行记录。
- `prove` 仍重新执行 `keygen_with_k()`，setup 阶段时间不能视为缓存复用。
- 研究状态仍为 **CONDITIONAL HOLD**；工程 soundness 修复不构成论文创新或研究 GO。
