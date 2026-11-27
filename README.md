# ZK-AGENT-IFC-AUDIT

Zero-Knowledge Auditing of Information-Flow Compliance in LLM Agent Sessions.

本仓库研究：对**由可信采集器认证的一次 Agent 会话信息流图**生成零知识证明，使第三方验证者只凭**随机盲化承诺** `C`、策略标识、会话标识与验证者 nonce，即可验证该图满足指定的 Trace-IFC 策略，而无需获得原始节点、边、标签与操作细节。

> 第一阶段证明的是 **Trace-IFC Compliance**（单次会话图上的前向闭包/无 High→Low 流），**不是**经典两运行全局 Noninterference，也**不是**运行时执行保证。四者严格区分，见 `docs/PROBLEM_DEFINITION.md`。

## 阶段状态

| 阶段 | 内容 | 状态 |
| --- | --- | --- |
| Phase 0 | 研究问题、安全模型、相关工作、关系定义、承诺/来源、实验计划、决策门 | 完成 |
| Phase 1A | 普通程序参考模型 + A–G 反例/正例测试 + BFS/DFS 一致性 | 完成 |
| Phase 1B（基线 `a5acdc5`） | Halo2 固定规模原型（50/100/200 事件）与实测 | 完成；已被 Phase 1B.1 审查出固定电路/独立验证/承诺隐藏/计时口径问题 |
| Phase 1B.1（分支 `phase1b1-fixed-verifier`） | 固定电路、图无关 VK、独立验证者、盲化承诺、计时分离 | soundness 已被 1B.1.2 收窄重测；原始结果保留 |
| Phase 1B.1.2（分支 `phase1b1-2-soundness`） | 承诺 preimage 与谓词字段绑定、crossbar 首行零约束、采集器 allowlist、OS CSPRNG blind | cap=50 工程实现 PASS；研究状态仍 CONDITIONAL HOLD |
| Phase 1B.1.3（分支 `phase1b1-3-evidence-closure`） | 独立复现、计时边界校正、VK digest 定位、隐私/安全边界整理 | cap=50 证据可信度 PASS；不做 GO 判定，HOLD 不变 |
| 基线 | Plaintext checker / Commitment+signature / Halo2 ZK | 完成（见 `experiments/baselines/`） |

**裁决：CONDITIONAL HOLD** —— 工程协议修复后技术可行性 PASS，但研究/项目 GO 仍未成立，暂停 Halo2 扩展。详见 `docs/DECISION_GATE.md`。本仓库是一个研究假设检验，不预设项目一定值得继续。

Phase 1B.1 明确不宣称：独立密码学创新、形式化安全证明、采集器无漏记、运行时执行真实性或经典两运行 Noninterference。Distributed Sentinel §4.8.1 已覆盖“隐藏图 + Groth16 + 公开策略谓词”通用结构，见 `docs/RELATED_WORK.md`。

## 目录

- `docs/`：八份必需研究文档。
- `src/ifc_audit/`：Phase 1A 参考模型（Python，纯普通程序）。
- `tests/test_phase1a.py`：Phase 1A 指定测试 A–G 与一致性测试。
- `halo2/`：Phase 1B.1 固定电路与 setup/prove/verify 独立入口（Rust / Pallas / Poseidon）。
- `experiments/phase1b/`：Phase 1B 基线实测（保留，不覆盖）。
- `experiments/phase1b1/`：固定电路与独立验证者实测、setup/proof/public/verify 产物。
- `experiments/phase1b1_2/`：soundness 修复前后攻击用例、cap=50 正向/负向实测与性能口径。
- `experiments/phase1b1_3/`：独立复核日志、修正后计时、VK digest 审计与隐私/安全边界（R1–R10）。
- `config/trusted_collectors.test.json`：仅用于测试的独立采集器 allowlist。
- `experiments/baselines/`：三类基线的对照脚本与结果。
- `scripts/`：一键复现入口。

## 快速复现

```bash
# Phase 1A
PYTHONPATH=src:. python -m pytest tests/test_phase1a.py -q

# 参考模型自检 + 基线
PYTHONPATH=src:. python scripts/run_baselines.py

# Phase 1B.1.2（需要 Rust/cargo；只跑 cap=50）
cd halo2 && cargo build --release --offline && cd ..
python scripts/run_phase1b1_2.py

# 手动流程（cap=50 示例）
./halo2/target/release/zk-agent-ifc-audit-halo2.exe setup 50 experiments/phase1b1_2/raw/setup50.json
./halo2/target/release/zk-agent-ifc-audit-halo2.exe selftest 50
./halo2/target/release/zk-agent-ifc-audit-halo2.exe attack 50
./halo2/target/release/zk-agent-ifc-audit-halo2.exe prove 50 low 2026112601 \
  experiments/phase1b1_2/raw/setup50.json \
  experiments/phase1b1_2/raw/cap50_low.proof \
  experiments/phase1b1_2/raw/cap50_low.public.json \
  experiments/phase1b1_2/raw/cap50_low.meta.json
./halo2/target/release/zk-agent-ifc-audit-halo2.exe verify \
  experiments/phase1b1_2/raw/setup50.json \
  config/trusted_collectors.test.json \
  experiments/phase1b1_2/raw/cap50_low.proof \
  experiments/phase1b1_2/raw/cap50_low.public.json \
  experiments/phase1b1_2/raw/cap50_low.verify.json

# Phase 1B.1.3（独立复核；只跑 cap=50，输出到独立目录不覆盖历史）
PYTHONPATH=scripts python scripts/run_phase1b1_3.py
PYTHONPATH=scripts python scripts/vk_digest_stability.py
```

Phase 1B 使用 `halo2_proofs = 0.4.0`、`halo2_gadgets = 0.6.0`、`halo2_poseidon = 0.2.0`、`pasta_curves = 0.6.0`（Pallas base field，Poseidon P128Pow5T3, width 3/rate 2）。不引入递归证明；不把 LLM 推理放进电路。

## 信任边界速览

- **可信采集器**：负责把 Agent 运行时事件转成图并签名认证盲化承诺 `C`；它可能漏记事件，这不在证明关系内。
- **证明者**：持有隐藏图 G、编码见证与盲化因子 `blind`；不能伪造通过验证的证明（依赖 SNARK soundness）。
- **验证者**：只看公开输入、证明、固定 VK 参数与采集器公钥；不读原图、不接触 witness、不需要跟踪运行时。
- **策略权威**：`policy_id` 指向公开、版本固定的策略定义；策略内容真值不由本证明产生。

详见 `docs/SECURITY_MODEL.md` 与 `docs/COMMITMENT_AND_PROVENANCE.md`。
