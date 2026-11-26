# ZK-AGENT-IFC-AUDIT

Zero-Knowledge Auditing of Information-Flow Compliance in LLM Agent Sessions.

本仓库研究：对**由可信采集器认证的一次 Agent 会话信息流图**生成零知识证明，使第三方验证者只凭公开承诺根、策略标识、会话标识与验证者 nonce，即可验证该图满足指定的 Trace-IFC 策略，而无需获得原始节点、边、标签与操作细节。

> 第一阶段证明的是 **Trace-IFC Compliance**（单次会话图上的前向闭包/无 High→Low 流），**不是**经典两运行全局 Noninterference，也**不是**运行时执行保证。四者严格区分，见 `docs/PROBLEM_DEFINITION.md`。

## 阶段状态

| 阶段 | 内容 | 状态 |
| --- | --- | --- |
| Phase 0 | 研究问题、安全模型、相关工作、关系定义、承诺/来源、实验计划、决策门 | 完成 |
| Phase 1A | 普通程序参考模型 + A–G 反例/正例测试 + BFS/DFS 一致性 | 完成 |
| Phase 1B | Halo2 固定规模原型（50/100/200 事件）与实测 | 完成（见 `experiments/phase1b/`） |
| 基线 | Plaintext checker / Commitment+signature / Halo2 ZK | 完成（见 `experiments/baselines/`） |

**裁决：CONDITIONAL HOLD** —— 技术可行性 PASS，但研究/项目 GO 未成立，暂停 Halo2 扩展。详见 `docs/DECISION_GATE.md`。本仓库是一个研究假设检验，不预设项目一定值得继续。

## 目录

- `docs/`：八份必需研究文档。
- `src/ifc_audit/`：Phase 1A 参考模型（Python，纯普通程序）。
- `tests/test_phase1a.py`：Phase 1A 指定测试 A–G 与一致性测试。
- `halo2/`：Phase 1B Halo2 电路与基准二进制（Rust / Pallas / Poseidon）。
- `experiments/phase1b/`：实测结果 JSON 与生成脚本。
- `experiments/baselines/`：三类基线的对照脚本与结果。
- `scripts/`：一键复现入口。

## 快速复现

```bash
# Phase 1A
PYTHONPATH=src:. python -m pytest tests/test_phase1a.py -q

# 参考模型自检 + 基线
PYTHONPATH=src:. python scripts/run_baselines.py

# Phase 1B（需要 Rust/cargo；首次会编译依赖）
python scripts/run_phase1b.py
```

Phase 1B 使用 `halo2_proofs = 0.4.0`、`halo2_gadgets = 0.6.0`、`halo2_poseidon = 0.2.0`、`pasta_curves = 0.6.0`（Pallas base field，Poseidon P128Pow5T3, width 3/rate 2）。不引入递归证明；不把 LLM 推理放进电路。

## 信任边界速览

- **可信采集器**：负责把 Agent 运行时事件转成图并签名认证 `root_G`；它可能漏记事件，这不在证明关系内。
- **证明者**：持有隐藏图 G 与编码见证；不能伪造通过验证的证明（依赖 SNARK soundness）。
- **验证者**：只看公开输入与采集器公钥；不读原图、不需要跟踪运行时。
- **策略权威**：`policy_id` 指向公开、版本固定的策略定义；策略内容真值不由本证明产生。

详见 `docs/SECURITY_MODEL.md` 与 `docs/COMMITMENT_AND_PROVENANCE.md`。
