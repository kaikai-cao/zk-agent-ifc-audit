# 决策门（Phase 0 → 1A → 1B → 1B.1 → 继续/停止）

核对日期：2026-11-26。所有结论只针对本仓库当前提案，不扩大为 Agent IFC、ZK 审计或整个方向的总体裁决。

## 1. 阶段准入与重新界定

| 门 | 条件 | 状态 | 证据 |
| --- | --- | --- | --- |
| Phase 0 | 仓库创建、八份文档齐全、四类概念分离、必需相关工作清单 | **PASS（附 E 项勘误）** | `docs/` 八文件；`RELATED_WORK.md` 已纠正 Distributed Sentinel §4.8.1 |
| Phase 1A | 参考模型正确、A–G 全过、闭包与 BFS/DFS 一致、反例解释完整 | **PASS** | `tests/test_phase1a.py`：13 passed（含 3 个盲化承诺测试） |
| Phase 1B（基线 `a5acdc5`） | 证明/验证通过、50/100/200 实测、未冒充安全证明 | **重新界定为 PASS（仅本地具体图证明/验证）** | `experiments/phase1b/` 保留未改；原“独立第三方验证”表述撤销 |
| Phase 1B.1 | 固定电路、图无关 VK、独立验证者、盲化承诺、计时分离 | **PASS（技术协议；见第 5 节限制）** | `experiments/phase1b1/RESULTS.md` + `selftest*.json` |

### 为什么重新界定 Phase 1B
基线静态审查发现四个优先于创新性的问题，均已在 1B.1 处理或显式记录：

1. **VK 依赖具体图**：`q_edge` 只按 `e.active` 启用、Poseidon 布局随 active pattern 变化、`s_src/s_dst` 的 copy wiring 由 `src/dst` 决定，且验证阶段用完整 witness 重新 `keygen_vk`。→ 1B.1 改为固定 selector、固定 Poseidon 布局、固定 crossbar wiring，验证者不读图。
2. **承诺不隐藏**：确定性的 `root_G` 可被字典枚举并跨会话关联。→ 1B.1 公开 `C = H(BLIND+cap, root_G, blind)`，`blind` 在电路内参与计算。
3. **`verify_ms` 含 keygen_vk**：原报告是 `T_keygen_vk + T_verify`。→ 1B.1 只报 `pure_verify_ms`，VK 重建与签名验证单列。
4. **相关工作错误**：原称 Distributed Sentinel 只有签名、不提供隐藏图 ZK 合规证明，与 §4.8.1 原文矛盾。→ 已纠正；通用结构不再作为创新点。

## 2. Phase 1B.1 验收标准逐条核对

| # | 标准 | 判定 | 证据 |
| --- | --- | --- | --- |
| 1 | 不同图共享同一固定 VK | **PASS** | `selftest*.json` 中 `vk_graph_independent=true`（template 与真实图的 VK transcript digest 相同）；同一 `setup{cap}.json` 可验 low/mid/high 三种图 |
| 2 | active pattern 不影响电路结构 | **PASS** | 全部 edge slot 固定启用 `q_edge`、固定计算 edge leaf；crossbar 只由 `(j,i)` 决定 wiring；节点类型限定 0–5 |
| 3 | 独立 verifier 完全不接触 witness | **PASS** | `verify` 子命令只读 setup/proof/public 三份文件；`verifier_read_graph=false`；proving 与 verifying 为两个进程 |
| 4 | 实际验证隐藏图证明成功 | **PASS** | 9 个 case 的 `*.verify.json` 均通过真实 `verify_proof` |
| 5 | 非法图不能通过真实流程 | **PASS** | `selftest*.json` 的 `invalid_graph_rejected=true`；错误 nonce 实例被拒；错误签名被拒 |
| 6 | 盲化承诺通过针对性测试 | **PASS** | Python 3 个新增测试 + Rust `blind_changes_commitment=true`；改图或改 blind 均改变 `C` |
| 7 | 性能指标独立、可复现、定义正确 | **PASS** | `RESULTS.md` 分列 setup 三项一次性开销、`prove_ms`、`pure_verify_ms`、峰值内存 |
| 8 | 相关工作描述与原文一致 | **PASS** | `RELATED_WORK.md` §2 按 arXiv HTML §4.8.1 原文记录 Groth16、`∃w:R(x,w)=b`、45.2/2.1 ms、192 B；AttnNI 重分类为公开 Lean 项目、论文状态未确认 |

### 未满足的字面要求（必须披露）
`halo2_proofs 0.4` 不提供 VK/PK 序列化 API。验证者目前从公开固定模板重建 VK，并用 setup 中记录的真实 `vk_digest` 校验一致性。它满足“验证者不接触图/见证”，但**不满足任务包 B.3 的字面要求“verifier 不得调用 keygen_vk”**。这是接口层偏差，不是图相关 VK 回归；若必须满足字面要求，需另立任务包处理密钥序列化。

## 3. 停止条件逐条判定

| # | 停止条件 | 判定 | 依据 |
| --- | --- | --- | --- |
| 1 | 无法合理定义完整 Agent 会话的信息流依赖边 | **HOLD** | 对已记录事件可定义；语义转换、隐式因果、跨会话记忆传播仍未覆盖（NeuroTaint 指出）。 |
| 2 | 图的来源完整性没有可接受的信任机制 | **HOLD** | 可信采集器 + Ed25519 签 `C` 是协议内信任锚；ZKP 不减少该信任，漏边反例仍成立。 |
| 3 | 只是已有通用图谓词直接套用，无法论证新增安全价值 | **触发倾向加强** | Distributed Sentinel §4.8.1 已覆盖“隐藏图 + Groth16 + 外部公开策略谓词”；Cheesecloth 覆盖 ZK-IFC；zk-MCP 覆盖 ZK 通信审计。当前仅剩图对象/谓词/绑定字段的组合差异，未证明新的可证性质。 |
| 4 | 约束规模在目标规模下不可接受 | **HOLD（强成本警示）** | 固定 crossbar 使规模高于基线；cap=200 setup 合计约 477 s、prove 162–177 s、峰值 20–22 GB。功能可执行但接近实用上限。 |
| 5 | 普通签名与可信采集器已满足目标，ZKP 不值得其成本 | **HOLD（倾向触发）** | ZKP 新增“隐藏图的公开可验证合规与盲化隐藏”，采集器信任未减少；未建立“不能给验证者看图”的硬需求。 |

## 4. 实测口径与关键数值

本机（并行构建、`multicore` 开启）实测：

| cap | k | setup: params / vk / pk (s) | prove (s) | pure verify (ms) | VK rebuild (ms) | proof (B) | 峰值 prove / verify (MB) |
| ---: | ---: | --- | ---: | ---: | ---: | ---: | --- |
| 50 | 15 | 6.4 / 8.0 / 2.9 | 6.9–7.7 | 48–56 | 2242–2478 | 7968 | 2183 / 146 |
| 100 | 17 | 47.1 / 55.7 / 12.1 | 20.3–24.3 | 112–166 | 5435–7688 | 8096 | 8680 / 540 |
| 200 | 19 | 187.5 / 227.9 / 61.4 | 162–177 | 554–577 | 24295–26007 | 8224 | 20067–21806 / 2119 |

- 原 Phase 1B 的 `verify_ms`（7–25 s）包含 `keygen_vk`，**不可**与 Ed25519 验签或 Phase 1B.1 的 `pure_verify_ms` 直接比较。
- Phase 1B.1 的 `pure_verify_ms` 只含 `verify_proof`；`vk_rebuild_ms` 与 `sig_verify_ms` 单列，不计入验证时间。
- setup 阶段一次性报告 `params_gen_ms` / `vk_gen_ms` / `pk_gen_ms`；证明阶段只报 `create_proof`。
- 峰值内存为各自独立进程的 Windows `PeakWorkingSetSize` 采样值。
- cap=200 的 MockProver 自检在 2^19 域上不可承受，已跳过；该规模由真实 prove/verify 流程覆盖，非法图拒绝在 cap=50/100 用 MockProver 验证。
- 详细数值与复现命令见 `experiments/phase1b1/README.md` 和 `experiments/phase1b1/RESULTS.md`。

## 5. 最终裁决

**CONDITIONAL HOLD — Phase 1B.1 技术协议 PASS；研究/项目 GO 仍未成立；不进入更大规模实验，不宣布论文立项。**

具体表述：
1. 1B.1 证明了“固定电路 + 图无关 VK + 盲化承诺 + 独立验证者”这一**工程协议**成立；这是对 Phase 1B PASS 范围的必要收窄与修复，不是新研究贡献。
2. 它仍不证明经典两运行 noninterference、运行时执行真实性、采集器无漏记或标签来源真实；反例 D/E 边界不变。
3. 停止条件 3 因 Distributed Sentinel §4.8.1 原文核对而加强：通用隐藏图 ZK 谓词结构已被占用；字段/谓词替换不构成非组合式创新。
4. 停止条件 5 未闭合：未建立必须隐藏图的硬需求，且成本远高于 plaintext checker 与签名基线。
5. 若继续，须另立任务包并预注册，先闭合：采集器完整性机制、相对现有工作的新可证性质、明确隐私需求与成本上限、VK 序列化接口。

## 6. 本阶段不做什么

- 不覆盖或改写 `main` 上的 Phase 1B 基线与原始实验记录；
- 不增加递归证明、动态图规模、更多标签、declassification 或 LLM 推理入电路；
- 不声称形式化安全证明、exactly-once、跨存储原子性或承诺的统计隐藏性证明；
- 不建 PR，不改变任何其他冻结项目。
