# Phase 1C — 任务 3（上）：研究价值对照与相关工作矩阵

核对时间：2026-11-27。本轮**直接回到原始论文页面/官方仓库核对**了下列条目；不再仅依赖 `docs/RELATED_WORK.md` 或其他 Agent 的调研报告。

证据分级：
- `[原文核验]` = 本轮读取 arXiv abs/HTML 全文片段或 ACM DL 官方页面，主张来自原文；
- `[仓库记载]` = 来自本仓库 `docs/RELATED_WORK.md`，本轮未重新打开原文；
- `[未核验]` = 只有二手信息或未定位到精确出处；
- `[推论]` / `[待验证]` = 本阶段分析，非事实陈述。

---

## 1. A / B / C 研究价值对照（本阶段核心表）

| 维度 | A（单轨迹 Trace-IFC） | B（双轨迹关系非干扰） | C（有限模型有界全称 NI） |
| --- | --- | --- | --- |
| 证明对象 | 单图 G | 两条轨迹 τ₀,τ₁ | 有限执行模型 M |
| 关系性质 | 无 High→Low 可达性（前向闭包） | 低级观察等价（特定两实例） | 有界全称观察等价 |
| 是否涉及跨执行 | 否 | 是（一对） | 是（全体允许输入） |
| 是否自动证明经典 NI | 否 | 否 | 仅在明确边界 + 模型可信下 |
| 电路成本 | 已有基线（cap=50 prove 6.9–7.7 s） | `[待验证]` 待测；朴素约 2× 单轨迹 + 比较器件 | `[待验证]` 待评估；枚举式不可行，需证书路径 |
| 研究增量 | 需重新论证（停止条件 3 已倾向触发） | 需论证是否超出 Cheesecloth 成对定义 | 需论证证书/模型可信性与隐私硬需求 |
| SNARK 原生形态 | NP 型，直接可编码 | NP 型，但必须绑定挑战对 | 非原生；`∀` 需证书改写 |
| 首要风险 | 被误称为 NI | 平凡满足（自选相同对）或单点抽样 | 电路爆炸 + M 的来源信任 |

`[数学推导]` 三者不等价，层级关系见 `RELATIONAL_PROPERTIES.md` §5。

---

## 2. 五类机制对照：ZKP 究竟提供了什么普通机制无法提供的价值？

| 机制 | 验证者获得什么 | 验证者看到/信任什么 | 相对价值 | 局限 |
| --- | --- | --- | --- | --- |
| 1. 普通明文检查 | 直接重算谓词结果 | 拿到完整图 G；信任自己的计算 | 最快（cap=50 明文 0.028–0.039 ms，`[仓库记载]`） | 零隐私；验证者必须信任图的来源 |
| 2. 承诺 + 签名 | 验签 + 可自行重算谓词 | 仍需拿到图才能确认合规；信任采集器签名 | 绑定来源、防止篡改（sign 0.022–0.023 ms，`[仓库记载]`） | 不隐藏图；不减少采集器完整性信任 |
| 3. Halo2 单轨迹证明（A） | `Verify=1` ⟹ 存在满足 Trace-IFC 的隐藏图 | 只见 `C/policy_id/session_id/nonce/collector_id`；不接触图 | **唯一新增价值：验证者不必看见图内容，也不必信任证明者给的图** | 成本 5 个数量级；不减少采集器信任；不证明 NI |
| 4. Halo2 关系证明（B/C） | 隐藏轨迹下的跨执行观察等价 | 不看见秘密输入与轨迹 | 理论更接近经典 IFC | `[推论]` 若验证者**可以**看轨迹，明文对比 + 签名即可，ZK 只剩成本；硬隐私需求未建立 |
| 5. 已有 ZK-IFC / 形式化 IFC | 见第 3 节 | 见第 3 节 | 已有工作占据大部分通用结构 | 见第 3 节逐条 |

**核心回答（`[推论]`，基于上表与第 3 节原文核验）**：

ZKP 相对普通机制的**唯一可确认新增价值**是"在不把证据交给验证者的前提下，给出对某个谓词计算正确性的公开可验证判断"。它**不**减少采集器完整性信任，**不**减少标签来源信任，**不**证明运行时真实性，**不**自动提供任何全称性质。

对 Phase 1C 而言，这意味着：B/C 的 ZK 版本只有在"验证者**不能**看到两条轨迹/模型"这一硬需求成立时才有新增价值；否则明文运行两次 + 比较 + 签名即可达成同样结论。当前仓库停止条件 5 正是记录该硬需求**尚未建立**（`[仓库记载]`，`docs/DECISION_GATE.md` §3）。

---

## 3. 相关工作逐条核对（回到原始论文/官方页面）

### 3.1 Cheesecloth — ZK 信息泄漏/非干扰的最强近邻 `[原文核验]`

- 来源：Cuéllar et al., *Cheesecloth: Zero-Knowledge Proofs of Real-World Vulnerabilities*, arXiv:2301.01321（2023-01-03），USENIX Security 2023（仓库记载会议）。本轮读取 arXiv abs + HTML 全文片段。
- **原文 §2.2 成对定义**："Program P satisfies noninterference with respect to L if each pair of inputs that are only distinct at private inputs result in values that are the same at all public outputs... a leak is witnessed by a pair of executions that differ only at LL-labeled inputs and produce distinct LL-labeled outputs."
- **原文 §5.2 MicroRAM 实例化**："a MicroRAM program leaks if it has two executions whose inputs only differ at addresses given to source, but result in different values at an address given in calls to sink."
- **关键点 1（对 B 的 novelty 判定至关重要）**：Cheesecloth **已经在 ZK 语境下使用成对执行（pairwise）的 noninterference 定义**。因此"两条轨迹比较"本身不是新定义。
- **关键点 2（极性相反）**：Cheesecloth 的 ZK 证明是**存在性漏洞证明**——"a circuit whose satisfiability is equivalent to the existence of a vulnerability"；证明者持有 secret exploit，证明 `∃ exploit : leak`。它**不是**证明"对所有成对输入都满足 NI"。
- **关键点 3（电路优化先例）**：原文明确说直接编码两次执行"would result in a statement of twice the size required for validating a single execution"，因此改用**单执行 + storage labeling 的下近似**（"when the labels say so, a leakage *is* present"）来避免电路翻倍。这直接命中 B/C 的成本担忧，属于已有技术路线。
- **对本项目的影响**：若 B 仅做"两条轨迹公开输出相等"的 ZK 证明，相对 Cheesecloth 的差别是**极性（合规 vs 漏洞）与对象（Agent 会话 vs 通用程序）**，不构成新的可证性质。`[推论]`

### 3.2 Distributed Sentinel — 隐藏图 + Groth16 策略谓词 `[原文核验]`

- 来源：Wu & Gong, *Beyond Single-Agent Alignment*, arXiv:2604.22879（2026-04-24）。本轮读取 arXiv abs + HTML §4.8.1 原文。
- **原文 §4.8.1 Definition 4.4**：`R(x,w)=1` iff entity `x` with witness **w (the graph structure)** satisfies policy predicate `P`；协议为 `∃w : R(x,w)=b, b∈{0,1}`，"without revealing w or any other information about the graph"。
- 实现：Groth16 zk-SNARK，策略谓词编译为算术电路。Table 3：proof generation 45.2 ms、verification 2.1 ms、proof size 192 B、one-time circuit setup 3,200 ms（作者实验数值）。
- **明确不证明** noninterference；只证明隐藏图上的策略谓词判定正确。
- **对本项目的影响**：A 的通用结构（隐藏图 + ZK + 外部谓词）已被占据，事实清楚。差别只剩图对象/谓词种类/绑定字段，`[推论]` 与停止条件 3 一致。

### 3.3 zk-MCP — ZK 通信审计 `[原文核验]`

- 来源：Jing & Qi, *Zero-Knowledge Audit for Internet of Agents*, arXiv:2512.14737（2025-12-11）。本轮读取 arXiv abs。
- 声称：结合 ZKP 与 MCP，隐藏消息内容，审计"format and general message types"与 usage metrics；Circom 实现；形式化 data authenticity 与 communication privacy。
- **不**涉及信息流图前向闭包或 noninterference。
- **对本项目的影响**：ZK + Agent 审计的通用结构已被占据；若 B/C 最终只剩"字段更完整"，应判 NO-GO（`[推论]`）。

### 3.4 FIDES — Agent IFC 执行期强制 `[原文核验]`

- 来源：Costa et al., *Securing AI Agents with Information-Flow Control*, arXiv:2505.23643 v2（2025-09-03）。本轮读取 arXiv abs；官方教程仓库 `github.com/microsoft/fides`（abs 页给出）。
- 原文：形式化 planner 模型；"characterize the class of properties enforceable by dynamic taint-tracking"；Fides planner 跟踪机密性与完整性标签、确定性执行策略、引入选择性隐藏原语；AgentDojo 评估。
- **不是** ZK 证明，不生成供第三方验证的证明。
- **对本项目的影响**：Agent IFC 的形式化与强制机制已有成熟工作；C 的"有界全称"若退化为动态污点强制的形式化，创新点需重新论证。

### 3.5 LLMbda — 机器检验的全称 NI 定理 `[原文核验]`

- 来源：Garby, Gordon, Sands, *The LLMbda Calculus*, arXiv:2602.20064 v2（2026-07-10）。本轮读取 arXiv abs。
- 原文："Our central result is a termination-insensitive probabilistic noninterference theorem over the whole calculus, including code-generating agents, with an insulated variant that holds even when the attacker chooses all untrusted inputs." 以及 "The verified interpreter is itself the harness that calls the model... Our harness and all proofs are in Lean."
- **这是全称 NI 的最强近邻**：在 Lean 中机器检验、覆盖整个演算、含工具/代码生成。
- **不是** ZK 证明，不隐藏轨迹。
- **对本项目的影响**：C 若在程序语义层证明全称 NI，领域已被占据；可辩护的差异只剩"隐藏语义/轨迹 + 对外公开可验证"，但需独立论证价值。`[推论]`

### 3.6 NeuroTaint — 明文轨迹 IFC 审计 `[原文核验]`

- 来源：Cai et al., *Ghost in the Agent*, arXiv:2604.23374（2026-04-25）。本轮读取 arXiv abs。
- 原文：离线审计执行轨迹，把污点传播理解为"explicit content transfer, semantic transformation, causal influence on decisions, and cross-session persistence through memory"；TaintBench 400 场景。
- **明文离线工具**，不提供 ZK 证明。
- **对本项目的影响**：这正是停止条件 1 所引"语义转换、隐式因果、跨会话记忆传播"的来源；它说明 A 的边定义不完整，但不提供 ZK 方案。

### 3.7 ZEKRA — ZK 控制流证明 `[原文核验（部分）]`

- 来源：Debes et al., *ZEKRA: Zero-Knowledge Control-Flow Attestation*, ACM Asia CCS 2023, DOI 10.1145/3579856.3582833。本轮通过 ACM DL 官方页面核对标题与 venue；摘要正文在 Basic Edition 下不可读，机制描述沿用 `[仓库记载]`（DTU/UBitech 全文）。
- 记载机制：CFA 外包给 worker，用 zkSNARK 证明验证结果正确，隐藏执行路径与程序细节。
- **对本项目的影响**：ZK 隐藏执行证据的通用先例；不占据 IFC 关系。

### 3.8 SME（Secure Multi-Execution）`[仓库记载]`

- Devriese & Piessens, IEEE S&P 2010；Barthe 静态变换版；FlowFox。机制性 NI 强制，每个安全级别执行一次并重定向 I/O。
- **不是** ZK 证明；说明"证明 NI 有成熟路线"，提醒不得把 N2 误称为 N1。

### 3.9 Pave `[仓库记载；本轮 arXiv 定位失败]`

- 仓库记录：Park et al., ASPLOS 2025, DOI 10.1145/3676641.3716266，PaveBox 在 Intel SGX 拦截数据流并提供形式模型与安全证明。
- **诚实披露**：本轮尝试的 arXiv ID（2404.14213）对应的是一篇电子健康数据信号检测论文，**不是** Pave。因此本轮**未独立核验 Pave 原文**；只按 `[仓库记载]` 的 ABSTRACT 级别记录，不作为已确认论文细节。

### 3.10 AttnNI `[未核验]`

- 仓库记录为 USER-PROVIDED：公开 Lean 形式化项目，`Session.lean` 涉及工具交互下的会话级非干扰；论文状态未确认。本轮未定位精确出处。
- 可核验近邻 GPR-NIAM/AttnIso（arXiv:2509.22700）与 RENNERVATE（NDSS 2026）属于注意力隔离/注入检测，**不是**形式化 IFC。
- **对本项目的影响**：会话级 NI 的机器检验形式化已有公开实现，`[推论]` 不得把"会话级 NI 形式化"当空白。

---

## 4. 专门检索：是否存在 ZK 证明的"全称 noninterference"？

本轮用多组关键词检索（`zero-knowledge noninterference universal quantifier`、`zkSNARK proof program satisfies noninterference` 等），**未找到**直接命中"用 ZK 证明对所有秘密输入满足 NI"的原始工作。

`[待验证]` **这不是"不存在"的证明**。检索质量受限于关键词与索引覆盖；正式 novelty 声明需要后续系统性文献综述（含 IEEE/ACM DL、Google Scholar 前向引用链、Cheesecloth 与 LLMbda 的引用列表）。本阶段按 HOLD 处理，不据此宣称创新。

---

## 5. 已覆盖 vs 潜在空白（`[推论]`，基于第 3 节原文核验）

**已被占据的通用结构**：
1. ZK 隐藏执行/通信证据（ZEKRA、zk-MCP、Cheesecloth）；
2. 隐藏图 + Groth16 + 外部公开可验证策略谓词（Distributed Sentinel §4.8.1，原文确认）；
3. ZK 语境下的**成对执行 noninterference 定义**（Cheesecloth §2.2，原文确认）；
4. 避免 ZK 电路翻倍的单执行 + 标签下近似（Cheesecloth §5.2，原文确认）；
5. Agent IFC 执行期强制（FIDES、SME）；
6. 机器检验的全称概率 NI（LLMbda，Lean）；
7. 明文轨迹 IFC 审计与跨会话语义流（NeuroTaint）；
8. 会话级 NI 的公开 Lean 形式化（AttnNI，未核验）。

**尚未观察到单一工作同时具备的组合**（沿用仓库记录并更新）：
`Agent grant/session/nonce 绑定 + 隐藏会话流图承诺 + 外部公开可验证 Trace-IFC 闭包结果 + 采集器认证根 + 盲化隐藏承诺`。

**关键判断**：这仍只是**特征组合层面的待验证空白**，不是 novelty 定论。若 B/C 不能给出新的可证性质（而非字段增加/组件拼接），按停止条件 3 应保持 HOLD 或 NO-GO。`[推论]`

---

## 6. 本轮核验与未核验清单

本轮 `[原文核验]`：Cheesecloth（abs + HTML §2.2/§3/§5.2）、Distributed Sentinel（abs + HTML §4.8.1 Table 3）、zk-MCP（abs）、FIDES（abs v2）、LLMbda（abs v2）、NeuroTaint（abs）、ZEKRA（ACM DL 标题/venue）。

本轮未核验：Pave（arXiv 定位错误）、SME（仅仓库记载）、AttnNI（未定位）、Distributed Sentinel 运行时层的 F1/延迟数字（只核对 §4.8.1）。所有作者实验数值均标注为"作者数值"，本阶段不独立复现。
