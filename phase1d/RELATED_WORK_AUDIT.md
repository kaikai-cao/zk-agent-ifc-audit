# Phase 1D — D6：相关工作原文核查与技术差异

核查时间：2026-11-27。原则：**以原始论文/官方页面为准**，不因"没搜到完全相同的方案"就宣称创新空白。

证据分级：
- `[原文核验]` = 本轮读取 arXiv abs/HTML 或 ACM DL 官方页面，主张来自原文；
- `[部分核验]` = 只读到摘要/二手，机制细节标为作者声称；
- `[标准结论]` = 教科书级标准结论，本轮未定位到具体原文页面，按标准定义引用；
- `[待验证]` = 未确认。

每项的六个固定问题：**(1) 哪种 IFC 性质；(2) 单/双轨迹；(3) 存在性/全称；(4) 机器检验/密码学；(5) 是否隐藏模型/输入/轨迹；(6) 与本阶段归纳证书的实质区别**。

---

## 1. Cheesecloth `[原文核验]`

- 来源：Cuéllar et al., arXiv:2301.01321（2023-01-03），USENIX Security 2023（仓库记载）；本轮读取 arXiv HTML 全文片段。
- 原文 §2.2：`"Program P satisfies noninterference with respect to L if each pair of inputs that are only distinct at private inputs result in values that are the same at all public outputs"`；`"a leak is witnessed by a pair of executions that differ only at LL-labeled inputs and produce distinct LL-labeled outputs."`
- 原文关于双执行开销：`"such an approach would result in a statement of twice the size required for validating a single execution"`；改用 `"a single execution in which storage is annotated with labels"`；并保证 `"when the labels say so, a leakage is present"`（下近似，must-leak）。
- 原文 §3：`"a circuit whose satisfiability is equivalent to the existence of a vulnerability"`；证明者持 secret exploit。

| 问题 | 回答 |
| --- | --- |
| (1) IFC 性质 | **Noninterference 的违反（leakage）**，成对执行定义 |
| (2) 单/双 | 语义定义是**双执行**；实现优化为**单执行 + 存储标签** |
| (3) 存在/全称 | **存在性**：`∃ exploit/witness` 使泄漏发生；不是证明对所有对 NI 成立 |
| (4) 方法 | **密码学**（ZK proof statement compiler），非机器检验 |
| (5) 隐藏 | 隐藏漏洞触发细节与输入；公钥程序公开 |
| (6) 实质区别 | 方向相反（证"泄"而非证"不泄"）；对象是程序执行而非有限 Agent 模型；不构造跨全部输入的归纳不变量；其单执行标签技巧是**绕过**双执行，不是**压缩全称量化** |

**关键判断**：Cheesecloth 已占据"ZK + 成对 IFC 定义 + 双执行电路翻倍"的问题空间，但**没有**做"用归纳不变量压缩 `∀h₀h₁` 的全称证明"。这是可能的差异点，但差异是"证明方向与量化结构"，不是"Agent 对象"。

---

## 2. LLMbda `[原文核验]`

- 来源：Garby, Gordon, Sands, arXiv:2602.20064 v2（2026-07-10）；本轮读取 arXiv abs。
- 原文：`"Our central result is a termination-insensitive probabilistic noninterference theorem over the whole calculus, including code-generating agents, with an insulated variant that holds even when the attacker chooses all untrusted inputs."`；`"Our harness and all proofs are in Lean."`

| 问题 | 回答 |
| --- | --- |
| (1) IFC 性质 | 终止不敏感的**概率 noninterference**（全演算，含代码生成 Agent） |
| (2) 单/双 | 语义层面全称跨运行；演算定义，非双轨迹证明对象 |
| (3) 存在/全称 | **全称定理**（对所有程序/运行） |
| (4) 方法 | **机器检验**（Lean），非密码学证明；无 ZK |
| (5) 隐藏 | 不隐藏模型/输入/轨迹；解释器和证明公开 |
| (6) 实质区别 | LLMbda 证明的是**语言语义层 NI**，且公开可审计；归纳证书证明的是**给定有限模型的 `C_T`** 并隐藏模型。二者的"全称"来源完全不同：一个是类型/语义定理，一个是模型上的归纳关系 |

**关键判断**：若把本阶段证书退化为"公开模型 + 公开不变量 + 普通验证"，它相对 LLMbda 没有明显理论增量；ZK 隐藏是唯一可能差异，但隐藏的硬需求未建立（见 DECISION.md）。

---

## 3. Distributed Sentinel `[原文核验]`

- 来源：Wu & Gong, arXiv:2604.22879（2026-04-24）；本轮读取 arXiv HTML §4.8.1。
- 原文 Definition 4.4：`"Let R be a relation such that R(x,w)=1 iff entity x with witness w (the graph structure) satisfies policy predicate P... ∃w: R(x,w)=b where b∈{0,1} is the policy decision, without revealing w or any other information about the graph."`
- 实现：Groth16；Table 3：proof gen 45.2 ms、verify 2.1 ms、proof 192 B、setup 3,200 ms（作者数值）。

| 问题 | 回答 |
| --- | --- |
| (1) IFC 性质 | **策略谓词判定**，不是 NI |
| (2) 单/双 | 单图 witness |
| (3) 存在/全称 | **存在性** `∃w: R(x,w)=b` |
| (4) 方法 | **密码学**（Groth16），非机器检验 |
| (5) 隐藏 | 隐藏图结构 w，公开布尔决策 b |
| (6) 实质区别 | 无全称量化、无归纳不变量、无双状态关系；本阶段证书针对跨全部高输入的性质，结构不同 |

**关键判断**：占据"隐藏图 + ZK 谓词证明"通用结构；本阶段若只做单模型谓词证明会落入其覆盖范围。

---

## 4. 经典 self-composition / product programs `[标准结论]`

- 代表：Darvas–Hähnle–Sands 的 self-composition；Barthe et al. 的 product programs（FM 2011）。本轮**未能**从 Springer/HAL 取回原文页面（链接失效/反爬），按标准结论引用，**不**声称已原文核验。
- 标准做法：把程序 `P` 与自身拷贝组成 `P ‖ P'`，对两次运行施加不同秘密输入，用普通（非关系）验证器证明关系性质；全称 NI 通过把两个输入写成任意符号变量实现。

| 问题 | 回答 |
| --- | --- |
| (1) IFC 性质 | 经典（终止不敏感/敏感）noninterference、关系性质 |
| (2) 单/双 | **双执行**（self-composition 的本质） |
| (3) 存在/全称 | **全称**（输入为符号变量，覆盖全部对） |
| (4) 方法 | **程序验证/演算推理**，通常非密码学、非 ZK |
| (5) 隐藏 | 不隐藏模型/输入/轨迹 |
| (6) 实质区别 | 本阶段证书的双状态关系是 self-composition 的**不变量压缩版**：不构造两条完整执行电路，而构造状态对关系。区别在证书规模与隐藏性，不在逻辑目标 |

**关键判断（诚实）**：归纳证书在逻辑上与 self-composition 的 relational invariant 同源。若不能证明"更紧凑 + 可隐藏"带来实质价值，则本阶段工作可能只是"把 self-composition 搬进 Halo2"——这正是任务包要求警惕的情形。

---

## 5. Bisimulation / 互模拟 `[标准结论]`

- 标准定义：状态关系 `R` 使 `(s,t)∈R` 时对任一 `s→s'` 存在 `t→t'` 且 `(s',t')∈R`（强互模拟还要求反向）；互模拟蕴含 trace equivalence，反之一般不成立。
- 本轮尝试 Wikipedia 原文被 429 拦截，按标准结论引用。

| 问题 | 回答 |
| --- | --- |
| (1) IFC 性质 | 不是 IFC，是**行为等价**；可作 NI 的关系证明工具 |
| (2) 单/双 | **双状态关系** |
| (3) 存在/全称 | 对关系的全称匹配条件 |
| (4) 方法 | 语义/演算证明，非密码学 |
| (5) 隐藏 | 不隐藏 |
| (6) 实质区别 | D3 的 Step (a)(b) 实质上就是带 `Obs⁺` 约束的**互模拟条件**。本阶段证书 = 互模拟 + 有界索引 + 低观察一致性 + ZK 隐藏 |

**关键判断（诚实）**：就数学内容而言，归纳证书**就是**有界互模拟证书。新增的是：(i) 限制在有限步 T；(ii) 与 `Obs⁺` 绑定；(iii) ZK 隐藏见证。若 (i)(ii)(iii) 不产生可测价值，则不构成新研究贡献。

---

## 6. zk-MCP `[原文核验]`

- 来源：Jing & Qi, arXiv:2512.14737（2025-12-11）；本轮读取 arXiv abs。
- 原文：结合 ZKP 与 MCP，隐藏消息内容，审计 `"format and general message types"` 与 usage metrics；Circom 实现；形式化 data authenticity 与 communication privacy。

| 问题 | 回答 |
| --- | --- |
| (1) IFC 性质 | 消息格式/类型/统计与哈希绑定，不是 IFC 流性质 |
| (2) 单/双 | 单通信审计 |
| (3) 存在/全称 | 存在性证明（消息满足格式），无全称跨输入 |
| (4) 方法 | 密码学（Circom ZK） |
| (5) 隐藏 | 隐藏消息内容 |
| (6) 实质区别 | 无关系性质、无不变量、无 NI；占据"ZK + Agent 审计"通用结构 |

---

## 7. FIDES / NeuroTaint / SME / Pave `[原文核验:摘要级]`

- FIDES（arXiv:2505.23643 v2）：`[原文核验]` 摘要确认"formal model + dynamic taint-tracking + planner + AgentDojo"，执行期 IFC 强制，**非 ZK、非证明**。
- NeuroTaint（arXiv:2604.23374）：`[原文核验]` 摘要确认"audits execution traces offline... semantic transformation, causal influence... cross-session persistence"，明文离线审计。
- SME（Devriese–Piessens, IEEE S&P 2010）、Pave（ASPLOS 2025, DOI 10.1145/3676641.3716266）：`[部分核验]`，本轮未重新定位原文；按仓库记载为机制性 NI 强制与 TEE 路线。
- 共同点：都**不**产生供外部验证的 ZK 全称关系证明；都是执行期/离线强制或分析。

---

## 8. 横向矩阵

| 工作 | IFC 性质 | 单/双 | 存在/全称 | 机器/密码 | 隐藏 | 与归纳证书实质区别 |
| --- | --- | --- | --- | --- | --- | --- |
| Cheesecloth | NI 违反 | 语义双/实现单 | 存在 | 密码 | 隐藏漏洞 | 证泄不证不泄；无全称压缩 |
| LLMbda | 概率 NI | 语义跨运行 | 全称 | Lean | 否 | 语言语义定理 vs 有限模型证书 |
| Distributed Sentinel | 策略谓词 | 单图 | 存在 | 密码 | 隐藏图 | 无全称/无不变量 |
| self-composition | NI | 双执行 | 全称 | 验证器 | 否 | **同源**；证书是其压缩版 |
| bisimulation | 行为等价 | 双状态 | 关系全称 | 语义 | 否 | **证书本质即此** + 有界 + 隐藏 |
| zk-MCP | 格式审计 | 单 | 存在 | 密码 | 隐藏消息 | 无关系 IFC |
| FIDES/NeuroTaint | 执行期/离线 IFC | 单轨迹 | 机制保证 | 工程 | 否 | 非证明系统 |

---

## 9. 结论：不能宣称创新空白

1. **归纳证书的数学内核（双状态互模拟不变量）是标准的**；本阶段没有发明新的关系验证逻辑。
2. 可能的新增点只有三个：**有界索引 `I₀..I_T`**、**`Obs⁺` 绑定的有限 Agent 模型**、**ZK 隐藏 `I`/`δ`**。三者都需证明实际价值，不能靠"没搜到相同方案"成立。
3. 最危险的误判：把"self-composition + bisimulation 搬进 Halo2"当成创新；任务包已明确要求警惕，本文件确认该风险真实存在。
4. 原文核验缺口：self-composition 原文、bisimulation 原文、SME/Pave 原文本轮未取回，按标准结论/二手标注，**不作为已核验事实**。

---

## 10. 阻断项 3 的回答准备

由上表可见：普通 self-composition（公开模型 + 符号输入）已能证明全称 NI；bisimulation（公开关系）已能给出关系证明；Lean 已能机器检验。ZK 的不可替代价值只剩**"必须隐藏模型/不变量而验证者仍需可信判断"**这一条，而该硬需求尚未由任何应用场景建立（Phase 1C 停止条件 5 未闭合）。详见 DECISION.md。
