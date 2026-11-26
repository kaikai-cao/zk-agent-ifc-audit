# 相关工作（Phase 0 必需清单）

核对日期：2026-11-26（Phase 1B.1 修订）；Distributed Sentinel §4.8.1 于同日按 arXiv HTML 原文重新核对。证据分级：
- `FULLTEXT`：原文/官方摘要页可读，主张来自原文或官方摘要；
- `ABSTRACT`：仅摘要/二手解读可读，正文不可得，机制细节标为作者声称；
- `USER-PROVIDED`：由项目方提供、本轮未独立定位到精确出处，不作为已确认论文；
- `UNVERIFIED`：未找到精确命名来源，只列可能近邻，不作为已确认重叠。

本项目关系 R 的特征向量（用于比较）：
`R = {单次会话流图, 两元素保密格, 前向闭包/无 High→Low, 图承诺根, 隐藏 G, 验证者 nonce, 采集器认证根}`.

## 1. ZEKRA — Zero-Knowledge Control-Flow Attestation

- 来源：Debes et al., ASIA CCS 2023, DOI 10.1145/3579856.3582833；DTU/UBitech 全文可读。`FULLTEXT`
- 内容：控制流证明（CFA）中把执行路径验证外包给 worker，用 zkSNARK 向不可信验证者证明“验证结果正确”，隐藏执行路径与程序细节；不要求 worker 有 TEE。
- 与 R 的关系：同样用 ZK 隐藏证据并公开验证结果；但对象是**程序控制流路径合法性**，不是信息流格/前向闭包，也没有会话图承诺根与采集器认证语义。可作为“ZK 隐藏审计证据”路线先例，不占据本关系。

## 2. Distributed Sentinel — Beyond Single-Agent Alignment

- 来源：Wu & Gong, arXiv:2604.22879；§4.8.1 `Zero-Knowledge Predicate Proofs` 已按 arXiv HTML 原文核对。`FULLTEXT`
- 内容（运行时层）：多智能体上下文碎片化违规（CFV）；sidecar + Semantic Taint Token（STT）跨组织传递安全状态；报告 F1=0.95、106ms（作者实验数值）。
- 内容（ZK 层，此前误记，本版纠正）：§4.8.1 明确让源 sidecar 在**不暴露底层知识图结构**的前提下，向请求方证明策略谓词判定正确；关系写成 `∃w: R(x,w)=b`，其中 `w` 原文定义为 **graph structure**，`b∈{0,1}` 为策略判定；实现用 **Groth16 zk-SNARK**，策略谓词编译为算术电路。Table 3 报告 proof generation 45.2 ms、verification 2.1 ms、proof size 192 B、一次性 circuit setup 3,200 ms（作者实验数值）。
- 图对象：§2.1 定义每个 agent 持有私有本地知识图 `G_i=(V_i,E_i)`，节点为实体、边为关系/属性（所有权、分类、权限）。它服务于**跨组织策略谓词验证**，不是为 Agent 会话 Trace-IFC 前向闭包设计。
- 与 R 的关系：Distributed Sentinel **已覆盖“隐藏图 + Groth16 + 外部公开可验证策略谓词”这一通用结构**，原 Phase 0 表述“STT 有签名但不提供对隐藏图的公开 ZK 合规证明”与原文矛盾，已撤销。本项目的可能差异只剩图对象（会话信息流图 vs 跨组织知识图）与谓词（High→Low 前向闭包 vs 通用策略谓词）；这不足以把通用结构宣称为独立密码学贡献。采集器认证根与会话/nonce 绑定仍未被其覆盖，但属于工程语义层，不自动构成非组合式新语句。

## 3. zk-MCP — Zero-Knowledge Audit for Internet of Agents

- 来源：arXiv:2512.14737，Circom 实现；官方摘要可读，附录片段可读。`FULLTEXT`（部分正文）
- 内容：MCP 通信审计，公开消息类型计数与消息哈希，隐藏消息内容；形式化 data authenticity 与 communication privacy，声称验证开销可忽略。
- 与 R 的关系：最接近“ZK + Agent 审计 + 隐私”；但其声明是消息格式/类型/统计与哈希绑定，不是会话依赖图的 IFC 前向闭包。它也未给出采集器完整性或 nonce 会话绑定的图级关系。若后续只剩“字段更完整/哈希更多”，本项目应判 NO-GO。

## 4. FIDES — Securing AI Agents with Information-Flow Control

- 来源：Costa et al., arXiv:2505.23643。`FULLTEXT`
- 内容：为 Agent planner 建立形式化模型，动态追踪保密与完整标签，确定性执行 P-T（可信动作）和 P-F（允许流），在 AgentDojo 上评估；给出 explicit secrecy 与 integrity noninterference 形式化。
- 与 R 的关系：FIDES 是**执行期 IFC 强制机制**，其保证依赖 planner/策略引擎可信并可观察历史；它不生成供第三方验证的零知识证明，也不对承诺图做隐藏验证。FIDES 定义的“数据流到 sink”语义是本项目边定义的重要参考，但其保证不是 N4。

## 5. SME — Secure Multi-Execution

- 来源：Devriese & Piessens, IEEE S&P 2010；Barthe et al., 静态变换版；FlowFox 浏览器版。`ABSTRACT`（官方摘要可读）
- 内容：每个安全级别运行一次程序，I/O 按级别重定向，实现 noninterference；精确且语言无关，但需多次执行/运行时改造。
- 与 R 的关系：SME 是**机制性 NI 强制**，针对程序语义与运行；不是审计图上的存在性闭包证明。它说明“证明 NI 有成熟路线”，也提醒本项目不能把 N2 误导为 N1。

## 6. LLMbda Calculus — The LLMbda Calculus

- 来源：Garby, Gordon, Sands, arXiv:2602.20064。`FULLTEXT`
- 内容：无类型按值调用 λ 演算 + 动态 IFC + 对话原语（`@`, `fork`, `clear`）；在 Lean 中机器检验概率/终止不敏感非干扰定理；AgentDojo 银行场景评估。
- 与 R 的关系：给出**语言层、机器检验的 N1/NI 类保证**，对象是演算与可执行解释器；本项目对象是单次会话图与外部验证，不做语言语义证明。LLMbda 明确 FIDES 忽略控制流，支持我们把控制依赖边纳入图谓词的动机。

## 7. AttnNI — 公开 Lean 形式化项目；论文状态未确认（`USER-PROVIDED`）

- 项目方提供的归类：AttnNI 有**公开 Lean 形式化项目**，其中 `Session.lean` 已涉及**工具交互下的会话级非干扰性**。本轮检索未独立定位到同名论文或该仓库的精确 URL，因此不把“已发表论文”写入已确认事实。
- 可核验近邻（注意力隔离/注入检测，非形式化 IFC）：
  - GPR-NIAM / AttnIso, arXiv:2509.22700（NeurIPS'25）：联邦提示学习中用“无干扰注意力掩码/注意力隔离”阻断提示 token 与文本 token 的交互；这是优化/泛化意义上的非干扰。
  - RENNERVATE（NDSS 2026，二手解读可读）：用 response→context attention 特征定位并删除间接提示注入 token；不是形式化 IFC 证明。
- 结论：按“已公开 Lean 形式化项目（会话级 NI、含工具交互），论文状态未确认”记录，替代原“精确来源未确认”的笼统表述。它提示：**会话级非干扰的机器检验形式化已有公开实现**，本项目不得把“会话级 NI 形式化”当作空白；但仍不构成本项目 ZK 关系的直接重叠。

## 8. Cheesecloth — Zero-Knowledge Proofs of Real-World Vulnerabilities

- 来源：Cuellar et al., USENIX Security 2023；arXiv:2301.01321。`FULLTEXT`
- 内容：用 ZK 证明真实程序漏洞（如 Heartbleed 泄露），包括单执行标签系统与成对执行定义；支持内存安全、信息流安全等语句；不泄露漏洞触发细节。
- 与 R 的关系：**ZK + information flow** 的最强近邻。Cheesecloth 证明“存在泄露/违反 NI 的成对执行证据”，本项目证明“单条已认证轨迹满足前向闭包”。方向相反（漏洞存在 vs 合规），对象不同（程序执行 vs Agent 会话图）。若把本项目简化为通用图谓词 ZK，需面对 Cheesecloth 已覆盖 ZK-IFC 编码的事实。

## 9. Pave — Information Flow Control for Privacy-preserving Online Data Processing Services

- 来源：Park et al., ASPLOS 2025, DOI 10.1145/3676641.3716266。`ABSTRACT`（官方摘要可读，正文付费墙）
- 内容：PaveBox 在 Intel SGX 沙箱拦截数据流，按 IFC 规则放行；提供形式模型与安全证明、原型实验。
- 与 R 的关系：用 TEE 实现**运行时 IFC 强制 + 远程证明**，与本项目的“隐藏图合规证明”是互补路线。Pave 说明传感器/执行层信任可用硬件锚定，但不提供公开的零知识图谓词证明。

## 10. Information Flow Audit — 以 NeuroTaint 为可核验近邻

- 来源：Cai et al., arXiv:2604.23374, “Ghost in the Agent: Redefining Information Flow Tracking for LLM Agents”（NeuroTaint）。`FULLTEXT`
- 内容：离线审计执行轨迹，构建动态上下文溯源图 DCPG，用语义证据、因果推理、跨会话记忆跟踪发现不可信源到特权 sink 的流；在 TaintBench 400 场景上优于 FIDES 基线（作者实验）。
- 与 R 的关系：都把“审计轨迹/图”作为对象；NeuroTaint 是**明文离线分析工具**，输出可疑流，不提供隐藏图上的公开可验证证明。它是我们图边定义（显式内容传播、隐式控制影响、跨会话复用）的直接参考。

## 11. 小结：重叠与空白

已覆盖：
- ZK 隐藏执行/通信证据（ZEKRA、zk-MCP、Cheesecloth）；
- **隐藏图 + Groth16 + 外部公开可验证策略谓词（Distributed Sentinel §4.8.1）**；
- Agent IFC 执行期强制（FIDES、SME、LLMbda、Pave）；
- 多 Agent 跨域污点传播（Distributed Sentinel 运行时层）；
- 明文轨迹信息流审计（NeuroTaint）；
- 会话级非干扰的公开 Lean 形式化（AttnNI，论文状态未确认）。

因此：**“对隐藏图生成 ZK 证明并由外部验证策略谓词”这一通用结构不是本项目创新点**。尚未观察到单一工作同时具备的组合是：
`Agent Grant/session/nonce 绑定 + 隐藏会话流图承诺 + 外部公开可验证的 Trace-IFC 前向闭包结果 + 采集器认证根 + 盲化隐藏承诺`。

这仍只是**特征组合层面的待验证空白**，不是 novelty 定论。当前仓库不宣称相对 Distributed Sentinel / Cheesecloth / zk-MCP / FIDES 形成非组合式新增安全语句；按 `DECISION_GATE.md` 停止条件 3/5 保持 HOLD。若后续要提出研究贡献，须先证明该组合带来新的可证性质，而非字段增加或组件拼接。
