# Phase 1D.2 — 原始相关工作核查

证据标记：`[原文核验]`（本轮实际取回原文页面）、`[标准结论]`（教科书/领域共识，原文页面本轮未取回）、`[原文核验失败]`、`[待验证]`。

> **核查原则**：每条记录回答五问——原始论文及链接、对应定义/定理、已解决的问题、与目标差异、能否复用。**不把"没搜到完全相同论文"写成创新证据**。本轮只做一次范围内的补充研究，不无限扩展。

---

## 1. NFA / DFA 语言等价

### 1.1 NFA 语言等价与包含（`[标准结论]` + `[原文核验失败]`）

- **论文**：Stockmeyer & Chandra, *Provably Difficult Combinatorial Problems*, SIAM J. Comput. 1979（NFA 等价/universality PSPACE-complete 的经典来源）。
- **链接尝试**：dblp API `.../search/publ/api?q=Provably Difficult Combinatorial Problems` —— 本轮返回 Anubis 反爬验证页，**未取回原文元数据**。
- **定理**（`[标准结论]`）：NFA universality、NFA inclusion、NFA equivalence 均 **PSPACE-complete**。
- **已解决**：判定两个 NFA 是否接受同一语言的最坏复杂度下界与按需子集构造算法。
- **差异**：这是**判定复杂度**结果，不提供"紧凑可 ZK 验证的证书结构"；PSPACE-complete 意味着任何多项式大小证书若存在会塌缩复杂度类（`[数学推导]`：若 NP 证书充分则 PSPACE⊆NP，通常认为不成立）。
- **能否复用**：算法思想（按需子集）可复用；**不能**复用为"短证书"——复杂度结论反而提示 NFA 路线在 SNARK 中不会有短公开证书。

### 1.2 DFA 等价与最小化（`[标准结论]` + `[原文核验失败]`）

- **论文**：Hopcroft, *An n log n Algorithm for Minimizing States in a Deterministic Finite Automaton*, STOC 1971。
- **链接尝试**：dblp API —— 本轮同样被 Anubis 拦截，**未取回原文**。
- **定理**（`[标准结论]`）：DFA 等价可在多项式时间判定（乘积自动机可达性 `O(|Q₀||Q₁||Σ|)`）；最小化 `O(|Σ| n log n)`；DFA inequivalence 是 NL-complete。
- **已解决**：确定化自动机的高效等价判定与规范最小化。
- **差异**：要求 DFA 输入（NFA 需先子集构造，最坏指数）；最小化算法是组合算法，**不是**密码学证书。
- **能否复用**：乘积可达性检查可直接作为 `TRACE_AUTOMATA_CERTIFICATE.md` §3 的证书结构；在 SNARK 中表现为对每个状态对的约束（电路成本另计）。

---

## 2. Bisimulation 与 trace equivalence 的关系（`[标准结论]` + `[原文核验失败]`）

- **原始来源**：Milner, *Communication and Concurrency*（1989）；van Glabbeek 的进程代数谱系。
- **链接尝试**：Wikipedia Bisimulation 页 —— 本轮返回 Wikimedia 429（"We suspect this request is automated"），**未取回正文**；CMU 讲义 PDF 链接 404。
- **定理**（`[标准结论]`）：bisimulation ⇒ trace equivalence；反向不成立。弱互模拟 ⇒ 弱 trace equivalence；反向不成立。
- **本轮独立验证**（`[反例]`，不依赖外部来源）：`STATE_RELATION_CERTIFICATE.md` §2 与 `TRACE_AUTOMATA_CERTIFICATE.md` §4 给出的 `s→a→{a₁,a₂}` vs `t→a→u→{b,c}` 实例，trace 集合同为 `{ab,ac}`，但逐状态互模拟不存在（`a₁` 无 `c` 边而 `u` 有）。该反例是本轮自己构造并逐步验证的，可作为"反向不成立"的自含证据。
- **已解决**：两种等价的严格包含关系与判定算法。
- **差异**：经典理论比较的是**等价关系本身**，不关心"隐藏模型 + 外部验证者"的密码学场景。
- **能否复用**：理论结论直接复用（Phase 1D.1 定理即弱互模拟 soundness 的有界版）；但**不能**据此声称新贡献。

---

## 3. Bounded Model Checking（`[原文核验]`）

- **论文**：Armin Biere, Alessandro Cimatti, Edmund Clarke, Yunshan Zhu, *Symbolic Model Checking without BDDs*, TACAS 1999, LNCS 1579, pp. 193–207.
- **链接**：https://link.springer.com/chapter/10.1007/3-540-49059-0_14 —— **本轮取回原文页面与摘要**。
- **摘要原文**（`[原文核验]`）：
  > "We introduce a *bounded model checking* procedure for LTL which reduces model checking to propositional satisfiability."
  > "This new technique avoids the space blow up of BDDs, generates counterexamples much faster … it produces counterexamples of minimal length."
- **已解决**：把有界步数内的模型检查归约到 SAT，避免 BDD 空间爆炸。
- **与我们的差异**：
  - BMC 把有界性质归约到 SAT（NP 侧），本地运行；我们关心的是**隐藏模型下的外部可验证性**；
  - BMC 的"有界"是步数上界，与我们的 `T`（可观察动作上界）同构，但 BMC 不隐藏模型；
  - BMC 归约到 SAT/SMT，若直接套 SNARK 就是把 SAT 实例塞进电路——不等于"短证书"。
- **能否复用**：**可以复用**"有界展开 + SAT 约束"的编码思想作为 SNARK 电路的约束来源；但 BMC 本身不是我们的证书，也不解决隐藏/真实性问题。

---

## 4. 自动机性质的零知识证明（`[原文核验]` + `[待验证]`）

### 4.1 Distributed Sentinel §4.8.1（`[原文核验]`）

- **论文**：Jie Wu, Ming Gong, *Beyond Single-Agent Alignment: Preventing Context-Fragmented Violations in Multi-Agent Systems*, arXiv:2604.22879（2026-04-24）。
- **链接**：https://arxiv.org/abs/2604.22879 —— **本轮取回摘要**；§4.8.1 细节为 Phase 1C 已核验内容（本轮沿用，未重新取全文）。
- **摘要原文**（`[原文核验]`）：提出 Context-Fragmented Violations、Semantic Taint Token 协议、Counterfactual Graph Simulation；F1=0.95，16ms 验证 + 90ms 实体提取（A100）。
- **ZK 谓词**（Phase 1C §4.8.1 核验）：`∃w : R(x,w)=b`，`w` 为图结构，Groth16，证明 45.2ms / 验证 2.1ms / 192B。
- **已解决**：隐藏图结构上的**存在性策略谓词**证明，且已工程化。
- **差异**：这是**存在性**谓词（"存在一个满足策略的隐藏图"），不是**全称语言等价**（"所有高输入下观察语言相等"）；证明对象是图结构谓词，不是自动机语言等价。
- **能否复用**：工程参数（Groth16、证明大小）可复用为量级参考；**不能直接复用证书结构**——存在性谓词与全称语言等价是不同命题。

### 4.2 Cheesecloth（`[原文核验]`）

- **论文**：Santiago Cuéllar, Bill Harris, James Parker, Stuart Pernsteiner, Eran Tromer, *Cheesecloth: Zero-Knowledge Proofs of Real-World Vulnerabilities*, arXiv:2301.01321（2023-01-03）。
- **链接**：https://arxiv.org/abs/2301.01321 —— **本轮取回摘要**。
- **摘要原文**（`[原文核验]`）：
  > "…proves practical vulnerabilities in ZK by soundly-but-aggressively preprocessing programs on public inputs, selectively revealing information about executed control segments, and formalizing information leakage using a novel storage-labeling scheme."
- **已解决**：隐藏具体漏洞与利用输入下的信息泄漏**存在性**证明（Heartbleed 等）。
- **差异**：证明方向是"存在漏洞"（存在性），与 bounded NI 的全称方向相反；用单执行 + 存储标签近似规避双执行电路翻倍（Phase 1C §5.2 已核验）。
- **能否复用**：单执行标签技巧可复用为降低电路规模的思路；但目标性质不同。

### 4.3 ZEKRA（`[原文核验]`）

- **论文**：*ZEKRA: Zero-Knowledge Control-Flow Attestation*, ACM AsiaCCS 2023, DOI 10.1145/3579856.3582833。
- **链接**：https://dl.acm.org/doi/10.1145/3579856.3582833 —— **本轮取回页面**（标题/作者/venue 可见，摘要正文在 Basic Edition 被折叠）。
- **已解决的问题**（标题与领域共识）：用 zkSNARK 证明控制流完整性（CFI）结果，同时隐藏执行路径。
- **差异**：控制流路径的"遵循策略"证明（存在性/单例），不是两个隐藏模型的语言等价；也不处理 Agent 信息流。
- **能否复用**：路径隐藏 + CFI 的电路编码经验可参考；证书结构不可直接复用。

### 4.4 搜索结果说明（`[原文核验失败]`）

WebSearch "zero-knowledge proof finite automaton language equivalence hidden automaton SNARK regular language membership" 返回的是 SNARK 通用综述、Σ-protocol 讲义、中文科普，**未找到**"NFA/DFA 语言等价的 ZK 证明"直接成熟工作。按核查原则：**这不构成创新空白证据**，只记录"本轮范围内未找到"；可能存在未检索到的文献（`[待验证]`）。

---

## 5. Hidden graph / hidden automata verification（`[原文核验]` + `[待验证]`）

- Distributed Sentinel §4.8.1 的隐藏图谓词证明（见 §4.1）是本轮唯一取回原文的"隐藏结构 + ZK"实例。
- 它证明的是 `∃w:R(x,w)=b`（存在满足谓词的隐藏图），**不是**"两个隐藏自动机语言相等"。
- 结论（`[数学推导]`）：隐藏结构验证的密码学构件（承诺 + Groth16）已成熟；剩余问题是**命题形态**（存在性 vs 全称等价）与**模型来源信任**，这两点现有工作未覆盖我们的目标。

---

## 6. 核心回答：已有工作是否提供了我们需要的证书结构？

| 方向 | 已有工作提供的结构 | 是否直接满足我们的需求 | 剩余改进空间 |
| --- | --- | --- | --- |
| NFA 等价 | PSPACE 算法、按需子集 | 否（无短证书，PSPACE-complete） | 无密码学短证书空间（`[数学推导]`） |
| DFA 等价/最小化 | 乘积可达、`O(\|Σ\|n log n)` 最小化 | 部分（可作为证书结构） | 子集构造指数；电路中成本未解决 |
| Bisimulation vs trace | 严格包含、判定算法 | 是（理论已够用） | 无理论空白；我们的 1D.1 是标准结论的有界版 |
| BMC | 有界展开归约 SAT | 部分（编码思想） | 隐藏模型与真实性不在其范围 |
| ZK 自动机/图谓词 | 存在性谓词 Groth16 工程 | 否（存在性 ≠ 全称语言等价） | 全称等价的 ZK 化未见成熟工作（`[待验证]`） |

**总结**（`[数学推导]`）：
1. **普通验证侧**：DFA 等价、最小化、互模拟判定、BMC 已提供**完整且高效**的证书/算法结构——如果我们只需公开验证，技术已经覆盖。
2. **密码学侧**：现有 ZK 工作证明的是存在性谓词（策略满足、漏洞存在、控制流遵循），**不是**全称语言等价；但这是命题形态差异，不是"找不到相同论文"的创新空白。
3. **剩余空间的诚实评估**：若存在"必须隐藏模型 + 外部验证全称语言等价"的真实需求，则需要把 DFA 等价检查装入 ZK 电路并绑定模型承诺——这是一项**工程/成本问题**，不是一个明显的新理论问题；且该需求本身未建立（Phase 1C 停止条件 5，`ZK_VALUE_ANALYSIS.md`）。

---

## 7. 核查完整性声明

- 本轮实际取回原文：`BIERE99` Springer 摘要全文、`2604.22879` 摘要、`2301.01321` 摘要、`ZEKRA` ACM 页面元数据。
- 原文页面被拦截/失败：dblp（2 次，Anubis）、Wikipedia（429）、CMU 讲义（404）；相关结论按 `[标准结论]` 标注，**未当作已核验事实**。
- Distributed Sentinel §4.8.1 细节沿用 Phase 1C 核验结果，本轮未重新取全文，已显式标注。
- 未因"没搜到完全相同方案"宣称创新。
