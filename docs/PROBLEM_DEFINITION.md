# 问题定义：四类命题必须分开

本项目的核心纪律：以下四个命题**不是同一个命题**，不得互相代替，也不得用一个的证明去宣称另一个。

| 编号 | 命题 | 量词/对象 | 本仓库是否证明 |
| --- | --- | --- | --- |
| N1 | 经典两运行 Noninterference（NI） | 对**所有**仅在 High 输入不同的两次运行，Low 可观察输出相同 | 否。Phase 0/1 都不证明 |
| N2 | 单次会话 Trace-IFC Compliance | 对**一条已认证轨迹**构成的图 G，存在前向闭包集合 S 使 High∉→Low | 是（第一阶段目标） |
| N3 | 运行时执行保证 | 实际执行事件与采集器报告的图一致、不可绕过、不可漏记 | 否。属于采集器/TEE/审计链信任模型 |
| N4 | 对已认证会话图的零知识合规证明 | 证明者隐藏 G，验证者只凭公开承诺与绑定值相信 N2 | 是（Phase 1B 原型） |

## 1. 经典两运行 Noninterference（N1）

设系统语义 `[[P]]`，Low 观察投影 `obs_L`，两次运行输入 `i_L, i_H` 与 `i_L, i_H'`。NI 要求：

```
∀ i_L, i_H, i_H' : obs_L([[P](i_L,i_H)]) = obs_L([[P](i_L,i_H')])
```

这是**全称量化、跨运行、关于程序/系统语义**的性质。它关心是否存在任何 High 到 Low 的隐式/显式通道，通常需要对所有执行路径做类型系统或语义证明。

本项目的图谓词只看**一条已经发生并被采集的会话图**。它既不枚举两次运行，也不对未发生的执行做任何断言。因此：

> `Trace-IFC Compliance(G) = true` **不蕴含** `NI(P)`。
> 反例：采集器只记录其中一次运行；或系统在其他输入下会泄露，但本次会话恰好没有。

## 2. 单次会话 Trace-IFC Compliance（N2）

### 2.1 图与标签

```
G = (V, E)
L : V -> {Low, High}          # 两元素格 Low < High
type : V -> {confidential_source, public_source, model_output,
             tool_invocation, tool_result, public_sink}
E ⊆ V × V × {data, control}   # 数据依赖或控制依赖
```

第一阶段**不支持 declassification**。

### 2.2 前向闭包判定

称 `S ⊆ V` 为 High 源的前向闭包，若：

1. `∀ v : L(v)=High ⇒ v ∈ S`；
2. `∀ (u,v) ∈ E : u ∈ S ⇒ v ∈ S`；
3. `∀ v : type(v)=public_sink ∧ L(v)=Low ⇒ v ∉ S`。

若存在这样的 S，则称 G 满足 Trace-IFC Compliance。等价的朴素判据是：不存在从任何 High 标记节点到任何 Low 标记 public_sink 的有向路径。

本仓库在 Phase 1A 同时实现闭包判定与 BFS/DFS 可达性判定，并要求两者在全部测试图上一致。

### 2.3 与 N1 的关系

N2 是**存在性 + 单图**性质：它回答“这条被记录的图有没有 High→Low 流”。N1 是**全称 + 跨运行**性质。N2 可作为审计证据，但不能被写成“系统满足 noninterference”。

术语纪律：文档中“IFC 合规”默认指 N2；提到 N1 时必须写全称“经典两运行 noninterference”。

## 3. 运行时执行保证（N3）

N3 关心：采集器是否真实、完整、不可绕过地记录了执行。包括事件来源认证、缺漏检测、工具调用边界、调用参数与结果绑定、时钟/nonce 新鲜性等。

本项目的立场：

- 证明关系以盲化承诺 `C=H(BLIND+cap, root_G, blind)` 为锚点，证明的是**被承诺的图**合规；
- 若采集器漏掉一条 High→Low 边，则“漏记后的图”可能合规，证明依然成立；
- 因此验证者的信任边界仍包含采集器完整性；ZKP 不消除这一信任，只是使验证者不必信任证明者提供的图内容。

反例 D（漏掉危险边）在 `tests/test_phase1a.py` 中显式实现。

## 4. 对已认证会话图的零知识合规证明（N4）

### 4.1 公开输入

```
C               # 随机盲化图承诺（Pallas/Poseidon，隐藏 root_G 与 blind）
policy_id       # 公开策略标识（固定版本）
session_id      # 会话标识
nonce           # 验证者 nonce
collector_id    # 采集器身份/公钥标识
```

采集器对 `(C, policy_id, session_id, nonce, collector_id)` 的签名由验证者在电路外校验；电路内部计算 `C` 并约束其与公开值一致。`root_G` 与 `blind` 均不公开（Phase 1B.1 修订）。签名验证信任模型见 `docs/COMMITMENT_AND_PROVENANCE.md`。

### 4.2 见证

```
w = (nodes, edges, labels, S, encoding_aux, merkle_paths, collector_attestation_fields)
```

### 4.3 证明关系 R

给定公开输入 `x=(C, policy_id, session_id, nonce, collector_id)`，证明者持有 w，使得：

1. 图编码 Merkle 根 `root_G` 与见证中的 `blind` 共同生成公开承诺 `C`（电路内计算并绑定）；
2. 所有节点、边、标签和数量满足编码格式（类型域、标签域、索引范围、数量上限）；
3. 所有 High 来源都属于隐藏前向闭合集合 S；
4. 所有 Low 输出均不属于 S；
5. S 对图中所有边前向闭合；
6. 证明绑定当前会话和验证者 nonce（公开输入约束 + 承诺域分离）；
7. 图盲化承诺由指定可信采集器认证（验证者验签；电路绑定同一 `C`）。

`Verify(x, π)=1` 时，验证者只学到：存在满足上述条件的隐藏图。学不到节点内容、边结构、标签分布、S 的具体形状或工具名/参数。

### 4.4 明确不证明

- 不证明采集器没有漏记事件（N3）；
- 不证明标签来源真实性（错误降级标签仍是“合规的坏图”，反例 E）；
- 不证明经典两运行 NI（N1）；
- 不证明 LLM 内部推理安全；
- 不把参考模型测试当作密码学安全证明（S1）。

## 5. 停止条件与研究假设

研究假设：相对于“普通明文图检查器”和“承诺 + 签名”，ZK 图合规证明在**不把图交给验证者**的前提下，仍能提供公开可验证的合规判断，且成本可接受。

若第六节停止条件任一成立，则暂停 Halo2 扩展，不以“有电路”为继续理由。见 `docs/DECISION_GATE.md`。
