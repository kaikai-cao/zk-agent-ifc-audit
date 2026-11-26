# Trace-IFC 关系定义（Phase 1A/1B 共用）

## 1. 图模型

```
V = {0,1,...,n-1}, n <= MAX_EVENTS
type[v] ∈ T = {0: confidential_source, 1: public_source, 2: model_output,
               3: tool_invocation, 4: tool_result, 5: public_sink}
label[v] ∈ {0:Low, 1:High}
E = {(u,v,k)}, u,v ∈ V, u != v, k ∈ {0:data, 1:control}
```

第一阶段限制：
- 不支持 declassification；
- 标签格只有 Low < High；
- 边只表示数据或控制依赖；
- 固定上限图规模，Phase 1B 分别测试 `MAX_EVENTS ∈ {50,100,200}`。

## 2. 朴素判定（BFS/DFS）

从所有 `label[v]=High` 的节点出发做可达性搜索；若存在 `type[w]=public_sink` 且 `label[w]=Low` 的节点被到达，则拒绝；否则接受。

该判定与下面的前向闭包判定应在 Phase 1A 全部测试图上一致。

## 3. 前向闭包判定（电路采用）

见证包含布尔数组 `S[0..n-1]`。接受条件：

```
(C1) ∀ v: label[v]=1 ⇒ S[v]=1
(C2) ∀ (u,v,k)∈E: S[u]=1 ⇒ S[v]=1        # 等价 S[u]*(1-S[v])=0
(C3) ∀ v: type[v]=5 ∧ label[v]=0 ⇒ S[v]=0
(C4) ∀ v: S[v] ∈ {0,1}
```

注意 C3 只约束 public_sink。若把“所有 Low 节点都不在 S”写成约束，会错误拒绝合法中间节点；任务表述“所有 Low 输出均不属于 S”对应 public_sink。

等价性证明（概念）：
- 若存在 High→Low-sink 路径 `v0→v1→...→vm`，由 C1 得 `S[v0]=1`，由 C2 归纳得 `S[vm]=1`，与 C3 矛盾；
- 反之若无路径，取 S 为 High 节点的前向可达集，则 C1–C3 成立。

## 4. 编码与承诺

### 4.1 叶子编码

每个节点编码为域元素元组：

```
leaf_node[v] = Poseidon(DOMAIN_NODE, type[v], label[v], v, n)
```

每条边编码为：

```
leaf_edge[j] = Poseidon(DOMAIN_EDGE, src[j], dst[j], dep_kind[j], j)
```

`DOMAIN_NODE / DOMAIN_EDGE` 为固定域分离常数，避免节点/边叶子互换。

### 4.2 Merkle 承诺

把 `leaf_node[*]` 与 `leaf_edge[*]` 顺序放入固定大小叶层，空叶用 `DOMAIN_EMPTY` 编码；逐层 `Hash(DOMAIN_MERGE, left, right)` 得到 `root_G`。Phase 1A 用 Python 复刻同一 Poseidon 参数；Phase 1B 用 halo2_gadgets 的 Pow5Chip（Pallas, P128Pow5T3, width 3, rate 2）。

承诺只绑定编码值与顺序；它不绑定采集器是否观察完整（见 `SECURITY_MODEL.md`）。

## 5. 公开输入与绑定

```
x = (root_G, policy_id, session_id, nonce, collector_id)
```

电路约束：
- 见证中的 `root_G_witness` 与公开 `root_G` 相等；
- 见证中的 `policy_id/session_id/nonce/collector_id` 与公开值相等；
- 这些值参与域分离编码，防止将同一证明用于不同会话/策略/nonce。

采集器签名在电路外验证：

```
Sig = Sign(sk_C, encode(root_G, policy_id, session_id, nonce, collector_id))
Verifier: Verify(pk_C, Sig, x) == 1 且 Verify_ZK(x, π) == 1
```

验证者不把签名验证交给证明者，也不信任证明者提供的公钥。

## 6. 关系 R（最终形式）

```
R(x, w) = 1  iff
  EncodingValid(w.graph, MAX_EVENTS)                     # 类型/标签/索引/数量
  ∧ MerkleRoot(w.graph_encoding) == x.root_G             # 承诺绑定
  ∧ BindingFields(w) == (x.policy_id,x.session_id,x.nonce,x.collector_id)
  ∧ ForwardClosureExists(w.graph, w.S)                   # C1–C4
```

`Verify(x, π)=1` 意味着（在 soundness 假设下）存在 w 使 R(x,w)=1。

明确不包含：
- `Complete(w.graph, actual_execution)`（采集器完整性）；
- `LabelTruth(w.graph, real_sources)`（标签真实性）；
- `NI(system)`（两运行全局非干扰）；
- `ExecTruth(events, tool_results)`（运行时执行真实性）。

## 7. 反例与本关系的对应

| 测试 | 输入变化 | R 的结果 | 说明 |
| --- | --- | --- | --- |
| A | 无 High→Low 路径 | 接受 | 正例 |
| B | 直接 High→Low 边 | 拒绝 | C2+C3 矛盾 |
| C | 多跳 High→Low 路径 | 拒绝 | C2 归纳传播 |
| D | 漏掉危险边后伪造 clean graph | 对新 G 接受 | 证明关系不检测采集器漏报 |
| E | 错误降级标签 | 可能对坏图接受 | 标签来源真实性不在 R 内 |
| F | nonce/session 不匹配 | 拒绝 | 公开输入绑定 |
| G | 节点/边/标签编码不一致 | 拒绝 | Merkle 根不匹配 |

## 8. Phase 1B 的规模策略

- 只支持固定 `MAX_EVENTS`，不在同一电路里动态支持任意 n；
- 叶层固定容量，空叶参与承诺；
- 不加入递归证明；
- LLM 推理不进电路，只把其输出作为 `model_output` 节点/边的来源事件记录；

约束规模随 `MAX_EVENTS` 与边数线性增长，Merkle 树深度 `ceil(log2(leaf_count))`。实测见 `experiments/phase1b/RESULTS.md`。
