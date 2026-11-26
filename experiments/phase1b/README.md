# Phase 1B 实测说明

本目录记录 Halo2 原型在固定规模 50/100/200 事件下的实测。

## 电路关系

公开输入：`(root_G, policy_id, session_id, nonce, collector_id)`。
见证：节点类型/标签/S 位、边 src/dst/kind、Merkle 路径输入、公开字段副本。

电路约束：
- 节点类型域 0..5（3 位分解）、标签布尔、S 布尔；
- C1：High ⇒ S；
- C2：每条 active 边 `S[src] ⇒ S[dst]`，通过 copy constraint 把边的 S 位绑定到节点 S 位；
- C3：`public_sink ∧ Low ⇒ S=0`；
- 边端点必须等于某个已承诺节点的索引（copy 到 `node_index`），且 `src != dst`（delta 逆元门）；
- Poseidon Merkle 承诺重算并绑定到 `root_G`；
- 公开字段副本绑定到 instance。

采集器 Ed25519 签名在电路外验证；nonce 唯一性由协议层负责。

## 指标边界

- `k` 是 Halo2 domain log2；取通过 keygen 的最小值。
- `poseidon_permutations` 由编码结构确定性计数：节点/边叶子各 2 次置换（ConstantLength<3>），empty/merge 各 1 次（ConstantLength<2>）。
- `own_gate_declarations=2`，`own_constraints=13`，`poseidon_gate_declarations=3`（来自 halo2_gadgets Pow5Chip 源码）。halo2_proofs 0.4 公共 API 不暴露精确全局约束数，因此不编造该数字。
- `witness_field_elements` 是见证主要字段的计数估计，不含证明系统内部 witness。
- `proof_bytes` 为 Blake2b transcript 序列化字节数。
- `peak_working_set_mb` 由 Windows `PeakWorkingSetSize` 采样得到。
- 时间包含 keygen / prove / verify 独立分段；keygen 与证明使用相同 active 模式，避免形状不匹配。active 边数（密度）在本原型中是公开形状参数，不是隐藏见证；生产化时应把上限固定为与策略公开的静态形状。

## 反例检查

- 错误 nonce 的公开输入使验证失败；
- 错误采集器签名被拒绝；
- 对 50 事件规模，加入一条 High→Low-sink 边后 `MockProver::verify()` 失败。

这些是原型正确性测试，不是密码学安全证明，也不是隐藏性的统计测试。
