# 图承诺与来源认证设计

## 1. 为什么需要两层分离

承诺回答：“这个 root 对应哪张图？”
来源认证回答：“这个 root 是指定采集器在指定会话中认证的吗？”

二者不能混为一谈。一个有效签名配上一个不存在相应见证的 root，验证者仍无法相信图合规；一个正确承诺没有采集器认证，则图可能由证明者自造。

本项目采用（Phase 1B.1 修订）：
- 电路内：Merkle/Poseidon 绑定根计算 + **随机盲化承诺** + 公开字段绑定；
- 电路外：采集器对公开输入元组的数字签名验证。

必须区分两个概念：
- `root_G` 是绑定用的固定规模 Merkle 根，**未盲化**，单独公开时可通过枚举图字典恢复图；
- `C = H(DOMAIN_BLIND + cap, root_G, blind)` 才是公开承诺，`blind` 为每会话采样的 secret 域元素。验证者只见 `C`，不见 `root_G` 与 `blind`。

## 2. Poseidon 参数

```
field      = Pallas base field
spec       = P128Pow5T3 (x^5 S-box)
width (t)  = 3
rate       = 2
domain     = fixed constants: NODE, EDGE, EMPTY, BIND, BLIND
```

域标签以域元素形式作为每个 Poseidon 调用的第一输入，防止不同类型的叶子/合并被互换复用。

叶子与承诺（Phase 1B.1 实现）：
```
node_leaf(i)  = H<3>(NODE + cap, type_i*2 + label_i, i)
edge_leaf(j)  = H<3>(EDGE + cap, src_j*cap + dst_j, kind_j)
empty_leaf    = H<2>(EMPTY + cap, 0)
merge(a,b)    = H<2>(a, b)
root_G        = Merkle(node_leaves || edge_leaves)
C             = H<3>(BLIND + cap, root_G, blind)
```
`blind` 在电路内参与 `C` 的计算并通过等式约束绑定到公开实例第 0 项；图或 `blind` 任一改变都会改变 `C`，原证明无法复用。

注意 `H` 用 width=3/rate=2 的 sponge；叶子/承诺输入长度为 3，空叶/合并为 2。不同用途通过域标签区分；固定容量下所有布局均为常量。

## 3. Merkle 承诺构建

1. 加载 `n` 个节点叶子和 `m` 个边叶子；
2. 叶层补齐到 `2^depth` 个位置，空位填 `empty_leaf`；
3. 逐层两两 `merge` 到 `root_G`；
4. 若 `n=0` 或 `m=0`，仍保留固定空叶编码，避免 root 退化。

承诺绑定节点/边的**顺序**。顺序由采集器在会话事件序号上固定，Phase 1A 与 1B 使用同一 canonical ordering。

## 4. 会话与 nonce 绑定

采集器签名消息（canonical JSON / 定长域编码）为：

```
attestation = (C, policy_id, session_id, nonce, collector_id)
```

`nonce` 由验证者生成并在一次验证请求中使用；协议层负责记录已消费 nonce，防止重放。SNARK 本身只保证证明与该公开输入绑定，不维护全局状态。

电路见证复制这些字段，并用等式约束绑定到公开输入。若把签名消息替换为 `{root_G}` 而不含 session/nonce，则同一 root 的证明可被重放；本设计避免这一点。公开的是盲化承诺 `C`，因此同一张图在不同会话使用不同 `blind` 时也不会产生可关联的公开根。

## 5. 采集器密钥与身份

- Phase 1A/1B 原型用 Ed25519 固定测试密钥对（公开测试用，不作生产安全）；
- `collector_id` 是公钥标识（哈希或公钥字节的域表示），验证者从可信配置获得公钥；
- 更换采集器公钥需要带外治理流程，不由证明关系决定。

## 6. 证明者不能做的事

| 攻击 | 结果 |
| --- | --- |
| 用不满足闭包关系的 G 出证明 | soundness 下不可行 |
| 修改公开 `root_G` 但复用 π | Verify 失败（公开输入绑定） |
| 修改 nonce/session 复用 π | Verify 失败 |
| 用另一个图产生相同 `C` | 需同时命中 `root_G` 与 `blind`，或 Poseidon 碰撞/第二原像 |
| 枚举候选图并比对公开根 | 被盲化阻断：公开的是 `C` 而非 `root_G`，每个候选还需猜中 255-bit `blind` |
| 跨会话关联同一张图 | 每次采样新 `blind` 即得到不同 `C`；若复用 `blind` 则关联风险回归 |
| 从 π 恢复边结构/标签 | SNARK zero-knowledge（协议层声明，本原型未做统计隐藏性测试）；与承诺隐藏性是不同保证 |
| 伪造采集器签名 | 需 Ed25519 私钥；原型测试用错误签名拒绝 |
| 漏记边后仍得到“真实执行无泄露”结论 | 不可：只能得到“被承诺图合规” |

## 7. 与经典图形承诺的区别

普通 graph commitment + signature 也能绑定 root，但验证者要么重算谓词（需拿到图），要么信任签名者的判定。本项目把“重算谓词”改成“验证盲化承诺隐藏图上的证明”，新增的是**不暴露图的公开可验证性**；采集器完整性信任并未减少。

残留公开元数据仍可能泄漏：cap/edge_cap、密度/活动边数、策略 ID、会话 ID、nonce、采集器 ID、证明大小与计时，以及验证者自身已知的上下文。盲化不隐藏这些字段，也不隐藏“存在一次合规判定”这一事实。

## 8. Phase 1B.1.2 修订

1B.1 的承诺公式未变，但新增了以下电路约束，使公式中的字段不再是自由 advice：

```
node_tl_i   = 2 * node_type_i + label_i
node_index_i = fixed_row_position_i
edge_idx_j  = src_j * cap_fixed + dst_j
domain_cell in {NODE, EDGE, EMPTY, BLIND} + cap  (fixed-column pinned)
empty_padding_input = 0
crossbar block prev_* at row 0 = 0
```

`src/dst` 的范围和 `S[src]/S[dst]` 继续由固定 one-hot crossbar 与 copy constraint 约束；`q_first` 防止证明者通过非零初始累加器伪造查表结果。修复前的五类拆字段攻击见 `experiments/phase1b1_2/ATTACK_CASES.md`。

来源认证方面，`collector_id` 现在统一定义为：

```
collector_id = big_endian_u64(SHA256(raw_ed25519_public_key)[0..8]) & (2^63 - 1)
```

Rust 与 Python 使用同一规则。验证者从 `config/trusted_collectors.test.json`（仅测试信任根）按 `collector_id` 查找公钥，重新派生 ID 后验签；`public.json` 中任何自称公钥字段均被忽略。正式部署必须替换该 allowlist。

盲化方面，正式证明路径由操作系统 CSPRNG 采样 254-bit blind，不再从 CLI seed 派生。`public.json` 和 `GraphEncoding.as_dict()` 均不输出 blind；`density` 与 `active_edges` 只进入 benchmark 私有 `meta.json`，不属于证明 public inputs。这里只说明随机化接口按预期工作，不声称已形式化证明统计隐藏性。
