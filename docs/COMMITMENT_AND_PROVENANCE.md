# 图承诺与来源认证设计

## 1. 为什么需要两层分离

承诺回答：“这个 root 对应哪张图？”
来源认证回答：“这个 root 是指定采集器在指定会话中认证的吗？”

二者不能混为一谈。一个有效签名配上一个不存在相应见证的 root，验证者仍无法相信图合规；一个正确承诺没有采集器认证，则图可能由证明者自造。

本项目采用：
- 电路内：Merkle/Poseidon 承诺验证 + 公开字段绑定；
- 电路外：采集器对公开输入元组的数字签名验证。

## 2. Poseidon 参数

```
field      = Pallas base field
spec       = P128Pow5T3 (x^5 S-box)
width (t)  = 3
rate       = 2
domain     = fixed constants: NODE, EDGE, EMPTY, MERGE, BIND
```

域标签以域元素形式作为每个 Poseidon 调用的第一输入，防止不同类型的叶子/合并被互换复用。

叶子：
```
node_leaf(v) = H(NODE, type_v, label_v, v, n)
edge_leaf(j) = H(EDGE, src_j, dst_j, dep_j, j)
empty_leaf   = H(EMPTY, 0, 0, 0, 0)
merge(a,b)   = H(MERGE, a, b)
```

注意 `H` 用 width=3/rate=2 的 sponge，输入长度固定为 4 或 3；不同长度通过域标签与固定槽位区分。

## 3. Merkle 承诺构建

1. 加载 `n` 个节点叶子和 `m` 个边叶子；
2. 叶层补齐到 `2^depth` 个位置，空位填 `empty_leaf`；
3. 逐层两两 `merge` 到 `root_G`；
4. 若 `n=0` 或 `m=0`，仍保留固定空叶编码，避免 root 退化。

承诺绑定节点/边的**顺序**。顺序由采集器在会话事件序号上固定，Phase 1A 与 1B 使用同一 canonical ordering。

## 4. 会话与 nonce 绑定

采集器签名消息（canonical JSON / 定长域编码）为：

```
attestation = (root_G, policy_id, session_id, nonce, collector_id)
```

`nonce` 由验证者生成并在一次验证请求中使用；协议层负责记录已消费 nonce，防止重放。SNARK 本身只保证证明与该公开输入绑定，不维护全局状态。

电路见证复制这些字段，并用等式约束绑定到公开输入。若把签名消息替换为 `{root_G}` 而不含 session/nonce，则同一 root 的证明可被重放；本设计避免这一点。

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
| 用另一个图产生相同 root | 需 Poseidon 碰撞/第二原像 |
| 从 π 恢复边结构/标签 | zero-knowledge（协议层声明，本原型未做统计隐藏性测试） |
| 伪造采集器签名 | 需 Ed25519 私钥；原型测试用错误签名拒绝 |
| 漏记边后仍得到“真实执行无泄露”结论 | 不可：只能得到“被承诺图合规” |

## 7. 与经典图形承诺的区别

普通 graph commitment + signature 也能绑定 root，但验证者要么重算谓词（需拿到图），要么信任签名者的判定。本项目把“重算谓词”改成“验证隐藏图上的证明”，这是相对签名基线新增的可验证性与隐私；采集器完整性信任并未减少。
