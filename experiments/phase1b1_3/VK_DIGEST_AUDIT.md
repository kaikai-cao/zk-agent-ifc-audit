# VK Digest 稳定性与定位审计（Phase 1B.1.3 / C）

## 1. 当前实现

`halo2/src/main.rs::vk_digest()`：

```rust
let pinned = format!("{:?}", vk.pinned());
// digest = SHA-256(pinned.as_bytes())
```

setup 写入两个不同用途的字段：

| 字段 | 计算 | 用途 |
| --- | --- | --- |
| `vk_hash` | `host_hash::<3>([DOMAIN_BIND+cap, k, CIRCUIT_VERSION.len()])` | 公开固定参数标识符；verifier 用它做快速 schema/参数门禁，与 VK 内容本身无关 |
| `vk_digest` | `SHA256(format!("{:?}", vk.pinned()))` | 声称绑定实际 VK 内容；verifier 重建固定模板 VK 后比较 |

两者都进入 `setup50.json`，verifier 都会检查。二者角色不同：`vk_hash` 只依赖公开参数（cap/k/版本字符串长度），`vk_digest` 才是试图覆盖 VK 内容的摘要。

## 2. C1：五个问题的回答

**Q1. Debug 格式是否为稳定、规范化的跨版本序列化格式？**
否。`format!("{:?}", ...)` 是 Rust `Debug` 派生/手写实现，语言层面不保证跨编译器版本、跨 `halo2_proofs` 版本、跨依赖补丁版本的字段顺序或文本表示稳定。它不是规范化（canonical）序列化。`vk.pinned()` 是 halo2 0.4 提供的"pinned VK"视图，比直接对 `VerifyingKey` 取 Debug 更聚焦于验证所需结构，但其 `Debug` 文本仍不构成正式序列化协议。

**Q2. 相同代码、相同依赖、相同参数下是否稳定？**
预期稳定，本阶段用 `scripts/vk_digest_stability.py` 对同一二进制连续三次 `setup(50)` 做实测（见第 4 节）。该结论仅限"同一构建内重复运行"，不外推。

**Q3. 不同 cap 是否得到不同 digest？**
电路形状随 cap 变化（节点行数、crossbar 行数、固定列尺寸），因此 `vk.pinned()` 不同、digest 应不同。本阶段实验规模限定 cap=50，未实测 cap=100/200 的 digest；`vk_hash` 则显式含 `DOMAIN_BIND+cap`，按构造必然随 cap 变化。此回答基于代码结构，不是跨 cap 实测。

**Q4. 修改电路版本是否能检测到 digest 变化？**
分两种：(a) 若修改改变了电路约束/列布局/置换等 pinned 结构，`vk_digest` 会变；(b) `vk_hash` 只用了 `CIRCUIT_VERSION.len()`——若把版本字符串改成**等长**的另一文本，`vk_hash` 不变。因此 `vk_hash` 不是可靠的版本指纹；`CIRCUIT_VERSION` 作为元数据写入 setup/public，但真正的版本绑定依赖 pinned 结构变化。这是一处需要如实记录的弱点。

**Q5. digest 是否真正覆盖验证者所需的全部 VK 信息？**
`vk.pinned()` 覆盖 halo2 0.4 认为"pin 后不再随 prove 变化"的 VK 部分（固定列、置换、selector 多项式承诺等），但 verifier 仍需独立的 `k` 与固定模板 `IfcCircuit::template(cap)` 才能重建完整验证上下文；`vk_digest` 不替代 `k`/模板/curve 元数据。因此本实现是"重建 + 摘要钉住"，不是" opaque VK 序列化后直接喂给 verifier"。

## 3. C2：处理方式

halo2_proofs 0.4 未提供稳定的 VK 字节序列化 API。本阶段据实处理：

1. 不把 `vk_digest` 称为正式 VK serialization；明确标记为 **pinned-build prototype digest**；
2. setup metadata 已包含 `circuit_version`、`cap`、`edge_cap`、`k`、`schema`；依赖版本由 `halo2/Cargo.lock` 固定（halo2_proofs 0.4.0、Pallas/vesta、sha2 0.10.9、ed25519-dalek 2.1.1、rand 0.10.4），见 `REPRODUCTION_LOG.md`；
3. 对重复 setup 做稳定性测试（第 4 节）；
4. 明确声明：跨编译器、跨依赖版本的兼容性**尚未保证**，需要自定义 VK 序列化或升级到提供稳定序列化 API 的证明库才能闭合。

本阶段不强行实现自定义 VK 序列化协议。

## 4. 稳定性测试（原始证据）

证据文件：`raw/vk_digest_stability.json`（`scripts/vk_digest_stability.py` 三次独立 `setup(50)` 进程）。

| run | k | circuit_version | vk_digest（前 16 hex） | vk_hash（前 16 hex） | exit |
| --- | --- | --- | --- | --- | --- |
| 1 | 15 | phase1b1-2-soundness-v1 | `09a7d83d3a397ec5` | `3d84086f4e9127271` | 0 |
| 2 | 15 | phase1b1-2-soundness-v1 | `09a7d83d3a397ec5` | `3d84086f4e9127271` | 0 |
| 3 | 15 | phase1b1-2-soundness-v1 | `09a7d83d3a397ec5` | `3d84086f4e9127271` | 0 |

- `vk_digest_stable_within_build = true`
- `vk_hash_stable_within_build = true`
- `distinct_digests = 1`

三个独立进程的 `vk_digest` 与 `vk_hash` 完全一致；同一 digest 亦出现在正向 prove 的 VK 一致性断言中（`summary.json` 三例 prove 的 `accepted=true` 即通过 `vk_digest` 比对）。这支持"同一构建内重复可复现"，不跨构建外推。

## 5. 结论边界

- 可支持：同一二进制、同一依赖集下，`vk_digest` 可重复，且 verifier 重建的模板 VK 与 setup 钉住的 digest 一致（真实证明与验证通过即为佐证）。
- 不支持：该 digest 是跨版本稳定序列化；`vk_hash` 是可靠版本指纹；跨编译器/依赖兼容性已建立；任何形式化 soundness 证明。
