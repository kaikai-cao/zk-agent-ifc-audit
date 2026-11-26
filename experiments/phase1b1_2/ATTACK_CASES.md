# Phase 1B.1.2 恶意 witness 攻击用例

本文件记录“谓词检查字段”和“承诺 preimage 字段”被故意拆开的尝试。原始结果保存在：

- `raw/pre_fix_attacks.json`：加入 A1–A4 约束之前；
- `raw/post_fix_attacks.json`：加入约束之后。

所有用例在 cap=50 下以 `MockProver` 运行。`compliant` 是正常 witness；其余为攻击/负向用例。`satisfied=true` 表示电路约束被满足。

## 1. 修复前可实际利用的缺口

| 攻击 | 修改的 advice / preimage | 修复前 | 修复后 | 结论 |
| --- | --- | --- | --- | --- |
| `node_tl_mismatch` | 节点检查字段改为 High；`leaf_domain` 中参与 Merkle 叶子的 `2*type+label` 保持 Low 编码 | **true** | false | 承诺节点类型/标签与谓词检查脱钩 |
| `node_position_mismatch` | Merkle 叶子中的 `node_index` 改为循环移位位置；谓词仍按真实行位置检查 | **true** | false | 节点位置与固定行位置脱钩 |
| `edge_idx_mismatch` | 检查端点为 Low→Low；`leaf_value` 中的 `src*cap+dst` 改为另一对 Low→Low 端点 | **true** | false | 边承诺 preimage 与谓词端点脱钩 |
| `domain_node` | node Poseidon 域 advice 改为 `DOMAIN_NODE + cap + 1` | **true** | false | 域标签未固定 |
| `domain_edge` | edge Poseidon 域 advice 改为 `DOMAIN_EDGE + cap + 1` | **true** | false | 域标签未固定 |
| `domain_empty` | empty Poseidon 域 advice 改为 `DOMAIN_EMPTY + cap + 1` | **true** | false | 域标签未固定 |
| `domain_blind` | blind Poseidon 域 advice 改为 `DOMAIN_BLIND + cap + 1` | **true** | false | 域标签未固定 |
| `empty_zero` | empty leaf 第二个输入从 0 改为 1 | **true** | false | padding 输入未固定 |
| `crossbar_prev_dst` | 第二个 edge block 的 `prev_dst` 初值设为 1，同时把 `s_dst` 伪造为 1；High→Low 边通过闭合检查 | **true** | false | crossbar 初始累加器可伪造 `S[dst]` |

这些用例说明：修复前“被承诺的图”和“被检查的图”可以由恶意证明者拆开；公开 `C` 只绑定到一组自由 advice，而闭包谓词检查另一组字段。

## 2. 修复前尝试但未成功的 crossbar 变体

以下六个变体分别修改 block 首行的 `prev_src`、`prev_dst`、`prev_sel_src`、`prev_sel_dst`、`prev_idx_src`、`prev_idx_dst`。修复前只有 `prev_dst` 成功绕过；其余被既有 copy constraint 或 selector 累加约束拒绝。修复后六者均由新增 `q_first` gate 直接拒绝。

| 用例 | 修改的首行累加器 | 修复前 | 修复后 |
| --- | --- | --- | --- |
| `crossbar_prev_src` | `prev_src = -1` | false | false |
| `crossbar_prev_dst` | `prev_dst = 1` | **true** | false |
| `crossbar_prev_sel_src` | `prev_sel_src = -1` | false | false |
| `crossbar_prev_sel_dst` | `prev_sel_dst = 1` | false | false |
| `crossbar_prev_idx_src` | `prev_idx_src = 1` | false | false |
| `crossbar_prev_idx_dst` | `prev_idx_dst = 1` | false | false |

诚实边界：这些“未成功”的变体说明攻击没有在修复前全数得手，不说明原电路安全；上表中已有多个字段可拆开承诺与谓词，足以否定原电路的 soundness 命题。

## 3. 真实证明层负向结果

真正的 `create_proof` / `verify_proof` 结果见 `RESULTS.md` 与 `raw/proof_layer_negatives.json`。合规 witness 必须正向通过；`illegal_ifc`、节点/边 preimage mismatch、crossbar 篡改允许在 `create_proof` 阶段直接失败；若生成 proof，则必须被 `verify_proof` 拒绝。

`verify` 现在从独立 allowlist 读取采集器公钥，忽略 `public.json` 中任何自称的公钥字段；伪造公钥、错误 `collector_id`、错误 nonce 的测试见 `raw/collector_attacks.json`。
