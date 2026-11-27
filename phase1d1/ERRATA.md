# Phase 1D.1 — Soundness Errata

基线：`phase1d-inductive-ifc-certificate` @ `4c349ee56998140438e916466c0030b32b0912ee`（父 `2ac445c`）
本分支：`phase1d1-soundness-errata`
修改范围：`phase1d/{FINITE_AGENT_MODEL,PROPERTY_DEFINITIONS,INDUCTIVE_CERTIFICATE,SOUNDNESS_PROOF}.md` + 本文件
冻结未改：`phase1d/{COMPLEXITY_COMPARISON,RELATED_WORK_AUDIT,DECISION}.md`

**本轮裁决：PARTIAL**——bounded weak bisimulation 的充分性已证明；对 bounded NI（trace equivalence）的完备性**未**证明，且给出不完备反例。未进入 Halo2 原型。

---

## 1. 原定义的问题（逐条）

| # | 原文档位置 | 问题 | 后果 |
| --- | --- | --- | --- |
| E1 | `FINITE_AGENT_MODEL` §2.3–2.4、`PROPERTY_DEFINITIONS` §1 | `A = A_L ⊎ A_I`，`lowEffect(a)=ε`；`ε` 作为元素留在 `obs` 序列中 | `(ℓ₁,ε,ℓ₂)` 与 `(ℓ₁,ℓ₂)` 被当作不同观察；违反任务包 D2 |
| E2 | `FINITE_AGENT_MODEL` §2.4 | `δ:S×A→𝒫(S)`，空集表示动作不可用，但无 `Enabled(s)` 定义 | 空集与"动作存在但无后继"歧义；真空通过风险 |
| E3 | `INDUCTIVE_CERTIFICATE` §2.2 `Sync(4)` | 强制 `τ` 对 `τ` 逐步同步，配合 stuttering 公理对齐长度 | 与"内部步数可不等"的弱转移语义冲突；旧证明在 `a₀∈A_I` 分支含混 |
| E4 | `INDUCTIVE_CERTIFICATE` §3–4 | 单关系 `I(s₀,s₁)`，无预算索引 `k` | 无法区分"全局不变量 / 可达不变量 / 有界证书"三个层次 |
| E5 | `SOUNDNESS_PROOF` §2.1 引理 A | 引理命题含"`Obs⁺` 一致到 k 步"但未定义该谓词；证明引用不存在的 Step 前提 | 引理不可检验 |
| E6 | `SOUNDNESS_PROOF` §2.2 步骤 2 `a₀∈A_L` | 需假定 `a₀` 在 `s₁` 可用（旧 AM2），但旧 (Init)/(Obs) 不保证这一点 | 归纳步骤有缺口；旧文把它推给"额外模型假设" |
| E7 | `SOUNDNESS_PROOF` §4.1–4.2 | "状态重命名 / 不同 pc 标号"反例 | 允许任意二元关系即可证明，**不构成**不完备性证明 |
| E8 | `SOUNDNESS_PROOF` §4.3 + 冻结 `COMPLEXITY_COMPARISON` §5 + 冻结 `DECISION` | "紧凑 I 与完备 I 不可兼得"写成普遍断言，标注"[推论]，未形式化证明" | 无复杂度假设/归约/下界支撑的过度断言 |
| E9 | 全部四份文档 | 只按"执行步数"谈 `T`，未区分可观察动作与内部动作 | `T` 边界含混；τ-divergence 未定性 |

---

## 2. 修正后的定义（摘要）

| 项 | 修正后定义 |
| --- | --- |
| 模型 | `M=(S,Λ,→,Init,Obs,Term,X_L,X_H,T)`，有限 LTS；`Λ` 为低可观察标签，`τ∉Λ` |
| 内部动作 | 原 `A_I` 全部统一投影为 `τ`；原 `A_L` 映射为 `Λ` 标签 |
| 弱转移 | `s ⇒^ℓ t ⟺ ∃u,v: s —τ→* u ∧ u —ℓ→ v ∧ v —τ→* t`（`ℓ∈Λ`）；`s ⇒^ε t ⟺ s —τ→*` |
| `T` | 只限制可观察动作数；`τ` 数不计入；`τ`-divergence 默认不产生观察差异 |
| 观察 | `obs(π)=(visibleTrace(π), Term(last(π)))`；`visibleTrace=delete_τ(a₁..a_n)`，序列内无 ε |
| 缓冲一致性 | AM0：`τ` 不改 `Obs`；`—ℓ→` 使 `Obs(s')=Obs(s)·ℓ` ⇒ `Obs(s_n)=Obs(s₀)·visibleTrace(π)` |
| 动作可用性 | `Enabled(s)={a∈Λ∪{τ} \| ∃s': s—a→s'}`；非确定性所有后继参与匹配 |
| 终止 | `RUN/DONE/STUCK` 明确；`DONE≠STUCK`；`T` 内未终止记 `RUN` |
| 证书 | 有界关系族 `I₀..I_T`，`k` = 剩余可观察预算；条件 (OBS)+(BASE)+(TAU)+(STEP)+(INIT) |
| (TAU) | `I_k(s₀,s₁) ∧ s₀—τ→s₀' ⇒ ∃s₁': s₁⇒^ε s₁' ∧ I_k(s₀',s₁')`（对称）；`⇒^ε` 含零步 |
| (STEP) | `I_{k+1}(s₀,s₁) ∧ s₀⇒^ℓ s₀' ⇒ ∃s₁': s₁⇒^ℓ s₁' ∧ I_k(s₀',s₁')`（对称） |
| (INIT) | `∀x_L∀h₀∀h₁ : I_T(Init(x_L,h₀),Init(x_L,h₁))`；否决 `∃` 与自选子集 |
| 定理 | 若 AM0–AM3 + 五组证书条件 ⇒ `Tr_T(Init(x_L,h₀))=Tr_T(Init(x_L,h₁))`（`C_T`） |

---

## 3. 被撤回的旧结论

1. **撤回** `Sync(a₀,a₁)` 强制 `τ` 对 `τ` 逐步同步（E3）；替换为弱转移 + (TAU)。
2. **撤回** `obs` 序列内保留 `ε` 的写法（E1）；`(ℓ₁,ε,ℓ₂)=(ℓ₁,ℓ₂)`。
3. **撤回** `SOUNDNESS_PROOF` §4.1（状态重命名 `ctr`）与 §4.2（不同 `pc` 标号）作为不完备性反例的地位（E7）；二者只能说明"浅层受限 I 不够"。
4. **撤回** "紧凑 I 与完备 I 不可兼得"的普遍断言（E8）；降级为 `[待验证]` 假设，本轮不提供下界。
5. **撤回** 旧 AM2（"`I₀` 相等时一侧可用 `A_L` 另一侧也可用"）作为独立模型假设（E6）；新 (STEP) 用 `⇒^ℓ` 与双向匹配直接处理，不需要该假设。
6. **撤回** 旧 stuttering 公理 `s∈δ(s,τ)` 的必要性（E3/E6）；`⇒^ε` 含零步已覆盖。
7. **修正** 反例 II（时序侧信道）（E9）：新默认语义下 `τ` 步数不进 `obs`，反例失效；必须显式把 `tick` 提升为 `Λ` 标签才能恢复。

---

## 4. 仍然成立的结论

1. **A/B/C 不可比较**（无 AM2/AM3 时）与两个修正反例的逻辑结构成立（`PROPERTY_DEFINITIONS` §5）。
2. **Init 必须对 `X_H` 全称**——否则只证 B 不证 C（阻断项 2）成立，且本轮把它写入 (INIT) 硬约束。
3. **双向匹配必需**——单向只给集合包含，不给相等，成立（(STEP-fwd/bwd)）。
4. **所有非确定性后继必须参与匹配**——成立（∀后继-∃后继）。
5. **`I_k` 的数学内核是 bounded weak bisimulation**——这一识别**成立且更精确**（旧版只说"有界互模拟"，本轮明确是弱互模拟，且给出完整条件）。
6. **ZK 不可替代价值仍未建立**——冻结 `DECISION.md` 的 STOP 理由中，第三阻断项结论不受本轮影响。
7. **模型真实性不在证明内**——成立，且本轮进一步把 AM0 明确为构造公理而非 ZK 自动结论。

---

## 5. 尚未解决的问题（`[待验证]`）

1. **完备性**：`I_k`（bounded weak bisimulation）对 `C_T` 不完备（§反例）。是否存在其他**紧凑**关系证书能覆盖 trace-equivalent but not bisimilar 情形？本轮不主张结论。
2. **复杂度**：`I` 表达能力与证书规模的关系未形式化；不提供下界、归约或复杂度假设。冻结 `COMPLEXITY_COMPARISON.md` §5 的"不可兼得"表述需在未来单独修订（本轮范围外，仅记录）。
3. **实现层全称化**：即使在定义上 (INIT) 是 `∀h₀∀h₁`，电路实现是否真对 `X_H` 全称化未验证。
4. **SNARK 隐藏边界**：`I_k`/`→` 作为见证时，验证 ∀后继匹配仍需访问转移结构（承诺+查找论证或公开模板）；隐藏是否免费、泄露哪些规模信息，未验证。
5. **τ-divergence 敏感性**：本定理默认不敏感；需在何种应用场景引入 divergence-sensitive 语义，未研究。
6. **模型来源信任**：ZK 不能证明被承诺模型忠实描述真实 Agent（Phase 1C 停止条件 5）。
7. **冻结文档同步**：`COMPLEXITY_COMPARISON.md` §5、`DECISION.md` §4 中"紧凑/完备不可兼得"的文字仍与本协议冲突；因范围冻结未改，留待下一阶段。

---

## 6. 裁决依据（PASS / PARTIAL / FAIL）

| 标准 | 判定 |
| --- | --- |
| Soundness 定理成立 | ✅ 完整七步证明，含 τ 段对齐、双向后继匹配、终止/长度/非确定性处理（§2–4） |
| 证书适用边界清楚 | ✅ 明确 `I_k` = bounded weak bisimulation，`⇒ C_T` 但反向不成立（§5 反例） |
| 对 bounded NI 完备 | ❌ 未证明，且给出反例说明 `I_k` 形式不完备 ⇒ 不能判 PASS |
| 量词/非确定性/终止/动作匹配漏洞 | 无（本轮逐条修复 E1–E9）⇒ 不能判 FAIL |

**⇒ PARTIAL**。按用户裁决标准："证明了 bounded bisimulation 的充分性，但没有证明对 bounded NI 的完备性"——与本节判定一致。

**由此不进入 Halo2 原型**：本轮修好了定理，但没有改变 Phase 1D 的核心研究判断（数学内核是标准互模拟，ZK 价值未建立）。冻结 `DECISION.md` 的 STOP 裁决**不因本轮修改而改变**；只在 `ERRATA.md` 记录其推导链中的一处未证明断言需未来处理。
