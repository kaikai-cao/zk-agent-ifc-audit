# Phase 1C — 任务 1：真实基线恢复与核对

核对时间：2026-11-27（GMT+8）。仓库：`kaikai-cao/zk-agent-ifc-audit`，本地路径 `D:/Research/zk-agent-ifc-audit`。

本阶段严格只读。执行的操作只有：`git status`、`git rev-parse`、`git branch -v`、`git ls-remote`、`git cat-file`、`git diff`、`git fetch origin phase1b1-2-soundness:refs/remotes/origin/phase1b1-2-soundness`（仅更新远端跟踪引用，不改动工作区、本地分支、main）。**未执行** reset / rebase / 强推 / 任何 commit / 任何对 main 的写入。

证据标记：`[源码/命令核验]` = 本轮由 git 命令或文件原文直接确认；`[文档记载]` = 来自仓库文档，未在本轮重新运行实验；`[推论]` = 由前两类推导，非直接观测；`[待验证]` = 尚未确认。

---

## 1. HEAD 与分支状态（命令核验）

| 项目 | 值 | 备注 |
| --- | --- | --- |
| 当前本地分支 | `phase1b1-3-evidence-closure` | 不是任务描述中假定的 `phase1b1-2-soundness` |
| 当前本地 HEAD | `d3a14f34b3a2d43be2acc0122443e1382ac19892` | 与 `phase1b1-2-soundness` 本地 HEAD 相同 |
| 远端 `phase1b1-2-soundness` HEAD | `1d44e4b4eed80cf5501fa5748d9bea57e5669148` | `git ls-remote` 直接读取，与任务描述一致 |
| 远端 `main` HEAD | `a5acdc5b4bb29dd9a11c6870321834bf29b3422d` | 未被本次任何提交修改 |
| 本地 `main` HEAD | `a5acdc5b4bb29dd9a11c6870321834bf29b3422d` | 与远端 main 一致 |
| 远端 `phase1b1-fixed-verifier` HEAD | `c25bf1ac3652237fec7ef49294839aeb2c37ee3b` | 与本地一致 |
| 本地 `phase1b1-fixed-verifier` HEAD | `c25bf1ac3652237fec7ef49294839aeb2c37ee3b` | 固定基线 |

工作区状态（命令核验）：**不干净**。

```
 M halo2/src/main.rs
?? experiments/phase1b1_3/
?? scripts/run_phase1b1_3.py
?? scripts/vk_digest_stability.py
```

这说明：上一轮"提交推送完成"只覆盖已提交内容；当前工作区存在 Phase 1B.1.3 的未提交证据收集工作。**这些未提交内容不属于任何已核验基线，也不得被本阶段当作已验证事实引用。**

### 跟踪引用缺口（命令核验）

在 `git fetch` 之前，本地**没有** `refs/remotes/origin/phase1b1-2-soundness` 这一跟踪引用（`git branch -a -v` 只列出 `origin/main` 与 `origin/phase1b1-fixed-verifier`）。因此仅看本地 `git branch -a` 会误以为远端不存在该分支。本轮通过 `git ls-remote` 直接从 GitHub 读取真实远端引用，然后 fetch 该单一分支建立跟踪引用。这是本阶段唯一一次写本地 git 元数据的操作，不涉及工作区与分支切换。

---

## 2. `1d44e4b` 与本地 `d3a14f3` 的差异（命令核验）

| 比较项 | 远端 `1d44e4b` | 本地 `d3a14f3` | 结论 |
| --- | --- | --- | --- |
| tree | `dfeda0015f107610de5d337d7bae6f1562425099` | `dfeda0015f107610de5d337d7bae6f1562425099` | **完全相同** |
| parent | `c25bf1ac3652237fec7ef49294839aeb2c37ee3b` | `c25bf1ac3652237fec7ef49294839aeb2c37ee3b` | 相同 |
| commit message | `Phase 1B.1.2 circuit soundness fixes` + 三段说明 | 同左，逐字相同 | 相同 |
| author / committer | `kaikai-cao <1726338747@qq.com>` | `kaikai-cao <kaikai-cao@126.com>` | **不同** |
| timestamp | `1795704516 +0800` | `1795704184 +0800` | **不同（相差 332 秒）** |
| `git diff --name-status 1d44e4b d3a14f3` | — | — | **输出为空** |

**结论（命令核验）**：两者是"提交孪生体"——同一父提交、同一棵树、同一提交信息，**源码与文档内容逐字节相同**；唯一差异是提交者邮箱与时间元数据。`[推论]` 结合时间戳先后与仓库历史，远端版本由 GitHub API 侧写入（本地版本先提交、远端版本后生成）；但 git 对象本身只能证明元数据不同，**不能**证明写入渠道，本阶段不把 API 渠道作为已核验事实。

**操作含义**：不存在"远端领先需要拉取覆盖本地"的情况，也不存在"本地领先需要强推"的情况。任何 resync 都会制造一个内容相同但哈希不同的第三份提交，没有收益。维持现状即可。

---

## 3. 最近提交的实际文件变更（命令核验）

`git diff --stat c25bf1a d3a14f3`：**53 个文件，+1480 / -122**。关键变更：

| 类别 | 文件 | 说明 |
| --- | --- | --- |
| 电路核心 | `halo2/src/main.rs`（+589 / -?） | 承诺 preimage 与谓字段绑定、Poseidon 域固定、crossbar 初始累加器归零、`without_witnesses` 保持 cap |
| 绑定 | `src/ifc_audit/binding.py`、`src/ifc_audit/encoding.py` | 采集器身份派生统一、编码修正 |
| 信任锚 | `config/trusted_collectors.test.json`（新增） | 独立 allowlist 测试 fixture |
| 决策文档 | `docs/DECISION_GATE.md`、`docs/SECURITY_MODEL.md`、`docs/COMMITMENT_AND_PROVENANCE.md`、`README.md` | 更新 soundness 收窄与诚实边界 |
| 实验 | `experiments/phase1b1_2/`（整套新增，含 cap=50 正/负真实证明） | `ATTACK_CASES.md` / `RESULTS.md` / `raw/*` |
| 脚本/测试 | `scripts/run_phase1b1_2.py`、`tests/test_phase1b1_2.py` | 复现脚本与 2 个新增测试 |

**注意**：以上是"提交中声称的变更"与"文件确实被改动"的核验，**不是**对本轮重新运行实验的核验。cap=50 的正向/负向真实证明结果来自 `experiments/phase1b1_2/raw/` 的已落盘证据与本轮之前的报告，本阶段不重新运行证明。

### 未提交工作区的性质（命令核验）

`git diff halo2/src/main.rs`：+56 / -16，**全部是计时边界与字段重命名**，例如 `prove_ms` → `create_proof_ms`，新增 `witness_generation_ms` / `params_generation_ms` / `vk_generation_ms` / `pk_generation_ms` / `setup_inner_ms` / `keygen_vk_attempts` / `collector_allowlist_lookup_ms` / `signature_verification_ms` / `verify_proof_ms`，并保留 `pure_verify_ms`、`sig_verify_ms` 作为向后兼容别名。

**核验结论**：未提交改动不改变电路约束、不改变公开输入、不改变谓词语义，属于 Phase 1B.1.3 的成本口径精化。`experiments/phase1b1_3/` 中的 `VK_DIGEST_AUDIT.md` 仍含"实测结论待运行后填入"的未完成段落（第 51–53 行），因此该目录尚不构成完整证据闭环。

---

## 4. 决策门中尚未闭合的条件（文档原文核验）

`docs/DECISION_GATE.md` 最终裁决（第 66–75 行）：**CONDITIONAL HOLD**——Phase 1B.1 技术协议 PASS，研究/项目 GO 未成立，不进入更大规模实验，不宣布论文立项。

停止条件逐条状态（第 39–47 行）：

| # | 停止条件 | 状态 | 未闭合的具体内容 |
| --- | --- | --- | --- |
| 1 | 无法合理定义完整 Agent 会话的信息流依赖边 | **HOLD** | 语义转换、隐式因果、跨会话记忆传播未覆盖（NeuroTaint 指出） |
| 2 | 图的来源完整性没有可接受的信任机制 | **HOLD** | 可信采集器 + Ed25519 签 `C` 是协议内信任锚；ZKP 不减少该信任，漏边反例 D 仍成立 |
| 3 | 只是已有通用图谓词直接套用，无法论证新增安全价值 | **触发倾向加强** | Distributed Sentinel §4.8.1 覆盖"隐藏图 + Groth16 + 外部公开策略谓词"；Cheesecloth 覆盖 ZK-IFC；zk-MCP 覆盖 ZK 通信审计。当前仅剩组合差异，未证明新的可证性质 |
| 4 | 约束规模在目标规模下不可接受 | **HOLD（强成本警示）** | 固定 crossbar 使规模高于基线；cap=200 setup 约 477 s、prove 162–177 s、峰值 20–22 GB |
| 5 | 普通签名与可信采集器已满足目标，ZKP 不值得其成本 | **HOLD（倾向触发）** | 未建立"不能给验证者看图"的硬需求，成本远高于明文检查与签名基线 |

另有两项接口/证据缺口（同文档核验）：

- 第 36–37 行：`halo2_proofs 0.4` 无 VK 序列化 API；验证者重建固定模板 VK，字面要求"verifier 不得调用 keygen_vk"**未满足**。
- 第 106–111 行（1B.1.2 复核诚实边界）：F1–F13 不构成形式化安全证明；修复后反例被拒 ≠ soundness 已证；`prove` 仍重新生成 keygen；只跑 cap=50。

**与本阶段相关的核心结论**：停止条件 3 与 5 的"倾向触发/未闭合"正是 Phase 1C 必须回答的问题——不是"再修电路"，而是"新的关系定义是否超出已有 Trace-IFC 图谓词，且是否值得用 Halo2 实现"。

---

## 5. 基线核对的边界声明

已核验：
- 远端三个分支的真实 HEAD；本地 HEAD、分支、工作区状态；`1d44e4b` 与 `d3a14f3` 的树/父/信息一致性与元数据差异；最近提交的文件清单；决策门的未闭合条件原文。

未核验 / 明确不声称：
- `[待验证]` 本轮未重新运行任何证明、MockProver 或 pytest；所有实验数值来自仓库已落盘文档。
- `[待验证]` 未确认 GitHub 上 API 提交的具体生成机制，只确认元数据差异。
- 未改动任何被冻结内容；未创建分支、未提交、未推送。
- 结论只针对本仓库当前提案，不外推为 Agent IFC、ZK 审计或整个研究方向的总体裁决。
