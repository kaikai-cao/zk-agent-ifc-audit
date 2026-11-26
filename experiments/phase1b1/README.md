# Phase 1B.1 — Fixed-Circuit and Independent-Verifier Audit

基线：`a5acdc5b4bb29dd9a11c6870321834bf29b3422d`（原 Phase 1B，保留于 `main`，本分支不覆盖）。
本分支：`phase1b1-fixed-verifier`。范围仅限固定电路、独立验证、盲化承诺与计时口径；不增加递归证明、更多标签、declassification 或真实 LLM 执行。

## 1. 修复内容

### A. 固定电路形状
- `q_edge` 在全部 `edge_cap` 个 edge slot 上启用；`active` 是受约束的 witness bit（`active*(active-1)=0`）。
- inactive slot 被约束为规范编码：`(1-active)*src = (1-active)*dst = (1-active)*kind = 0`，`(1-active)*inv_delta = 0`。
- 每个 slot 都计算 `edge_hash = H<3>(EDGE+cap, src*cap+dst, kind)`，再由 `active` 在受约束选择门中选出 leaf；Poseidon 布局与 active pattern 无关。
- `S[src]` / `S[dst]` 通过**固定 one-hot crossbar** 关联：每个 `(j,i)` 行的选择位为 witness，但 `s_copy ← S_i`、block 末尾累加器 `→ s_src_j / s_dst_j / src_j / dst_j` 的 copy wiring 只由 `(j,i)` 决定，不随图内容变化。
- 节点类型由 3 位布尔分解约束，且 `b1*b2=0` 排除 6/7，限定枚举 0–5；`src,dst` 通过 crossbar 的 `Σ i·sel = index` 约束被限定在 `[0,cap)`；`kind` 为布尔。

### B. 固定 VK 与独立验证
- `setup <cap> <setup.json>`：仅用图无关 `fixed_template(cap)` 生成 params/VK/PK，分别计时。
- `prove`：用 setup 指定的固定 `k` 与固定 PK 出证明，输出 `proof.bin` + `public.json`。
- `verify`：独立进程，只接收 `setup.json`、`proof.bin`、`public.json`；不读 graph/witness 文件，不对 witness 调用 `keygen_vk`。
- `selftest`：直接比较 template / 合规图 / 违规图的 VK transcript digest，验证 VK 图无关性。
- **已知偏差（诚实记录）**：`halo2_proofs 0.4` 没有 VK/PK 序列化 API。验证者目前从公开固定模板重建 VK，并以 `vk_hash` pin 住公开参数；这不是“接收不透明序列化 VK”的理想接口。它满足“不接触图/见证”，但不满足 B.3 的字面“完全不调用 keygen_vk”。

### C. 盲化承诺
- 公开实例第 0 项由 `root_G` 改为 `C = H<3>(BLIND+cap, root_G, blind)`；`blind` 在电路内参与计算并绑定到实例。
- 采集器签名消息改为 `(C, policy_id, session_id, nonce, collector_id)`。
- 针对性测试：合规图满足电路、违规图被 MockProver 拒绝、错误签名被拒、错误 nonce 公开输入被拒、改变 blind 或图都会改变 `C`。

### D. 计时口径
- `prove_ms` = 仅 `create_proof`。
- `pure_verify_ms` = 仅 `verify_proof`（`vk_rebuild_ms` 与 `sig_verify_ms` 单独列出，均不计入验证时间）。
- setup 分别报告 `params_gen_ms` / `vk_gen_ms` / `pk_gen_ms`。

## 2. 运行

```bash
cd halo2 && cargo build --release && cd ..   # 需要 multicore 特性（否则 Params::new 极慢）
PYTHONPATH=src python scripts/run_phase1b1.py
```

产物在 `experiments/phase1b1/raw/`：`setup{cap}.json`、`selftest{cap}.json`、每 case 的 `.proof` / `.public.json` / `.verify.json` / 汇总 `.json`。
汇总表在 `experiments/phase1b1/RESULTS.md`。

## 3. 验收口径

| # | 标准 | 证据 |
| --- | --- | --- |
| 1 | 不同图共享同一固定 VK | `selftest*.json` 的 `vk_graph_independent=true`；同一 setup 可验 3 种 density |
| 2 | active pattern 不影响电路结构 | 固定 selector + 固定 Poseidon 布局 + 固定 crossbar wiring（源码） |
| 3 | 独立 verifier 不接触 witness | `verify` 子命令只读 setup/proof/public；`verifier_read_graph=false` |
| 4 | 实际验证隐藏图证明成功 | 9 个 case 的 `.verify.json` 均返回成功 |
| 5 | 非法图不能通过真实流程 | `selftest*.json` 的 `invalid_graph_rejected=true` + MockProver |
| 6 | 盲化承诺通过针对性测试 | `tests/test_phase1a.py` 新增 3 个测试；`blind_changes_commitment=true` |
| 7 | 性能指标独立、可复现、定义正确 | `RESULTS.md` 分列 setup/prove/pure verify |
| 8 | 相关工作与原文一致 | `docs/RELATED_WORK.md` 已按 §4.8.1 原文纠正；AttnNI 重分类 |

停止条件：若固定电路无法维持合理约束规模或无法建立独立验证者不接触图的协议，则暂停项目。当前结果见 `docs/DECISION_GATE.md`。
