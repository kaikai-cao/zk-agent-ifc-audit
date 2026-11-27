# Phase 1B.1.3 结果：独立复核与证据边界

基线 `1d44e4b`（tree 等价本地 `d3a14f3`），分支 `phase1b1-3-evidence-closure`，cap=50 only。
本阶段只读复核 + 计时校正 + 证据边界整理；不改电路、不扩规模、不做研究 GO 判定。

## 1. R1–R10 验收表

| # | 标准 | 判定 | 证据（均在 `experiments/phase1b1_3/`） |
| --- | --- | --- | --- |
| R1 | Python 全量测试独立复现 | **PASS（以 pytest 为准）** | `raw/pytest.log`：15 passed，EXIT_CODE=0；`raw/unittest.log`：unittest discover 发现 0 例（EXIT_CODE=5，见下方口径说明） |
| R2 | cap=50 三正向真实证明与验证通过 | **PASS** | `raw/cap50_{low,mid,high}.json`：`accepted=true`、exit=0、proof 均 8096 B；`raw/verify50_*.log` |
| R3 | 四类负向真实证明层拒绝 | **PASS** | `raw/proof_layer_negatives.json`：四例 `create_proof_ok=true`（真实生成 proof，8096 B）且 `verify_accepted=false`（`verify_proof rejected`）；`raw/neg_*_{prove,verify}.log` |
| R4 | 采集器身份与签名负向复现 | **PASS** | `raw/collector_cases.json`：legit=true；forged_public_key / wrong_collector_id / wrong_nonce / wrong_signature 全部 false，分别落在 allowlist、allowlist、SNARK public input、Ed25519 四层 |
| R5 | Params/VK/PK 计时边界正确 | **PASS** | `raw/setup50.json`：`params_gen_ms=5647` + `vk_gen_ms=1399` + `pk_gen_ms=2729` = 9775 ≈ `setup_inner_ms=9776`；`keygen_vk_attempts=1`，无重复 probe Params |
| R6 | prove/verify 纯操作与 wall time 分离 | **PASS** | `raw/cap50_*.json`：prove 分列 witness/params/vk/pk/create_proof + wall；verify 分列 params_verify/allowlist/signature/vk_rebuild/verify_proof + wall |
| R7 | VK digest 稳定性与限制有证据 | **PASS** | `raw/vk_digest_stability.json`：三次独立 setup 的 digest 相同（distinct=1）；`VK_DIGEST_AUDIT.md` 明确标记为 pinned-build prototype digest |
| R8 | seed/blind/meta/public 可重建性与泄露边界核查 | **PASS（核查完成）** | `REPRODUCTION_LOG.md` + `COMMITMENT_AND_PROVENANCE.md` §9：合成图 seed 可重建；blind 由 OS CSPRNG；public 无 blind/图规模元数据 |
| R9 | 三个命题严格区分 | **PASS** | `SECURITY_MODEL.md` §7：Graph compliance / Trace completeness / Runtime enforcement 三分，不互相推广 |
| R10 | 全部原始日志与数据保留 | **PASS** | `raw/` 共 25 个 `*.log`（完整 command/exit_code/stdout/stderr）+ 全部 proof/public/meta/verify/vk 稳定性 json；历史阶段目录未改 |

### R1 口径说明（不得改写为"unittest 通过"）

仓库测试全部是 pytest 风格函数（`def test_*`），没有 `unittest.TestCase`。`python -m unittest discover -s tests -v` 实际 `Ran 0 tests`，退出码 5；这是"未发现测试"，不是"通过"。Python 全量测试的真实执行依据是 `pytest`：collected 15 items、15 passed、退出码 0。两者完整输出与退出码均留档。

## 2. 修正后的性能表（cap=50，单次原始毫秒值，不取平均、不删异常值）

### Setup（一次性，`raw/setup50.json`）

| 指标 | 值 |
| --- | ---: |
| k / circuit_version | 15 / phase1b1-2-soundness-v1 |
| params_gen_ms | 5647 |
| vk_gen_ms | 1399 |
| pk_gen_ms | 2729 |
| setup_inner_ms（三项 + 少量开销） | 9776 |
| setup_wall_ms（含进程启动） | 9894 |
| setup_peak_mb | 789.93 |
| keygen_vk_attempts | 1 |
| vk_digest | `09a7d83d3a397ec5cece1afb4729738b7f419a8cb995959dcea597a8375afa9f` |

计时边界修正：旧 `setup()` 生成 Params 两次，第二次落在 `vk_gen_ms` 窗口内；新版删除 probe Params，成功路径 Params 仅生成一次，`params_gen_ms`/`vk_gen_ms`/`pk_gen_ms` 各自只含对应纯操作。三项之和 9775 与 `setup_inner_ms` 9776 相符（1 ms 四舍五入），边界自洽。

### Prove / Verify（`raw/cap50_{low,mid,high}.json`）

| density | active | proof_B | witness_ms | prove: params/vk/pk_ms | create_proof_ms | prove_wall_ms | prove_peak_MB | verify: params/rebuild/sig/allow_ms | verify_proof_ms | verify_wall_ms | verify_peak_MB | accepted |
| --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | --- |
| low | 25 | 8096 | 5 | 8164 / 2257 / 3141 | 7095 | 20735 | 2258.23 | 10317 / 2285 / 0 / 0 | 55 | 12761 | 150.52 | true |
| mid | 50 | 8096 | 12 | 10811 / 2191 / 3180 | 7024 | 23311 | 2259.82 | 10862 / 2216 / 0 / 0 | 49 | 13226 | 150.52 | true |
| high | 100 | 8096 | 15 | 12020 / 2097 / 3093 | 7335 | 24638 | 2259.04 | 11024 / 2210 / 0 / 0 | 48 | 13386 | 150.83 | true |

对账（以 low 为例）：prove 纯操作之和 5+8164+2257+3141+7095 = 20662 ms ≈ `prove_wall_ms` 20735（差 73 ms 为进程启动/落盘）；verify 纯操作之和 10317+2285+0+0+55 = 12657 ms ≈ `verify_wall_ms` 12761（差 104 ms）。纯操作与端到端 wall 可逐项对上，不混用。

必须如实报告：
- **prove 进程每次都重新生成 Params/VK/PK**（`keygen_reused_from_setup=false`），setup 结果未被 prove 复用；`create_proof_ms` 只是纯证明时间，不是 prove 总成本。
- `verify_proof_ms` 只含 `verify_proof`；`verify_wall_ms` 含 Params 生成（约 10 s）、VK 重建（约 2.2 s）、验签与文件读取。不要把 48–55 ms 称为端到端验证时间。
- `params_generation_ms` 在 8.1–12.0 s 波动是本机负载导致的真实波动，未删除异常值。
- 与 1B.1.2 报告的 setup（5.4/6.6/2.3 s）数值不同，是旧口径把第二次 Params 计入 vk、且 Params 生成受机器负载影响；本阶段数值以修正后计时为准，旧数据保持原样未覆盖。

## 3. 真实证明层负向结果

四例恶意 witness（illegal_ifc / node_tl_mismatch / edge_idx_mismatch / crossbar_prev_dst）均**真实执行 `create_proof` 成功并生成 8096 B proof**，随后 `verify_proof` 全部拒绝（`verify_accepted=false`，reason=`verify_proof rejected`）。证据：`raw/proof_layer_negatives.json`、`raw/neg_*_prove.log`、`raw/neg_*_verify.log`。这不是 MockProver 结果。

## 4. 采集器身份/签名分层结果

| case | accepted | reason | 拒绝层 |
| --- | --- | --- | --- |
| legit_allowlist_collector | true | — | — |
| forged_public_key | false | collector signature rejected | allowlist（忽略 public 自称 key）+ Ed25519 |
| wrong_collector_id | false | collector_id not in trusted allowlist | allowlist 身份 |
| wrong_nonce | false | verify_proof rejected | SNARK public input（已用正确私钥重签，排除了验签层） |
| wrong_signature | false | collector signature rejected | Ed25519 签名 |

三层（allowlist 身份检查 / Ed25519 验签 / SNARK public input 验证）分别被独立触发，未混为一谈。

## 5. VK digest 结论

`vk_digest = SHA256(format!("{:?}", vk.pinned()))`。三次独立 `setup(50)` 得到相同 digest（见第 1 节 R7、`VK_DIGEST_AUDIT.md`）：同一构建内可复现。但 Rust `Debug` 文本不是规范化序列化，跨编译器/依赖版本稳定性**未建立**；正式标记为 **pinned-build prototype digest**。`vk_hash` 只用了 `CIRCUIT_VERSION.len()`，等长改版本字符串不会改变它，不是可靠版本指纹。verifier 仍需 `k` + 固定模板重建 VK，不是 opaque VK 反序列化。

## 6. 隐私与元数据泄露结论

- 合成图可由公开 seed + 公开代码重建（`SEEDS`/`make_compliant_witness`）；blind 由 OS CSPRNG 在证明进程内采样，不经 seed，不写入 public.json / 日志。
- public.json 仅含 commitment、policy_id、session_id、nonce、collector_id、signature、k、proof_bytes 等；density/active_edges 只在私有 meta.json（本阶段 meta 留在 raw 供复核，正式部署应不入公开渠道）。
- 仍公开并可能泄漏的元数据：cap/k、策略 ID、会话 ID、nonce、采集器 ID、proof 大小与计时，以及"存在一次合规判定"这一事实。
- 随机 blind + Poseidon 只说明随机化接口按预期工作；**不声称已形式化证明 commitment hiding**，不把公开合成数据实验说成真实 Agent 会话隐私实验。

## 7. 安全模型边界

严格区分三命题（详见 `SECURITY_MODEL.md` §7）：
1. **Graph compliance**：给定图满足 Trace-IFC 谓词——本原型证明的是这一项。
2. **Trace completeness/authenticity**：图完整真实反映 Agent 执行——未证明，依赖可信 collector，漏边/错标反例仍成立。
3. **Runtime enforcement**：Agent 实际执行被强制限制在策略内——未证明，需外部收据/TEE，不继承本项目结论。

不得把 (1) 的验证通过推广成 (2) 或 (3)。

## 8. 阻断项与裁决

阻断项（未闭合，均属信任/范围边界，不是本轮失败）：采集器完整性与标签真实性、策略版本权威、运行时执行真实性、commitment hiding 形式化证明、跨版本 VK 序列化、新可证性质相对现有工作的差异。

**裁决：CONDITIONAL HOLD 不变。** 本阶段只说明 cap=50 原型的工程证据经独立复核、计时与隐私/安全边界表述更可信；不构成研究 GO、论文创新、形式化安全证明，也不结束 HOLD 状态。建议按任务包要求冻结工程原型，等待集中审阅与下一轮决策。
