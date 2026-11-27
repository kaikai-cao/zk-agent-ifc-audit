# Phase 1B.1.3 — Independent Reproduction & Evidence Closure

本目录记录对 Phase 1B.1.2（`1d44e4b`，tree 与本地 `d3a14f3` 一致）的有限范围独立复核。

## 范围与基线

- 仓库：`kaikai-cao/zk-agent-ifc-audit`
- 指定基线：`1d44e4b4eed80cf5501fa5748d9bea57e5669148`（上一轮经 GitHub API 创建的远端 commit；tree=`dfeda001…`）
- 本地等价起点：`d3a14f34b3a2d43be2acc0122443e1382ac19892`（tree/parent 与指定基线一致；`1d44e4b` 对象不在本地，因 API 创建 commit 元数据不同）
- 新分支：`phase1b1-3-evidence-closure`
- 规模：**cap=50 only**；不跑 cap=100/200，不扩电路、不加递归、不接真实 LLM Agent。

## 目标（只读复核 + 计时校正 + 证据边界）

1. 独立复现 cap=50 的 Python 测试、三例正向真实证明、四类负向真实证明、五类采集器身份/签名测试。
2. 修正 `setup()` 计时：`Params::new` 不再重复生成；`params_gen_ms`/`vk_gen_ms`/`pk_gen_ms` 各自只含纯操作。
3. 审计 `vk_digest`（`SHA256(format!("{:?}", vk.pinned()))`）的稳定性与定位，标记为 pinned-build prototype digest。
4. 核查公开 seed / OS CSPRNG blind / meta / public input 的可重建性与泄露边界。
5. 严格区分 Graph compliance / Trace completeness / Runtime enforcement 三个命题。

## 文件索引

| 文件 | 内容 |
| --- | --- |
| `RESULTS.md` | R1–R10 验收表、修正后性能表、结论边界 |
| `VK_DIGEST_AUDIT.md` | C1 五问、C2 处理、稳定性实测 |
| `REPRODUCTION_LOG.md` | 完整复现命令、环境版本、每个进程的退出码与原始日志索引 |
| `ATTACK_CASES.md`（在 1B.1.2 目录） | 修复前后恶意 witness 差异（本阶段不重做，只引用） |
| `raw/` | 全部原始证据：`*.log`（完整 stdout/stderr/退出码）、`*.json`（结构化结果） |

## 不覆盖历史

Phase 1B / 1B.1 / 1B.1.2 的原始结果与 raw 数据全部保留未改。本阶段所有输出只写入 `experiments/phase1b1_3/`。
