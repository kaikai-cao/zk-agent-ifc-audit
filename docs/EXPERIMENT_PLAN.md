# 实验计划（Phase 0 / 1A / 1B / 基线）

## 0. 原则

- 本计划先于 Phase 1B 实测写入仓库；实测后只追加结果，不改预注册目标。
- 不把参考模型测试当作密码学安全证明。
- 不把“逻辑图合规”写成“物理/运行时无泄露”。
- 不自动进入下一阶段；每阶段结束按 `DECISION_GATE.md` 判定。

## 1. Phase 1A：参考模型与反例

输入：普通 Python 图结构，不依赖 Halo2。

必做：
1. 图/标签/节点类型/边表示；
2. 朴素 BFS/DFS High→Low-sink 可达性；
3. 前向闭包集合构造与检查；
4. 图编码与 Poseidon commitment 接口设计（同一域参数）；
5. session_id/nonce/policy_id/collector_id 绑定数据结构。

测试 A–G：
- A 无路径 → 接受；
- B 直接边 → 拒绝；
- C 多跳路径 → 拒绝；
- D 漏边伪造 clean graph → 说明漏报不可检测；
- E 错误降级标签 → 说明标签真实性不在关系内；
- F nonce/session 不匹配 → 拒绝；
- G 节点/边/标签编码不一致 → 拒绝。

额外断言：闭包判定与 BFS/DFS 在全部正例/反例上一致。

## 2. Phase 1B：Halo2 原型

前置条件：Phase 1A 全部通过（本仓库已满足）。

电路版本：
- halo2_proofs 0.4.0 / halo2_gadgets 0.6.0 / halo2_poseidon 0.2.0；
- Pallas base field，Poseidon P128Pow5T3，width 3/rate 2；
- SimpleFloorPlanner；
- 无递归；无 LLM 推理；固定图规模上限。

规模：`MAX_EVENTS = 50, 100, 200`。
密度：每规模至少三档边数（低/中/高），边数上限按 `4*n` 设计，补齐空叶。

记录指标：
1. `k`（Halo2 domain log2）与 advice/fixed/instance 列数；
2. 自定义 gate 声明数、Poseidon 置换次数、约束等价估算（说明公式与边界）；
3. witness size（字段元素数 + 近似字节数）；
4. keygen 时间、证明生成时间、验证时间（ms）；
5. 峰值工作集内存（MB，采样 `PeakWorkingSetSize`）；
6. 证明字节数（Blake2b transcript 序列化）；
7. 不同密度下的变化。

正确性测试：
- 正例完整 `keygen -> create_proof -> verify_proof` 通过；
- 错误 root/nonce/session/policy 的公开输入使验证失败；
- 违反闭包关系的图无法生成证明（witness 分配失败/约束不满足）；
- 与 Phase 1A 参考模型在相同图上判定一致。

## 3. 基线对照

三类：
1. Plaintext graph checker：验证者拿到 G，直接跑 BFS/DFS；
2. Graph commitment + signature：采集器签名 root，验证者验签并信任判定；（如要自行重算谓词则必须拿到 G）
3. Halo2 zero-knowledge graph compliance proof。

回答：
- ZKP 相对签名减少了什么信任？（验证者不再信任证明者给的图；但采集器信任不变）
- 增加了什么隐私/可验证性？（隐藏 G；第三方可独立验证谓词成立）
- 成本是多少？（证明时间、内存、证明大小、约束规模）

## 4. 统计与可重复性

- 时间指标：每规模每密度至少 1 次完整流程；报告原始数值，不做无依据平均推断；
- 随机数：证明生成用固定 RNG seed，结果可复现；
- 图生成：固定 seed，公开生成脚本；
- 私有字段：本原型不引入真实用户数据，全部合成；
- 不宣称性能优势：只报告本机实测数值与相对基线倍率，不推广到其他硬件/证明系统。

## 5. 停止与继续

任一停止条件成立 → 暂停 Halo2 扩展，写 `DECISION_GATE.md`，不自动追加工程任务。

若继续，下一步必须另立任务包，且需先解决：
- 采集器完整性是否可接受；
- 边定义是否覆盖隐式控制流/语义转换；
- 与 Cheesecloth/zk-MCP 的增量价值是否可写成非组合式新语句。
