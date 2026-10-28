# ProvBound：来源约束的隐私授权运行时

ProvBound（Provenance-Bound Privacy Authorization Runtime）是一个部署在工具调用提交边界的运行时防护原型。它把用户目标、运行时能力引用、参数来源和最小披露策略绑定为可核验的授权契约，在工具产生外部副作用之前给出 ALLOW、BLOCK 或 REVIEW 决策，并生成可复算的决策证书。

本仓库是论文《大语言模型智能体的来源约束隐私授权与可验证运行时防护》对应的实验代码与正式冻结结果。为避免破坏冻结实验的脚本哈希与复算路径，历史 Python 包名仍保留为 causalguard；该包名不再表示论文中的方案名称。

状态：研究原型，论文在审。公开结果只支持仓库内声明的威胁模型与证据边界；零攻击事件不等同于开放世界中的零风险。

## 仓库结构

- causalguard/：授权契约、能力注册表、来源图、隐私策略、决策证书与执行前钩子。
- experiments_v3/：统一工具智能体、三种模型接入、冻结数据集、AgentDojo 适配器与统计脚本。
- results_v3/：四组正式冻结结果、逐样本记录、轨迹与 manifest（仅正式证据）。
- tests/：运行时机制、集成等价性、冻结协议与结果完整性测试。
- scripts/：测试与真实智能体运行入口。
- REPRODUCIBILITY.md：环境、冻结协议、命令与失败口径。

## 正式冻结证据

results_v3/manifest.json 只登记四组可进入论文的正式结果：

| 运行 ID | 内容 |
|---|---|
| offline-frozen-test-v1 | 结构化授权消融：30 个基础场景 × 3 类变体 |
| provenance-test-v2 | 运行时绑定来源的往返一致性测试：30 场景 / 60 参数 |
| real-agent-test-v2-all-providers | DeepSeek、MiMo、SenseNova 同一工具智能体的配对实验 |
| agentdojo-test-v4 | AgentDojo v1.2.2 workspace/direct 独立留出分区 |

开发集、pilot、smoke、失败诊断与作废冻结版本不随本仓库发布；冻结配置中可能仍保留其历史 gate 路径与哈希，仅用于说明当时的冻结流程。

## 环境

论文正式运行环境为 Apple Silicon macOS、Python 3.14.5。代码要求 Python 3.10 及以上。AgentDojo 固定到提交 089ed468cf3ed0322acc66b0211f26d9d90dbf60（包版本 0.1.35），对应实验中使用的 workspace v1.2.2 基准定义。

    python3 -m venv .venv
    source .venv/bin/activate
    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt

需要调用真实模型时，只通过环境变量提供凭据：

    export DEEPSEEK_API_KEY='...'
    export MIMO_API_KEY='...'
    export SENSENOVA_API_KEY='...'

仓库不读取或提交 .env、本地虚拟环境和第三方源码检出目录。

## 快速验证

运行全部单元测试（不修改冻结的 v3 源码）：

    python scripts/run_tests.py

复核冻结结果与论文数字（无需调用模型 API）：

    python -m experiments_v3.validate_real_agent_evidence --directory results_v3/real_agent_test_v2/all_providers
    python -m experiments_v3.agentdojo_statistics --rows results_v3/agentdojo_test_v4/rows.csv --output /tmp/agentdojo-statistics.json

## 证据边界

- results_v3 中的攻击是作者构造的冻结场景，用于机制与协议验证，不用于估计实际部署中的攻击发生率。
- 三模型合并结果属于描述性分析；论文的主分析为 DeepSeek+MiMo 的攻击成功配对终点。
- AgentDojo 留出集的 Base 已无攻击成功事件，该实验只支持集成兼容与效用证据。
- 证书验证是谓词与证据一致性检查，不绑定原始契约与调用摘要；来源测试是注册表往返一致性测试，不覆盖自由文本来源推断。

## 引用

论文《大语言模型智能体的来源约束隐私授权与可验证运行时防护》（《计算机应用研究》，在审）。

## License

本仓库暂未授予开源许可证。论文发表前如需复用代码或数据，请通过 GitHub Issue 联系作者。
