# 复现实验与证据登记

本文件说明 ProvBound 公开实验代码与正式冻结结果的复现方式。开发、pilot、smoke 与失败诊断运行不随公开仓库发布。

## 1 环境与安全边界

所有有副作用的工具都在本地可重置沙箱中执行，不发送真实邮件、不修改真实日历、不上传真实文件、不发起真实支付。真实模型只负责在统一智能体循环中生成原生函数调用，最终安全性由调用轨迹和沙箱提交状态判定。

不得把 API 密钥写入代码、命令历史、结果或论文。运行时只从 DEEPSEEK_API_KEY、MIMO_API_KEY 和 SENSENOVA_API_KEY 环境变量读取凭据。

## 2 可用的正式证据

证据资格以 results_v3/manifest.json 为入口。本仓库包含四组正式证据：

- offline-frozen-test-v1：30 个测试基础场景，每个场景包含合法、明确攻击和证据缺失三类变体，共 90 个判定实例。
- provenance-test-v2：30 个测试场景、60 个参数的结构化运行时绑定来源往返测试。
- real-agent-test-v2-all-providers：DeepSeek、MiMo 与 SenseNova 共 360 个预定单元，359 个完成；结果同时提供分模型、DeepSeek+MiMo 合并和三模型描述性合并统计。
- agentdojo-test-v4：AgentDojo v1.2.2 workspace/direct 的独立留出分区，每种模式 140 个单元。

## 3 复现命令

外部基准固定到 AgentDojo 提交 089ed468cf3ed0322acc66b0211f26d9d90dbf60。建议从仓库根目录建立独立环境并安装固定依赖：

    python3 -m venv .venv
    .venv/bin/pip install -r requirements.txt

随后运行：

    export PYTHONPATH="$PWD"
    .venv/bin/python -m unittest discover -s tests -v
    .venv/bin/python experiments_v3/validate_dataset.py
    .venv/bin/python experiments_v3/dataset_runner.py --dataset experiments_v3/datasets/base_scenarios.jsonl --split test --output results_v3/reproduction_offline_test
    .venv/bin/python experiments_v3/provenance_benchmark.py --dataset experiments_v3/datasets/base_scenarios.jsonl --split test --output results_v3/reproduction_provenance_test/results.json
    .venv/bin/python -m experiments_v3.validate_real_agent_evidence --directory results_v3/real_agent_test_v2/all_providers
    .venv/bin/python -m experiments_v3.real_agent_statistics --rows results_v3/real_agent_test_v2/all_providers/rows.csv --primary-provider deepseek --primary-provider mimo --output results_v3/reproduction_real_agent_statistics_primary.json
    .venv/bin/python -m experiments_v3.real_agent_statistics --rows results_v3/real_agent_test_v2/all_providers/rows.csv --output results_v3/reproduction_real_agent_statistics_three_provider.json
    .venv/bin/python -m experiments_v3.agentdojo_statistics --rows results_v3/agentdojo_test_v4/rows.csv --output results_v3/reproduction_agentdojo_statistics.json

复现输出不得覆盖已登记的冻结结果。复现者应比较新输出与 manifest 中登记文件的内容哈希。

## 4 三模型统一智能体协议

协议文件为 experiments_v3/configs/real_agent_protocol_v1.json。三个提供方使用同一系统提示、工具定义、最多 10 步的原生函数调用循环、温度 0、60 s 超时和 2 次 SDK 重试；仅模型标识、官方 Base URL 与凭据环境变量不同。Base 与 Full 顺序按场景标识的 SHA-256 交叉平衡。正式实验使用 DeepSeek deepseek-v4-pro、MiMo mimo-v2.5-pro 和 SenseNova sensenova-6.7-flash-lite。

正式顺序为：每个提供方 12 个开发 smoke 单元；全部通过后运行 30 个开发场景；冻结所有实现和协议哈希后，才允许各模型在 30 个测试场景上运行一次。认证、限流、连接、超时和协议错误作为失败类保留原始行并单独报告。

## 5 AgentDojo 协议

AgentDojo 使用官方任务状态与官方效用/安全检查器。方法通过通用函数运行时的执行前钩子接入，不含攻击模板字符串、任务编号白名单或由 gold label 生成的授权。40 个 workspace 用户任务按数字 ID 模 4 划分；最终余数为 1 的 10 个任务未参与调试。

## 6 统计约定

结构化实验以基础场景而不是文本变体为独立单元。真实智能体按同一模型、场景和任务类型配对；AgentDojo 按用户任务—攻击任务组合配对。比例报告 Wilson 95% 置信区间，配对差使用 10 000 次 Bootstrap 与双侧精确 McNemar 检验。零事件必须同时报告区间上界。

三模型合并分析按描述性结果报告；论文的主分析为 DeepSeek+MiMo 的攻击成功配对终点。三模型未授权良性提交在按 provider×scenario 配对时 p=0.031，但按基础场景聚类后 p=0.125，仅作为探索性证据。

## 7 未包含的归档运行

开发集、pilot、provider smoke、失败诊断、superseded 冻结版本，以及 v4/v5 后续实验代码与结果均不随公开仓库发布。experiments_v3/configs 中部分冻结配置仍保留这些历史 gate 的路径和哈希，用于说明当时的冻结流程，但对应文件不在本仓库中。

## 8 数据与隐私

所有工具调用均发生在本地合成沙箱中；仓库内数据为作者构造的合成场景与模型轨迹，不含真实个人数据或 API 密钥。
