# v3 实验结果

此目录只保存论文大修后由 `experiments_v3/` 生成的结果。

规则：

- 每次运行必须在 `manifest.json` 登记运行 ID、代码版本、配置哈希、数据集哈希、模型返回标识、时间、随机种子和输出文件；
- 原始 trace、逐样本判定和聚合统计分开保存；
- API 失败、超时、限流与协议错误不得计作安全成功；
- 人工修改结果文件会使该次运行失效；
- 投稿稿中的每一个数值都必须能追溯到一个 manifest 条目。

公开仓库范围：本目录只包含四组正式证据（offline-frozen-test-v1、provenance-test-v2、real-agent-test-v2-all-providers、agentdojo-test-v4）及其过滤后的 manifest。开发、pilot、smoke、作废冻结版本与失败诊断结果不随公开仓库发布，其登记信息保留在作者归档中。
