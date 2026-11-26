# WP-03 分析模型 CRC 卡

基于[原有 18 类候选](../Documentation/Planning/05_测试验收与需求追溯.md#8-分析类与-crc-候选)，按 [SRS](../Documentation/Requirements/SRS_v1.0.md#4-三个细化用例)补入 LogSource 和 CollectionAttempt，并重新核对采集、分析和处置链。每行是一张 CRC 卡，类名与[分析类图](analysis-classes.puml)一致。

| 类 | 职责 | 协作者 | 需求 |
| --- | --- | --- | --- |
| User | 表示账户状态、角色与告警负责人 | Session、Alert、AuditRecord | FR-01/02/18 |
| Session | 绑定已认证账户，控制有效期和撤销 | User | FR-01/02 |
| AuditRecord | 追加操作者、对象、动作与脱敏结果，支持审计追溯 | User、CollectionAttempt、AnalysisTask、DispositionRecord | FR-20 |
| LogSource | 保存授权引用、启停、解析参数、调度计划和已提交断点 | CollectionAttempt、SourceFile | FR-03—06/14 |
| CollectionAttempt | 固定来源配置和起始断点，记录阶段、统计、诊断和失败 | LogSource、Dataset、ParseIssue、AuditRecord | FR-04—06/14 |
| SourceFile | 表示来源文件代次，提供受控原文与行位置的定位依据 | LogSource、Dataset、NormalizedEvent、ParseIssue | FR-04/06/17 |
| Dataset | 固定 ready 批次的输入、来源统计与有序事件集合 | CollectionAttempt、SourceFile、NormalizedEvent、AnalysisTask | FR-04—06/13 |
| NormalizedEvent | 提供类型化字段、UTC 时间、输入序号及不可变原始引用 | Dataset、SourceFile、RuleEngine、Evidence | FR-06/13/17 |
| ParseIssue | 保留异常行的位置及脱敏原因，支持无 ready 批次的诊断 | CollectionAttempt、SourceFile | FR-04/06 |
| Rule | 管理草稿修订、启停及发布历史入口 | RuleVersion、AuditRecord | FR-07/10/11 |
| RuleVersion | 固定发布版规范、摘要及适用的引擎语义 | Rule、RuleEngine、AnalysisTask | FR-08/10/12/13 |
| RuleEngine | 以每次运行独立状态处理有序输入，输出命中、指标或阶段错误 | NormalizedEvent、RuleVersion、WindowState、Finding | FR-08/09/13 |
| WindowState | 按规则和分组维护窗口边界、阈值周期或待消费事件 | RuleEngine | FR-13/17 |
| AnalysisTask | 保存执行快照、领取状态、阶段和结果，关联已发布或复用的告警 | Dataset、RuleVersion、RuleEngine、Finding、Alert、AuditRecord | FR-13—16/22 |
| Finding | 标识引擎命中，固定指纹、原因和有序证据 | RuleEngine、Evidence、Alert | FR-13/15/17 |
| Evidence | 按序关联命中和输入事件，支持定位原日志 | Finding、NormalizedEvent | FR-17 |
| Alert | 表示逻辑告警、当前负责人和处置状态，冻结命中证据 | Finding、AnalysisTask、User、DispositionRecord | FR-15—19 |
| DispositionRecord | 固定成功动作、原因、操作者和前后状态，与审计共同提交 | Alert、User、AuditRecord | FR-18—20 |
| NotificationConfig | 固定通知启用状态与渠道配置版本，凭据使用受控引用 | NotificationDelivery、User | FR-21 |
| NotificationDelivery | 跟踪已发布告警的通知、有限重试和终态 | Alert、NotificationConfig、AuditRecord | FR-21/22 |

## 关键协作

- UC-04 使用 LogSource 与 CollectionAttempt 固定授权、配置和断点。CollectionAttempt 最多发布一个 Dataset。只有有效事件的尝试才发布批次，全部无效的尝试仍能通过 ParseIssue 和 SourceFile 查询原文与错误。
- UC-13 由 AnalysisTask 固定输入和 RuleVersion，RuleEngine 用独立 WindowState 生成 Finding。多个任务可以复用同一 Alert，告警的 Finding 和 Evidence 保留首次发布时的解释与证据。
- UC-19 由 User 和 Session 提供认证上下文，Alert 使用对象权限、状态及版本校验写操作。成功操作同时保存 DispositionRecord 与 AuditRecord。重跑复用 Alert，保留负责人及处置历史。
