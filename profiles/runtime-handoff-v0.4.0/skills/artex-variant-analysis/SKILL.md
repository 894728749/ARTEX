---
name: artex-variant-analysis
description: "在已知一个具体根因后，于 ARTEX 授权源码范围寻找同类代码变体并逐项分流。"
---

# ARTEX 根因变体分析
来源方法：Trail of Bits variant-analysis，CC BY-SA 4.0，提交 82fe8226252622fa807643bdca1710901198553a。
适用：已有具体代码缺陷后进行本地源码搜索；不用于无种子的初始发现，也不是黑盒 Web 测试。

## 五步法
1. 从原 finding 提炼根因：什么检查缺失或状态关系错误，为什么产生不安全结果。
2. 建立只匹配已知实例的精确模式，并确认它确实命中。
3. 每次只放宽一个维度，例如标识符、调用点、数据类型或输出路径。
4. 阅读全部命中，记录安全近似项、排除理由和遗漏可能。
5. 按相同根因和可达边界分流候选，报告证据、反证和未决问题。
按平台可用工具查询实时 schema；本地 ripgrep、Semgrep 或 CodeQL 仅在确实安装可用时使用。
生成查询不是扫描结果；未运行的规则明确标为草案。

## 质量控制
模式零命中表示对种子理解可能错误，先修正模式再扩大搜索。
不要只搜原模块；检查共享辅助函数、相邻调用点和跨组件实现。
不要同时概括多种特征；每次一个变化才能解释噪声来源。
若超过半数候选为噪声，退回上一步收窄模式。
“相似代码”不等于同一漏洞；逐项比较根因、入口、前提、控制和敏感结果。
只有源码证据支持同一缺陷时才标为变体；不同问题分开记录。
不要把候选列表当作动态利用、影响确认或修复建议。

## 交付
记录种子 finding、搜索范围、每版模式、命中/排除项及原因。方法参考：[根因提炼](references/root-cause.md)、[搜索策略](references/searching.md)、[候选分流](references/triage.md)、[报告建议](references/reporting.md)；[变体报告模板](references/variant-report-template.md)。方法参考：[根因提炼](references/root-cause.md)、[搜索策略](references/searching.md)、[候选分流](references/triage.md)、[报告建议](references/reporting.md)；[变体报告模板](references/variant-report-template.md)。
列明实际执行的本地工具、版本和输出；未执行项单独标示。
许可证与出处：[Trail of Bits CC BY-SA 4.0](references/TRAIL-OF-BITS-LICENSE.txt)。

