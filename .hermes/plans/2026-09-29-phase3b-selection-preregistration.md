# M0 外部开发选样预登记

在首次联网查询之前记录。沿用 M0 §6，不建立 K8 评测集；结果全部 development、claim_eligible=false。

读取 GitHub Reviewed Advisory API，ecosystem=pip，CWE-78/CWE-77，按 published 时间降序。最多审阅前 15 条，记录每条是否符合生态、CWE、仓库排除、明确修复提交、Python 进程创建和可直接调用入口条件。排除集合复用已提交的 23 仓库 URL 记录，不读取 held-out 输入或标注。

候选仅按 advisory 提供的信息初选；先记录初选理由，再 clone 该候选验证提交、调用位置和 Python 3.12 的 hash 锁定环境。不得依据检测结果、见证成功或源码看起来容易来跳过候选。环境不满足也必须保留失败记录。顺序中前两条完全合格者入选；达到 15 条即停止检索，不能另找容易的样本。

联网范围只有 GitHub Advisory 页面/API 只读、初选仓库 clone 和 PyPI 锁定安装。记录请求 URL、响应原文、时间与 SHA256。查询工具不加载模型凭据，不发模型请求。

阶段 2 的单次 B 重跑已经失败，因此 3b 只做选样、环境准备和 developer_scripted 能力检查；本轮没有 3b 真实模型运行。
