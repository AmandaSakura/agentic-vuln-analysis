# 配置导航

根目录不再堆放 JSON。文件按责任归类，不根据版本号或 pilot 字样认定无用。

## 当前 10／30 项入口

两个 shell 命令不变；现在实际读取下列声明：

| 配置 | 职责 |
| --- | --- |
| [datasets/advisory_pairs_v4.json](datasets/advisory_pairs_v4.json) | 共用的三个配对、六个快照、来源、输入和场景条件 |
| [profiles/advisory_gate_v4.json](profiles/advisory_gate_v4.json) | 门禁 10 项选择、系统、预算和检索策略 |
| [profiles/advisory_matrix_v4.json](profiles/advisory_matrix_v4.json) | 矩阵 30 项、预算、策略和预声明弃权 |
| [models/micro_benchmark_gemini_native.json](models/micro_benchmark_gemini_native.json) | 两个 profile 引用的原模型默认配置 |

`load_advisory_config` 合成原有的类型化实验契约，字段不能交叉覆盖；缺失或无效配置直接报错，不回退到历史版本。完整解析配置仍写入运行元数据。原 v4 独立配置在 `history/`，用于迁移等价检查，不再作为当前门禁、矩阵或 v4 审计的输入。

模型文件沿用历史名称和默认值；实际模型还受既有运行时提供商及环境设置影响，不能只看文件名认定使用 DeepSeek 或 Gemini。凭据仍放在 Git 忽略的环境文件中，本目录不存密钥。本次只迁移路径，不切换模型。

这些样本已反复用于开发，`claim_eligible=false` 不变。目录重组不会恢复 held-out 资格。

## 其他配置的位置

| 目录 | 职责与使用者 |
| --- | --- |
| `models/` | micro 与 native 两份模型默认参数，由 runner／诊断显式引用 |
| `datasets/` | advisory 数据、development manifest、LangChain 标签及 VulnGym 各版本输入；标签与检测输入仍由各协议隔离 |
| `profiles/` | 当前 advisory 门禁／矩阵运行策略 |
| `experiments/` | development、Python/LangChain 配对、repository/NLTK pilot、smoke、检索验证矩阵等专项实验 |
| `preparation/` | v2/v3 数据划分与准备声明；仍有对应准备模块读取 |
| `diagnostics/` | 传输探针、日志检查、历史运行审计等；部分探针会真实调用模型 |
| `history/` | 原 advisory v1–v4 独立配置；供版本比较、v3 审计及旧准备程序使用 |

所有 36 份已有 JSON 均保留。只迁移位置和配置间引用；样本、参数、源码／产物路径及哈希没有变化。迁移清单与原字节哈希见 [回归清单](../tests/fixtures/config_relocation.json)，测试逆向替换声明路径后逐文件核对哈希。由于引用路径更新，部分文件的原始字节哈希会变化；历史产物中的旧哈希和路径没有重写。

`history/` 并非可以删除的垃圾，也不是写保护机制。旧 `prepare_python_heldout_pairs` 仍具有重建 v2 文件的原行为；日常运行当前门禁／矩阵不需要执行这些准备程序。不要通过重写归档来让等价性测试通过。

专项入口继续使用 `python -m cv_agent.evaluation.runners.<模块名>`，准备与审计分别在 `preparation`、`diagnostics` 包内。旧的 `configs/<文件名>.json` 根路径已退场，没有兼容副本。操作入口见 [scripts 说明](../scripts/README.md)，科学解释见 [实验指南](../docs/EXPERIMENTS.md)。
