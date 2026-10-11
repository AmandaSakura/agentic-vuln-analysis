# CV-AGENT：离线产品恢复发行物（2026-10-01）

这份安装包冻结了本轮实际源码，包括原先未提交的修复。无需原仓库、测试目录、API 密钥或 `PYTHONPATH`。

验收平台是 **Linux x86-64 / Python 3.13.5**。发行元数据要求 Python ≥3.12；其他平台与 Python 版本未做发行验收。首次准备 Python/uv 与本包之后的离线安装、离线使用分开。

## 离线安装

解压后，在本目录执行（环境目录需要尚不存在）：

```bash
sha256sum --check SHA256SUMS
uv venv --python python3.13 --no-python-downloads product-env
uv pip install --offline --no-index --require-hashes --python product-env/bin/python --find-links local-wheelhouse --find-links dist -r install-requirements.lock
uv pip check --python product-env/bin/python
product-env/bin/cv-agent --help
```

依赖是现有环境的精确版本，没有升级。由于本地 uv 缓存的语法库平台索引不一致，`local-wheelhouse` 由原有已安装文件重新封装；每个文件均核对原始 RECORD 哈希及长度，平台标签保持。这里记录的是**本地重新封装 wheel 的哈希**，并不声称它是原始上游 wheel 的容器哈希。依赖细节见 `local-wheelhouse/dependency-manifest.json`。

产品现在的急切导入需要 Pydantic 及 Tree-sitter 的 Go/Java/JavaScript/TypeScript 语法库；这不是“仅 Pydantic”安装。最终安装环境未安装 pytest、LangGraph、evaluation、baselines、研究 workflow 或模型 transport。共享工具注册器中的未启用见证/fixture 定义仍保留；默认静态产品不运行它们。

## 自有文本演示

```bash
product-env/bin/cv-agent doctor demos/case-00
product-env/bin/cv-agent review demos/case-00 --output run-00 --profile product_triage_v2 --summary-bytes 1
product-env/bin/cv-agent verify run-00
```

`case-00` 的局部 mode 性质为 SUPPORTED，`case-01` 为 REFUTED，`case-02` 为 UNKNOWN。演示文件含顶层抛错；上述成功验收表明它们没有作为目标模块导入。

读取 `run-00/result.json` 中的精确 `candidate_id` 后，可用：

```bash
product-env/bin/cv-agent view run-00 --candidate-id 精确ID --source-root demos/case-00
```

结果给出原始操作片段及 UTF-8 行列位置。源码变化会拒绝 view，完整记录缺失或损坏会拒绝 verify。verify 核对用户自有包的一致性及已登记静态生产者结果，**不认证任意外部 producer 的来源**。

默认不带 `--profile` 时，保持历史 `product_triage_v1`。v2 必须显式选择；v2 用 `--summary-bytes`，不接受含混的 `--observation-bytes`。

## 结果与边界

v2 的完整原始记录在私有本地包；1 byte 分享预算仍保留本地 SUPPORTED 与已完成分析，`share.json` 会省略该候选，并标记 NOT_VERIFIABLE。分享件不提供独立可复核的强状态。

`--summary-bytes` 只计 finding body，分享件的元数据明确豁免，因此它不是整个 JSON 文件的大小上限。完整本地存储失败或内部异常会停止后续分析，并保留已建立记录及准确的运行/保存状态。

v2 的 `review` 在设置 CPU、内存与 wall 期限的自有 worker 中运行；`verify`/`view` 的只读静态重放目前在 CLI 进程内，未复用该 bounded-review worker。它们不执行目标源码，但不能把 review 的进程资源边界直接归给它们。

上述三个演示和 36 个中性自有控制属于软件夹具验收。36 控制得到 22 个精确状态匹配、0 错误强状态、0 缺失位置；14 个已知常量经变量传递的 mode 仍 UNKNOWN，因为当前权限验证器要求调用处是字面整数。参考标签未因此改写。用户真实使用环境与人工独立产品质量均 **NOT_MEASURED**；两个外部目录的清洁安装不能替代真实用户环境验收。这不是 held-out 漏洞检出率或项目安全证明。

36 个中性源码、独立参考和原始 CLI 输出均保存在 `quality-controls/`。可在已安装环境重新核对；评分器只把选定源码复制到 CLI 输入，标签只用于分析后的计分：

```bash
product-env/bin/python quality-controls/score_quality_controls.py --cli product-env/bin/cv-agent --output quality-recheck --profile product_triage_v2
```

源码清单、wheel/source 包哈希、独立环境日志和 v1/v2 回执位于本目录。`source-consistency.json` 逐文件核对最终发行源码与冻结工作树一致。没有新模型实验、联网、第三方目标执行，研究 G-A 结论仍 NO。
