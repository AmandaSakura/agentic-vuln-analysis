# M0 3b 固定前 15 条选样审核

本审核只使用已预登记并归档的 `ordered_first15.json` 和已提交的 23 个仓库 URL 排除记录。固定发布时间降序及并列顺序不变，共检查 15 条，不检索第 16 条，不读取 protected held-out 输入或标签。所有结果是 development，`claim_eligible=false`，真实模型请求为 0。

标准 4 按受影响路径严格解释：公告描述的路径须实际使用 Python `shell=True`、`os.system`、`os.popen` 或显式 `bash -c`。不能因为额外假想配置可以选择任意解释器，就把任意 argv 执行器纳入。若采用更宽解释，Chainlit 和 Glances 的任意程序配置都可能改变资格；本轮不采用该解释。这些排除不表示漏洞不存在，也不依据当前 detector 或 witness 是否容易运行。

15 条均为 Reviewed、PyPI、CWE-78/77，所列仓库均不属于已冻结的 23 个 URL。下表保留逐条决定；同仓库、撤回的重复公告也占用原顺序和检查上限。

| 顺序 | Primary advisory | 决定及标准理由 |
| --- | --- | --- |
| 1 | [Chainlit / GHSA-w3fx-mc44-mf6j](https://github.com/advisories/GHSA-w3fx-mc44-mf6j) | 初选后源码核验不合标准 4。`validate_mcp_command` 返回 argv，`connect_mcp` 交给 MCP stdio transport；公告路径由 native `npx -c` 解释命令。`allowed_executables=None` 时任选 bash 是额外部署配置，不能改变严格路径标准。明确修复提交保留。 |
| 2 | [MONAI / GHSA-rghg-q7wp-9767](https://github.com/advisories/GHSA-rghg-q7wp-9767) | 排除：只有 PR 8885 和版本 1.6.0，没有明确修复提交。未查询 PR API。GPU/训练环境并未被推断为新的排除理由。 |
| 3 | [Glances / GHSA-59fj-m2j6-hcxh](https://github.com/advisories/GHSA-59fj-m2j6-hcxh) | 初选后源码核验不合标准 4。修复父提交的 `secure.py` 自行拆分 `&&`、pipe 和重定向，两个进程调用均为 `Popen(argv, shell=False)`。 |
| 4 | [Glances / GHSA-73wf-9vmv-5pv9](https://github.com/advisories/GHSA-73wf-9vmv-5pv9) | 排除标准 4。该修复父提交的 `secure.py` 与顺序 3 完全同摘要；嵌套 Mustache 值进入上述自定义解析器。 |
| 5 | [Glances / GHSA-qcpp-8x79-hhp3](https://github.com/advisories/GHSA-qcpp-8x79-hhp3) | 排除标准 4。公告明确写出 `Popen(shell=False)`；该修复父提交同样有两个 argv 调用。跨字段命令构造漏洞保留为真实公告事实，不改称安全。 |
| 6 | [GitPython duplicate / GHSA-cw2r-r7mw-j3hc](https://github.com/advisories/GHSA-cw2r-r7mw-j3hc) | 撤回重复项，指向顺序 13；无明确修复提交，native Git 选项与 helper 执行也不符合标准 4。 |
| 7 | [GitPython duplicate / GHSA-6r2r-ww24-7h52](https://github.com/advisories/GHSA-6r2r-ww24-7h52) | 撤回重复项，指向顺序 12；无明确修复提交，native Git 长选项解释不符合标准 4。 |
| 8 | [GitPython duplicate / GHSA-4vpg-pfj8-m33q](https://github.com/advisories/GHSA-4vpg-pfj8-m33q) | 撤回重复项，指向顺序 11；无明确修复提交，native Git argv/文件操作不符合标准 4。 |
| 9 | [GitPython / GHSA-r9mr-m37c-5fr3](https://github.com/advisories/GHSA-r9mr-m37c-5fr3) | 排除标准 4。Python 构造 Git argv，native Git 解释 `--upload-pack` 并启动 helper，不是 Python shell 消费点。 |
| 10 | [GitPython / GHSA-6p8h-3wgx-97gf](https://github.com/advisories/GHSA-6p8h-3wgx-97gf) | 排除标准 4。native Git 复制并执行模板目录中的 checkout hooks。 |
| 11 | [GitPython / GHSA-956x-8gvw-wg5v](https://github.com/advisories/GHSA-956x-8gvw-wg5v) | 排除标准 4。native Git 解释 `--exec`、`--upload-pack`、`--output`；Python argv 创建本身不能满足 shell 消费标准。 |
| 12 | [GitPython / GHSA-2f96-g7mh-g2hx](https://github.com/advisories/GHSA-2f96-g7mh-g2hx) | 排除标准 4。native Git 接受长选项缩写并执行 helper。 |
| 13 | [GitPython / GHSA-v396-v7q4-x2qj](https://github.com/advisories/GHSA-v396-v7q4-x2qj) | 无明确修复提交，仅 PR 2162/版本 3.1.51；native Git 短选项/helper 路径也不合标准 4。 |
| 14 | [Pillow / GHSA-4x4j-2g7c-83w6](https://github.com/advisories/GHSA-4x4j-2g7c-83w6) | **暂定候选**：公告明确指出 `WindowsViewer.show_file` 的 `subprocess.Popen(command, shell=True)`，提供三个修复提交。已核对首个适用修复、父版本及指定入口；两份精确源码在受限 Python 3.12 空站点环境导入均因缺少目标 `_imaging` 失败。源码标准合格，当前环境标准 6 未满足；保留为唯一暂定候选，不把失败当作安全结论。 |
| 15 | [LangBot / GHSA-3pvh-63gf-j9mw](https://github.com/advisories/GHSA-3pvh-63gf-j9mw) | 排除：无明确修复提交或首个修复版本。MCP 任意程序启动也不自行证明存在符合标准 4 的 Python shell 路径。 |

Chainlit 与 Glances 的初选、克隆和失败核验均保留。Chainlit 的修复 `0565fd0eccb915fce159929598b053ed79f6e0c9` 父版本中，`backend/chainlit/mcp.py:72–77` 仅筛选 executable，`server.py:1393,1442–1446` 向 stdio 传递 command/args；`validate_mcp_command` 本身不创建进程，不能被单独当作 sink。`connect_mcp` 是 async 路由并需真实 in-memory session；没有仅因当前工具不支持 async 就排除。

Glances 三个修复父版本 `5c07c0d96423e9d5b9de71dd92e3717c66f504bd^`、`ea4cf2f54f0d961e24aa0b24fff9584bab39db93^`、`9c280eae5419da680827024b60f6265956e31994^` 的 `secure.py` 原文 SHA256 均为 `2f3affe647ad6a3171e4c21f2cef760f2732dc8aa195e01ce8105ec70d1a2d79`，两处 `shell=False`、零处 `shell=True`。这项排除来自指定消费语义，不来自运行难易或检测结果。

机器记录见 [审核 JSON](2026-09-30-phase3b-selection-audit.json)。Git source read 的命令、仓库 URL、UTC 时间、返回内容 SHA256 和原文均归档到 `artifacts/remaining_work_20260929/phase3b_selection/criterion_source_reads/`；原始 primary API 响应继续保留在上一层，未另取公告或 PR 数据。promisor Git 可能为指定仓库文件 lazy-fetch，其范围仅限已初选仓库。

Pillow 源码核验现已通过标准 4。按公告提交顺序，首个适用的修复为 `8404ea5fe5df40fc34aa1e51403dd6fce0778b8a`，父版本为 `87e788339e8746e7ceb8e901df9b0c7fda55e975`；修复直接移除 `WindowsViewer.show_file` 的 `Popen(shell=True)`，改为条件 `os.startfile` 和独立 Python argv 清理。另两个提交分别拒绝双引号和处理百分号扩展，不替代这个进程 sink 修复。精确 detached worktrees 已建立为 `phase3b_sources/pillow_a`、`pillow_b`，没有修改入口或平台常量。

两份源码版本均为 `12.3.0.dev0`。`ImageShow` 导入 `Image`，后者导入 native `_imaging` 并严格检查 core 的版本与该源码版本相同。PyPI 对准确 dev 版本返回 404；稳定版 12.3.0 有 cp312 manylinux wheel，但其 native 版本不能冒充这个源码版本。因此需真实 source build/import 核验，不能通过修改版本检查解决。build metadata 要求 `pybind11`、`setuptools>=77` 和 native jpeg/zlib。四个允许的 PyPI metadata GET 的 URL、UTC 时间、原文及 SHA256 已保存到 `pypi_metadata/network_receipts.json`，尚未下载或安装 package。

实际 PREPARATION 导入预检已在两份精确 detached worktree 上完成：使用独立的、无 pip 且空 `site-packages` 的 Python 3.12.12 venv，通过通用 `witness_import_worker.py` 以 `-I -S`、原始四个身份匹配的只读叶文件授权、`heavy_target` 资源上限、网络/执行隔离及全新写入禁止，分别直接导入 `PIL.ImageShow`，`check_kernel=false`。两次 worker 都正常写出结果，但 `ok=false`、`target_import_ready=false`，错误均为从各自 checkout 的 `PIL` 无法导入 `_imaging`。命令、UTC 时间、配置、原始结果、源码摘要和授权身份检查见 `artifacts/remaining_work_20260929/phase3b_selection/pillow_import_precheck_20260930/precheck-receipts.json`。这是准备阶段容量检查，未导入 witness kernel、未运行候选调用，不构成完整 K3 接纳或漏洞判断；无模型/API 请求、包下载或安装、target native build、版本修改或借用稳定版二进制。

目标源码版本 `12.3.0.dev0` 的 PyPI wheel 未发布；现有 K3 准备能力只锁定元数据与环境，不构建目标 native 扩展。因此当前无法满足标准 6 的精确源码可导入环境。这个限制是**本轮能力缺口**，不能外推成 Pillow 无法从源码构建。

Linux 的实际运行限制单独保留：父版本无默认值地读取 `subprocess.CREATE_NO_WINDOW`，该平台属性不应被补丁伪造。它不会改变源码标准 4 的结果，也不能借切换到仅生成命令字符串的 helper 绕开指定入口。后续 K3 须诚实报告 source import、环境容量和实际调用的 F4。

目前 **0 条完全合格、1 条源码合格但环境标准 6 未满足的暂定候选**。即使最终少于两条，也停止在这 15 条，不补找易运行样本。本轮不进行 3b 真实模型运行，也不能恢复阶段 2 失败后的 G-A。严格路径解释是在 Chainlit/Glances 初选源码核验后、Pillow 环境准备前一致确认；宽解释的敏感性已保留，未用于改变样本顺序。
