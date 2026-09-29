# M0 3b 外部新样本：固定选样与环境上限

按 [选样预登记](2026-09-29-phase3b-selection-preregistration.md)，从 GitHub Reviewed PyPI CWE-78/77 公告按发布日期冻结前 15 条，使用既有 23 个排除仓库 URL，只对满足元数据标准的仓库核对指定修复/父提交和受影响进程路径。没有读 held-out 输入或标签内容，没有第 16 条补选，也没有根据 detector/witness 运行难易挑样。逐条决定、原始公告、克隆与源码读取凭据见 [审核报告](2026-09-30-phase3b-selection-audit.md) 及 [机器记录](2026-09-30-phase3b-selection-audit.json)。

标准 4 的严格解释是公告受影响路径的 Python `shell=True`、`os.system`、`os.popen` 或显式 `bash -c` 消费；Chainlit 与 Glances 的初选源码在该标准下失败，原初选和克隆仍保留。宽解释可能改变入选者，报告已披露这一敏感性；这些排除不是安全判决。

唯一通过源码标准的暂定候选是 [Pillow GHSA-4x4j-2g7c-83w6](https://github.com/advisories/GHSA-4x4j-2g7c-83w6)：精确父提交 `87e788339e8746e7ceb8e901df9b0c7fda55e975` 与首个适用修复 `8404ea5fe5df40fc34aa1e51403dd6fce0778b8a` 已建立独立 checkout，修复直接移除受影响 `WindowsViewer.show_file` 的 Python shell 消费点。两份源码版本都是 `12.3.0.dev0`。用 Python 3.12、源 checkout、原四个哈希绑定读取授权、原隔离和资源上限作实际导入预检时，两版均因缺少与精确源码版本相容的 `_imaging` native 扩展失败。准确 dev 版本没有可从 PyPI 直接使用的 wheel；稳定版二进制不能冒充该源码。预检命令、源码 SHA、网络元数据与完整错误见 [导入记录](/home/joker/AAA_NUS_SEM3/cv_agent/artifacts/remaining_work_20260929/phase3b_selection/pillow_import_precheck_20260930/precheck-receipts.json)。这表明当前元数据-only K3 准备能力在 native 扩展上有缺口，不证明 Pillow 不可从源码构建。

因此本轮 **0 条满足全部入选/环境标准**，没有追加 v7、没有脚本见证或真实模型请求；3b 的 API 请求数与 reported tokens 都为 **0**。没有更改平台属性、用稳定版 native 代码代替、给目标内部打桩、授予宽目录读取或选择较容易的另一入口。即使环境今后可用，当前 Linux 对 `subprocess.CREATE_NO_WINDOW` 的访问仍需单独实测，不能从公告直接推断候选调用可达或安全。

M0 阶段 2 的 B-a 已在唯一确认性重跑后失败，所以 3b 本来就只执行离线部分。本轮零合格外部对既不恢复 G-A，也不能用来估计自主迁移成功率、召回率或误报率。
