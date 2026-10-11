# cv-agent 技术报告源码（2026-10-01）

[阅读 PDF](../cv_agent_technical_report_2026-10-01.pdf)，或打开 [LaTeX 主文件](main.tex)。本版记录 `4dba622` 基线加已验收、尚未提交的修复工作树，包含当前静态产品、保留研究流程、语义与身份边界、数值分析、伪代码、完整验收矩阵和前瞻评价协议。

数值来自既有回执；报告工作没有新增项目模型 API 实验或目标执行。历史 G-A 保持 NO，GP2 未启用，GP3/GP4 未测量。旧版报告与用户设计审查 PDF 保留。

源码包含：

- `sections/`：分节正文与附录。
- `figures/`：九张数值图的 PGFPlots 源码与矢量 PDF；另外四幅架构/状态图内嵌于正文。
- [冻结数据](data/report_data.json)：数值、分母、源码摘要与 27 份输入文件的 SHA-256。
- [独立事实核验记录](data/claim_verification.json)：fresh-context 核对与已落实的修订。
- [参考资料](references.bib)：经原始 DOI 元数据核实的外部论文及项目内来源。
- [构建脚本](scripts/build.py)、[数值图脚本](scripts/plot_figures.py) 和 [数据收集脚本](scripts/collect_data.py)。

从项目根目录运行：

```bash
python3 docs/reports/cv_agent_technical_report_2026-10-01/scripts/build.py
```

构建需要已安装的 XeLaTeX、BibTeX、CTeX、TikZ/PGFPlots、tcolorbox、Source Han Serif SC、Noto Sans SC 与 TeX Gyre 字体。脚本禁用 shell escape，不安装依赖、不运行测试或模型；构建日志位于 `artifacts/technical_report_20261001/build/`，PDF 写入 `docs/reports/`。

`plot_figures.py` 根据冻结 JSON 重建图，不新增实验。`collect_data.py` 读取当前源码和既有验收记录，测试数量来自已归档 collect-only 日志；重收数据需要同时复核其时态及正文结论。使用方法见 [产品指南](../../reference/PRODUCT_REVIEW.md)，逐项结果见 [核查记录](../../../audit/design_review_20260930/verification.md)。

历史原始日志、运行包和发行包不随 Git 提交。干净 checkout 可用保留的冻结数据和图形重建 PDF；重新采集数据或复核历史验收需要对应的本地原始产物。

版式参考 [OneReason Technical Report（arXiv 2606.06260v1）](https://arxiv.org/abs/2606.06260v1) 的单栏正文、首页总览、紧凑摘要、图表与附录组织；正文、图形和数值均来自本项目。
