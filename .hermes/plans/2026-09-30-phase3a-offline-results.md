# M0 3a：无场景入口与脚本容量检查

新增开发集 v6 仅追加 entry-00390 的 CLI 入口，两快照共享 MLflow 的原提交对；既有 v4/v5 内容未改。新入口 `mlflow/models/cli.py::serve@24-106` 的场景字段均为空，不向模型提供开关/文件/环境条件。修复调用链依据 v6 说明中记录的提交差异：CLI→flavor backend→PyFuncBackend.serve→MLServer get_cmd→execute；实际修复是 get_cmd 对模型 URI 的引用。CLI、backend 与标注落点 environment.py:1014 本身未改，不能把上游补丁与该行的实际执行混为一谈。

通用适配只允许真实 `click.Command` 的直接 callback；绑定精确 code、globals、装饰器 span 和文件哈希。普通函数、实例方法正例保留；替换 callback、伪造 wrapper/globals/frame、子类或来源错配均拒绝。不执行 CLI parser，不证明 parser 的输入转换或远程权限。

使用真实 Python 3.12 环境、原四个 SHA 绑定叶子准入和资源 profile，脚本显式提供完整正确部署场景与 MLmodel 文件。`artifacts/remaining_work_20260929/phase3a_cli_full_completed` 的两格都为 ABSTAIN / UNRESOLVED，缺口 `target_or_isolation_error`：MLflow 调用 TempDir，当前隔离拒绝所有文件系统写入，没有可用临时目录。没有到达实际 Popen 边界，也没有对照或重放，不能报告已验证 environment.py:1014。

每格 3 次脚本回复、1 次物理见证尝试；full 观察成本 978+3714=4692，compact 552+892=1444，均未截断。compact 产物为 `artifacts/remaining_work_20260929/eiter_cli_scripted`。这些是开发脚本检查，API 请求为零。早期中断/错误目录和日志均保留，没有覆盖成成功结果。

正确脚本未闭合，所以 M0 3a 模型请求按登记规则跳过。用户后来追加的 E-iter 明确包含此入口，其四格仍运行，但这里两格事前登记为基础设施受限；不能用它们的 U 判断模型是否会选择正确分支。未增加文件写权限、内部假对象或跳过无关进程事件。
