# E-iter 探索运行结果

源提交 `8f05292dbcbe42014f77bf8c42ca6a456b953cdc` 的四个开发格各运行一次，原始数据保存在 [运行目录](../../artifacts/witness_scenario_matrix/61ccd871658f48988e78ee038816292c)。真实调用前的新进程完整 pytest 门禁为 **2556 passed / 390.51s**。26 次实际请求的原始返回模型 ID 全是 `deepseek-flash`，均有 reported usage；没有解析失败、用量冲突或硬停。阶段限额 40 请求，累计账本由 46 请求 / 281330 tokens 增至 **72 请求 / 447812 tokens**，仍低于 210 请求 / 250 万 tokens。

四格最终都准入 **ABSTAIN / UNRESOLVED**。它们使用相同 DeepSeek Flash、E1、每格 8 步及 8192 观察单位；工具响应使用 compact，每次见证最多 1000 观察单位。这是明确提供入口和 advisory 摘要的开发探索，`claim_eligible=false`，不代表 repository-only held-out 能力。

| 格子 | 实际请求 / reported tokens | 准备 / schema 拒绝 / 物理见证 | 完整见证响应 | 人工审阅 |
| --- | ---: | ---: | ---: | --- | --- |
| hp003_a | 6 / 36234 | 2 / 0 / 1 | 968 单位，未截断，U | F3：选到 scoring_server 分支；后续搜索占用预算 |
| hp003_b | 7 / 44985 | 2 / 1 / 1 | 968 单位，未截断，U | 固定侧预期弃权；错误分支及预算只作事实记录 |
| hp004_a | 7 / 45465 | 2 / 0 / 1 | 861 单位，未截断，U | F4：临时目录不可用，候选帧之前停止 |
| hp004_b | 6 / 39798 | 2 / 0 / 1 | 861 单位，未截断，U | F4：同一临时目录障碍，候选帧之前停止 |

实际 B 输入把候选的四项数据集场景字段清空，并不提供数据集场景参考。预检四格通过；每对两个快照的初始请求逐字相同。hp003 两格的初始请求哈希 `b8cc6a56e0a924cca9c872e04387696fc1f1575bcbc6530858b072c0fff0306b` 与阶段 2 相同。数据集文件中仍有 hp003 历史场景注释，但没有送进这次 B 的候选和初始请求。保留的 advisory 摘要仍提到 MLServer；这是入口/advisory 提示下的探索，不是仅凭仓库发现。

模型共在工具参数中提出九份分类假设，原文字段、分类、理由与来源 request ID 全量见[伴随 JSON](2026-09-30-E-iter-results.json)。四个最终执行场景均声明 `model_uri` 为攻击者可控输入。hp003_a/b 各把 `enable_mlserver=false` 列为部署配置，选中 `scoring_server`；还把构造参数 `config` 的值写成**字符串** `"{}"`，而非 JSON 对象 `{}`。分类为部署配置不能弥补这个类型差异，也不能替代 MLServer 分支见证。两次 probe 在 `PyFuncBackend.serve` 的 Popen 记录 `exec uvicorn --host 127.0.0.1 --port 5000 --workers 1 mlflow.pyfunc.scoring_server.app:app`，但缺口是 `recorder_prefix_not_established`，均无对照或重放。

hp003_b 曾将未分类的外层构造参数和分类场景混用，工具 schema 拒绝并投递 434 单位错误；模型后续修正，只有一项物理场景实际执行。a 在 U 后读取一次 4446 单位的 `search_symbols`；b 在 U 后获得截断的 4076 单位 `read_span`，随后本地观察预算耗尽。这些搜索不是第二次场景执行。两条原始 `VULNERABLE/UNRESOLVED` 票提议分别来自 a、b，均被证据准入拒绝；其原文与 request ID 在伴随 JSON，最终票仍为 ABSTAIN。固定侧没有 producer CONFIRMED，即使计入错误或隐藏投递遥测，S1 也未触发。

CLI 两格（entry-00390，运行 ID 为 hp004_a/b）把 `model_uri`、host、port、timeout、workers 分类为调用者输入，数值采用字符串。工具直接调用真实 Click callback，未执行公开 CLI parser。两次物理尝试均在 MLflow TempDir 创建时抛出 `FileNotFoundError: No usable temporary directory`；候选帧、Popen、对照和重放均未出现。故人工审阅主因是 **F4 基础设施限制**，不能把 U 视为模型场景能力失败或补丁安全。自动审计的 F3（b 还有 F6）原样保存在 JSON，仅作未经人工校正的原始诊断。

四格各只有**一次**物理场景执行；没有模型驱动的第二场景尝试。离线 developer_scripted 正反控证明原预算和 compact 协议可容纳多次场景，但这次真实模型没有实际迭代。E-iter 不是 M0 B2 的再重跑，不能把提示、协议和响应投递同时变化的一次探索归因于单一预算因素，不能补救原 G-A 失败，也不支持 held-out 泛化结论。

## 逐请求 reported usage

| 顺序 | 格子 | request ID | prompt | completion | total | 原始模型 ID |
| ---: | --- | --- | ---: | ---: | ---: | --- |
| 1 | hp003_a | `6286425b7bc64e639dcbb3f969094b55` | 4712 | 139 | 4851 | `deepseek-flash` |
| 2 | hp003_a | `c388539607574ce9ae3aca729e192557` | 5474 | 154 | 5628 | `deepseek-flash` |
| 3 | hp003_a | `63fc90cedb2a4587b1b42b1aa9d7096c` | 6113 | 386 | 6499 | `deepseek-flash` |
| 4 | hp003_a | `f7c509777b92470e8382b1c825a15247` | 6845 | 111 | 6956 | `deepseek-flash` |
| 5 | hp003_a | `a928cf97be784a328693a3fea36c0d0f` | 5796 | 177 | 5973 | `deepseek-flash` |
| 6 | hp003_a | `b4d87190423d4a398ec448d06757789c` | 6157 | 170 | 6327 | `deepseek-flash` |
| 7 | hp003_b | `9a253c6f73ec4570bf8fecab871dc746` | 4712 | 139 | 4851 | `deepseek-flash` |
| 8 | hp003_b | `c7116178ce714eaa806754ccfb24111f` | 5474 | 145 | 5619 | `deepseek-flash` |
| 9 | hp003_b | `9f38c4823d4e4954920eaa905dd0f8c5` | 6104 | 469 | 6573 | `deepseek-flash` |
| 10 | hp003_b | `9741452d2e14472aaf95d54d8a7fe987` | 6687 | 385 | 7072 | `deepseek-flash` |
| 11 | hp003_b | `de132d5109f041158dc254249fbc4540` | 7425 | 107 | 7532 | `deepseek-flash` |
| 12 | hp003_b | `76266eff00ee4d5ab3ae86f14c30be5f` | 6282 | 177 | 6459 | `deepseek-flash` |
| 13 | hp003_b | `d6f7df92a4214567ae276399ab64e33e` | 6724 | 155 | 6879 | `deepseek-flash` |
| 14 | hp004_a | `fbce6c1db8744fe28fb0ac22e94c1b61` | 4897 | 132 | 5029 | `deepseek-flash` |
| 15 | hp004_a | `a7c7d821d9e04b7b86ba814bd3b6f84e` | 5529 | 139 | 5668 | `deepseek-flash` |
| 16 | hp004_a | `b173df4e574c403c8337d0ae7213c00f` | 6051 | 295 | 6346 | `deepseek-flash` |
| 17 | hp004_a | `e5189be7b97143869cb1812062048ee8` | 6636 | 121 | 6757 | `deepseek-flash` |
| 18 | hp004_a | `29884c0acd0843449d3912794666a130` | 6867 | 95 | 6962 | `deepseek-flash` |
| 19 | hp004_a | `8a0be46406cc474699c86aea1dd7bf61` | 8100 | 105 | 8205 | `deepseek-flash` |
| 20 | hp004_a | `ec5db7b28a52496ca6f964dfd85b1441` | 6304 | 194 | 6498 | `deepseek-flash` |
| 21 | hp004_b | `1c407179260c4591b4b60c1d1c71ad42` | 4897 | 122 | 5019 | `deepseek-flash` |
| 22 | hp004_b | `a6a7ca98bfae40eeb03689dc28dc94d0` | 6264 | 67 | 6331 | `deepseek-flash` |
| 23 | hp004_b | `b5187fd0e970448a889aab57757409da` | 6609 | 145 | 6754 | `deepseek-flash` |
| 24 | hp004_b | `c583c665749e47ec8022cf0a000d9e77` | 7137 | 315 | 7452 | `deepseek-flash` |
| 25 | hp004_b | `4cd344d9db284b40bdff3f3f67ecfac2` | 7748 | 133 | 7881 | `deepseek-flash` |
| 26 | hp004_b | `6d814e94b5e648649702a4207aafb15c` | 6181 | 180 | 6361 | `deepseek-flash` |

每条原始 usage 的缓存细项、服务端原始响应元数据、账本 reservation 与 usage history 均在伴随 JSON。完整 30 次工具事件、原始请求和回复保存在 [request_audit.json](../../artifacts/witness_scenario_matrix/61ccd871658f48988e78ee038816292c/request_audit.json) 与 [events.jsonl](../../artifacts/witness_scenario_matrix/61ccd871658f48988e78ee038816292c/events.jsonl)。

## 原始产物 SHA256

运行快照内的源码归档由 `metadata.json` 原有清单绑定；这里不重读受保护输入内容。下表对主要输出、四份私有见证、门禁日志及阶段结束账本逐一记录字节哈希。

| 产物 | SHA256 |
| --- | --- |
| [`metadata.json`](../../artifacts/witness_scenario_matrix/61ccd871658f48988e78ee038816292c/metadata.json) | `96ca121b3ba11c2c37d5c1d1f0b200eebab41bb82b6a05753bbd2c81f7562471` |
| [`events.jsonl`](../../artifacts/witness_scenario_matrix/61ccd871658f48988e78ee038816292c/events.jsonl) | `441fe5bfbd9ad5105c4dbf0f7fe255332a542c0510749e83e926056f612705af` |
| [`results.json`](../../artifacts/witness_scenario_matrix/61ccd871658f48988e78ee038816292c/results.json) | `5de88909c35dfcdd2f32ee833ed056cf50823fcba5fdece589af84690be36cf7` |
| [`summary.json`](../../artifacts/witness_scenario_matrix/61ccd871658f48988e78ee038816292c/summary.json) | `50cefb23005afdae9b9e54c4d66e3052d920253822cc19383d1891d7de129cc9` |
| [`usage.json`](../../artifacts/witness_scenario_matrix/61ccd871658f48988e78ee038816292c/usage.json) | `87bc73a9a80e3edc4a6b9d9cf2c95e6807508d4f5f58558bedf9352a5604b862` |
| [`request_audit.json`](../../artifacts/witness_scenario_matrix/61ccd871658f48988e78ee038816292c/request_audit.json) | `d0b7238a342fa8ff86d88f67445506ff69c3a77ed7ba827a1334406642a9ce21` |
| [hp003_a witness-result.json](../../artifacts/witness_scenario_matrix/61ccd871658f48988e78ee038816292c/shared-runtime-witness-artifact-qdpfwjv5/witness-result.json) | `0456ee1ece38bfe944ac2bce9064fd57eb52f11db71bac65c5ff7b34edf13dcf` |
| [hp003_b witness-result.json](../../artifacts/witness_scenario_matrix/61ccd871658f48988e78ee038816292c/shared-runtime-witness-artifact-xhqk17uh/witness-result.json) | `37fa0d7e121de538e0970ac6948e02ba38fec421cf1d9bea65ecc1e1acc0d16c` |
| [hp004_a witness-result.json](../../artifacts/witness_scenario_matrix/61ccd871658f48988e78ee038816292c/shared-runtime-witness-artifact-k66ymg5u/witness-result.json) | `90c9a3684dd156afa6593853ed0b6698eae2924b8bc71565fc346ffd18a73c34` |
| [hp004_b witness-result.json](../../artifacts/witness_scenario_matrix/61ccd871658f48988e78ee038816292c/shared-runtime-witness-artifact-7azynbgo/witness-result.json) | `87d41f9901f7f6badd50a9f8ed5cc416754b527156c42a199eb30e133666940b` |
| [`E_iter_live_console.log`](../../artifacts/remaining_work_20260929/E_iter_live_console.log) | `6ec8ba304d2423a8f55102dac00c2295dac907d2ed68f4f89139f725afae4223` |
| [`pytest.log`](../../artifacts/pytest_gate/d2d3653e8fdf4aeaa2cb4750602ca7ca/pytest.log) | `bf2335da2280ba7ec358689e2ebda1df6ba6bab278b9b9af04088d90f3a7bf9e` |
| [`authorization_ledger.json`](../../artifacts/remaining_work_20260929/authorization_ledger.json) | `a6c31be3824815decdf5e138e914c10fc8c4976f6376a648e880fa978dc7a3af` |
