"""Assemble evidence-linked audit only; never mutate product code or old reports."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
if not (OUT / "final-validation-patch2.json").is_file():
    raise SystemExit("Patch2 same-source validation is pending; preserve the current PENDING audit and do not regenerate old patch1 as final.")
ART = "artifacts/design_review_recovery_20261001/"
AUD = "audit/product_recovery_20261001/"

CATALOG = {
 "BASE": [ART+"baseline.json",ART+"baseline_full_pytest.log"],
 "FINAL": [AUD+"final-validation-patch2.json",AUD+"final-source-freeze-patch2.json",AUD+"final-harness-check-patch2.json",ART+"final_full_pytest_attempt1.log",ART+"final_full_pytest_attempt3.log"],
 "RELEASE": [AUD+"release-final-patch2/build-receipt.json",AUD+"release-final-patch2/install-acceptance.json",AUD+"release-final-patch2/install-v2-acceptance.json",AUD+"release-final-patch2/bundle-receipt.json",AUD+"release-final-patch2/extracted-bundle-acceptance-1.json",AUD+"release-final-patch2/extracted-bundle-acceptance-2.json"],
 "V06": [AUD+"v06-python-requires-rejection-patch2.json","tests/test_recovery_commit.py::test_existing_target_is_never_replaced","tests/test_product_preflight.py::test_missing_validator_does_not_disable_source_index"],
 "V2": [ART+"final_v2_controls.log","tests/test_recovery_product_v2.py::test_v2_public_static_positive_negative_unknown","tests/test_recovery_product_v2.py::test_v2_local_proof_survives_small_summary_and_share_has_no_standalone_proof","tests/test_recovery_product_v2.py::test_v2_same_line_operations_do_not_borrow_proof","tests/test_recovery_product_v2.py::test_v2_does_not_execute_shadowed_callee_and_counts_analysis_completion"],
 "FAULT": [ART+"v2_stage_failures_before.log",ART+"v2_presentation_failure_before.log",ART+"v2_stage_count_before.log",ART+"final_v2_controls.log","tests/test_recovery_v2_failures.py::test_complete_evidence_read_failure_retains_earlier_fact_without_strong_second_state","tests/test_recovery_v2_failures.py::test_unexpected_internal_failure_preserves_first_and_stops_later_tools","tests/test_recovery_v2_failures.py::test_record_quota_keeps_all_candidates_and_stops_future_producers","tests/test_recovery_v2_failures.py::test_cancellation_after_first_fact_stops_later_tools_and_preserves_denominator","tests/test_recovery_v2_failures.py::test_public_artifact_failure_has_presentation_stage_and_keeps_private_material","tests/test_recovery_v2_failures.py::test_public_copy_rejects_false_persisted_denominator_and_incomplete_verified_stage"],
 "SNAP": [ART+"snapshot_operations_receipt.json",ART+"snapshot_operations_final.log",ART+"fresh_review_before.log",ART+"fresh_review_after.log","tests/test_recovery_snapshot_operations.py::test_snapshot_is_sealed_and_discovery_never_rereads_mutated_source","tests/test_recovery_snapshot_operations.py::test_live_drift_cannot_change_a_snapshot_bound_read_view","tests/test_recovery_snapshot_operations.py::test_snapshot_accounts_invalid_encoding_read_errors_and_exclusions","tests/test_source_boundaries.py::test_source_reader_rejects_symlinked_parent_and_path_traversal"],
 "OPS": [ART+"R04_permission_receipt.json",ART+"R04_permission_before.log",ART+"R04_permission_after.log","tests/test_recovery_snapshot_operations.py::test_same_line_operations_receive_independent_exact_v2_ids","tests/test_recovery_snapshot_operations.py::test_module_function_and_decorated_spans_do_not_duplicate_operations","tests/test_recovery_snapshot_operations.py::test_nested_operations_are_distinct_even_when_they_share_a_line","tests/test_recovery_permission_operations.py::test_two_same_line_operations_receive_distinct_candidate_bound_mode_proofs","tests/test_recovery_permission_operations.py::test_original_utf8_coordinates_survive_indented_function_slice_and_encoding","tests/test_recovery_permission_operations.py::test_wrong_exact_locator_cannot_borrow_another_operation_proof"],
 "QUAL": [ART+"R06_receipt.json",ART+"R06_after.log","tests/test_recovery_local_evidence.py::test_shared_command_qualification_agrees_with_research_and_product","tests/test_recovery_local_evidence.py::test_shared_command_qualification_rejects_unsupported_controls","tests/test_product_reducer.py::test_unknown_and_unrelated_observations_cannot_erase_support","tests/test_product_reducer.py::test_local_counterfact_does_not_cancel_a_complete_supported_property","tests/test_product_contract.py::test_incomplete_or_pattern_receipt_cannot_support_property"],
 "LOCAL": [ART+"R06_receipt.json",ART+"R06_legacy_subset_control.log",ART+"R06_after.log","tests/test_recovery_local_evidence.py::test_full_local_conflict_survives_only_one_model_delivery","tests/test_recovery_local_evidence.py::test_unverifiable_material_file_blocks_one_sided_strong_projection","tests/test_recovery_local_evidence.py::test_missing_expected_descriptor_is_a_material_inventory_gap","tests/test_recovery_local_evidence.py::test_aliases_and_duplicate_descriptors_preserve_one_original_producer","tests/test_recovery_local_evidence.py::test_same_producer_cannot_change_original_payload_or_context","tests/test_recovery_local_evidence.py::test_record_write_failure_returns_no_descriptor_and_retains_inventory_gap"],
 "COPY": [AUD+"model-copy-graph-acceptance.json",AUD+"r08-before.log",AUD+"r08-final-copy.log",AUD+"r08-alias-after.log","tests/test_recovery_model_copy.py::test_candidate_copy_rejects_invalid_updates_like_construction","tests/test_recovery_model_copy.py::test_product_copy_revalidates_subject_cross_fields_and_contract_version","tests/test_recovery_model_copy.py::test_valid_public_copy_roundtrips_and_seals_nested_containers","tests/test_recovery_model_copy.py::test_result_copy_rejects_external_derived_counts_and_unregistered_schema"],
 "VIEW": [ART+"snapshot_operations_receipt.json","tests/test_recovery_snapshot_operations.py::test_actual_helper_grant_changes_next_tool_input_without_stale_result_cache","tests/test_product_context.py::test_non_granted_source_is_absent_from_analysis_paths","tests/test_product_delivery.py::test_cached_redelivery_is_billed_but_has_one_original_producer"],
 "NAV": [AUD+"release-final-patch2/install-v2-acceptance.json","tests/test_recovery_product_v2.py::test_v2_verify_rejects_missing_record_and_local_view_rejects_source_drift","tests/test_application_smoke.py::test_public_output_omits_secret_source_and_fake_proof_strings","tests/test_application_smoke.py::test_public_context_reason_redacts_fake_secrets"],
 "DISPLAY": [AUD+"display-invariance-patch2.json",AUD+"display-invariance-patch2.log"],
 "COMMIT": [ART+"R11_receipt.json",ART+"R11_before.log",ART+"R11_after.log","tests/test_recovery_commit.py::test_raced_empty_output_is_not_replaced","tests/test_recovery_commit.py::test_target_creation_at_commit_boundary_is_rejected","tests/test_recovery_commit.py::test_sync_failure_before_commit_never_publishes_output","tests/test_recovery_commit.py::test_final_parent_sync_error_explicitly_reports_publication","tests/test_recovery_commit.py::test_v1_completion_failure_does_not_invalidate_committed_result"],
 "VERIFY": [AUD+"release-final-patch2/install-v2-acceptance.json","tests/test_recovery_packaged_syntax.py::test_packaged_syntax_is_reparsed_from_bytes_with_binding_metadata","tests/test_recovery_packaged_syntax.py::test_packaged_operation_inventory_is_derived_from_complete_sealed_module","tests/test_recovery_local_evidence.py::test_descriptor_mismatch_is_rejected","tests/test_recovery_local_evidence.py::test_subject_or_context_from_another_analysis_cannot_supply_proof"],
 "RESOURCE": [ART+"resource_cache_receipt.json",ART+"resource_boundary_final.log","tests/test_recovery_resource_boundary.py::test_real_owned_worker_memory_limit_reports_resource_failure","tests/test_recovery_resource_boundary.py::test_real_owned_worker_cpu_limit_terminates_static_work","tests/test_recovery_resource_boundary.py::test_timeout_kills_only_owned_worker_and_retains_unknown_denominators","tests/test_recovery_resource_boundary.py::test_cancellation_kills_and_waits_for_owned_worker","tests/test_recovery_resource_boundary.py::test_worker_environment_drops_credentials_without_reading_their_values"],
 "SCALE": [AUD+"scale_runs/20261001T020648Z-30d93469/measurement.json",AUD+"scale_runs/20261001T020648Z-30d93469/final_source_receipt.json",AUD+"scale_runs/20261001T020648Z-30d93469/workload-correction.json"],
 "DIGEST": [ART+"resource_cache_receipt.json","tests/test_recovery_frozen_index_digest.py::test_cached_digest_serializes_once_for_many_candidate_consumers","tests/test_recovery_frozen_index_digest.py::test_mutable_legacy_index_edits_recompute_digest","tests/test_recovery_frozen_index_digest.py::test_arbitrary_index_digest_attribute_is_never_trusted"],
 "DEEPCOPY": [AUD+"copy_runs/20261001T020648Z-c1a8fe7f/measurement.json",AUD+"copy_runs/20261001T020648Z-c1a8fe7f/instrumentation_receipt.json",AUD+"copy_runs/20261001T020648Z-c1a8fe7f/workload-correction.json"],
 "SCOPE": [ART+"scope_receipt_before.log",ART+"scope_receipt_after.log","tests/test_recovery_scope_receipt.py::test_public_scope_receipts_cannot_rewrite_completed_context_accounting"],
 "RESEARCH": [AUD+"model-copy-graph-acceptance.json",AUD+"strict-copy-research-adaptation.json",AUD+"r13-graph-paths-final.log",ART+"final_compatibility_after.log","tests/test_global_evidence_review.py::test_late_matching_negative_proof_invalidates_earlier_material_quorum","tests/test_global_evidence_review.py::test_known_conflict_cannot_pass_the_fast_path_either","tests/test_recovery_graph_paths.py::test_eight_task_topology_finishes_without_enlarging_graph_limit","tests/test_graph_transition_bound.py::test_injected_no_progress_graph_stops_within_business_limit"],
 "DEPENDENCY": [ART+"dependency_binding_before.log",ART+"dependency_cli_layout_after.log","tests/test_recovery_dependency_binding.py::test_subject_helper_bytes_are_bound_to_analyzer_identity","tests/test_recovery_dependency_binding.py::test_static_tool_registration_bytes_are_bound_to_analyzer_identity"],
 "OWNED": [AUD+"owned-application-review-patch2/result.json"],
 "QUALITY": [AUD+"quality-final-patch2/summary.json",AUD+"release-final-patch2/quality-controls/results/summary.json",AUD+"quality_reference.json",AUD+"recovery-protocol.json"],
 "UNKNOWN": [AUD+"recovery-protocol.json"],
}

def rows(text, kind):
    result = []
    for line in text.strip().splitlines():
        ident,title,classification,status,refs,note = line.split("|",5)
        groups=refs.split(",")
        result.append({"id":ident,"title":title,"classification":classification,"status":status,
                       "evidence_groups":groups,"evidence":list(dict.fromkeys(p for group in groups for p in CATALOG[group])),
                       "finding":note,"kind":kind})
    return result

ISSUES = rows("""
F01|发布与原用户阻断|DOCUMENTED_RELEASE_GAP|PARTIAL_USER_FAILURE_UNKNOWN|BASE,RELEASE,UNKNOWN|已封存并安装工程试用发行物；2684pass前置baseline与源编辑并发，仅特征化而非不可变准入门禁；缺原用户命令/日志/输入/环境，不能宣称其失败已复现或修好。
F02|本地证据受公开8KiB池限制|FEATURE_GAP|REMEDIATED_IN_EXPLICIT_V2|V2,LOCAL|v2完整原始记录先保存，summary仅影响分享；v1原预算语义与历史数据保留。
F03|已知未投递反证可能被隐藏|CONTROLLED_CONSUMER_COUNTEREXAMPLE|FULL_LOCAL_SET_CONTROL_PASS|LOCAL|4000+4000字节控制注入只投递一份时旧子集单边强；完整本地归并为CONFLICT。原v1正常服务每候选一份观察，未复现其正常路径产生两份反证。
F04|分析完成与交付计数混用|ACCOUNTING_DESIGN_GAP|V2_STAGE_CONTROLS_PASS|V2,FAULT|v2分离analysis/persistence/property/share；budget1不把已完成分析写成未开始；不悄改v1分母。
F05|下一步行动是否有用|UNMEASURED_HUMAN_VALUE|NOT_MEASURED|NAV,UNKNOWN|已有责任方、输入和完成条件；无两名新人工审阅者任务完成或净时间证据。
F06|候选种类与窄验证范围|DOCUMENTED_CAPABILITY_GAP|PARTIAL_LITERAL_PROFILE|V2,QUALITY,OWNED|区分有界性质、线索及不支持范围；命名mode仍未知，自有application15文件3候选全部U。非一般权限、全应用或漏洞检出承诺。
F07|缺SUPPORTED公开CLI验收|MISSING_ACCEPTANCE|ENGINEERING_E2E_PASS|V2,RELEASE|真实公共CLI及仓库外安装wheel均交付匹配SUPPORTED/REFUTED/UNKNOWN；只证明声明mode性质。
F08|安装依赖是否牵连研究环境|INSTALL_HYPOTHESIS|CHARACTERIZED_MINIMAL_INSTALL_PASS|RELEASE,V06|无PYTHONPATH、pytest、langgraph、evaluation、provider运行包的独立环境可用；保留所声明tree-sitter等依赖，不称零依赖。
F09|同一行同规则操作碰撞|REPRODUCED_LEGACY_ID_COLLISION|REPAIRED_EXPLICIT_V2|OPS,V2|旧v1两chmod折成一个候选被实际特征化；v2完整AST span/规则版本身份区分操作，保留历史ID。
F10|摘要解析后读混版|NOT_REPRODUCED_INTRA_DISCOVERY|SNAPSHOT_EXTENSION_CONTROLS_PASS|SNAP|原discovery同一次读取即hash/parse，未复现该处混版；v2封存字节延伸至后读及verify，拒绝SOURCE_DRIFT，不声称活动树全局原子快照。
F11|公开copy绕过字段合法性|REPRODUCED_PUBLIC_UPDATE_BYPASS|REPAIRED|COPY,SCOPE|原公开copy修前10反例失败、3正控通过；RF06另修返回v2上下文回执别名；合法alias和copy正控保持，私有反射不属边界。
F12|补上下文复用旧缺项缓存|NOT_REPRODUCED_CACHE_HYPOTHESIS|CHARACTERIZATION_PASS|VIEW|实际tool新scope在显式paid helper grant后输入/视图改变；同scope重复仍blocked；未另建缓存或篡改冻结专家scope。
F13|量词范围与前提难消费|CONTRACT_PRESENTATION_GAP|BOUNDED_SHARED_DECISION_PASS|QUAL,V2|复用原PropertyContract和共享准入，保留命题/量词/输入/方法/范围；声明有限支持，不重写解释器或保证任意前提组合。
F14|强静态投影多处漂移|NOT_REPRODUCED_SEMANTIC_DRIFT|SHARED_WRAPPER_CONTROLS_PASS|QUAL,RESEARCH|只读AcceptanceDecision委托原_command_status/_matches_validator_subject；产品和研究同方向；原UNRESOLVED不改写。
F15|rename不能同时保证不覆盖|REPRODUCED_EMPTY_TARGET_RACE|REPAIRED_LOCAL_LINUX|COMMIT|修前并发空目录被替换；renameat2NOREPLACE及目录同步序列修复。unsupported显式失败，最终同步失败区分已发布，不保证所有FS断电耐久。
F16|保密与本地复核闭环|FEATURE_AND_HUMAN_GAP|MACHINE_NAVIGATION_PASS_HUMAN_UNKNOWN|NAV,VERIFY|私有完整记录+显式view/verify，分享件无原文且NOT_VERIFIABLE；人工能否独立完成动作未测。
F17|消息预算不约束解析资源|RESOURCE_BOUNDARY_GAP|OWNED_BOUNDARY_CONTROLS_PASS|RESOURCE,SCALE|文件/字节/AST/候选/记录限及owned worker墙钟CPUAS边界；worker丢失的分母为未知，不能伪造0。
F18|摘要与深复制规模放大|MEASURED_COMPLEXITY_GAP|DESCRIPTIVE_PROFILED|DIGEST,SCALE,DEEPCOPY|1000消费者旧索引1000000文档序列化，封存索引1000/一次JSON；仅声明观测热点与入口copy计数，不证明整体线性或因果加速。
F19|共享观察多专家非独立证明|DOCUMENTED_RESEARCH_LIMIT|PRESERVED|RESEARCH|引用别名及票数不增加producer独立证据强度；共享事实准入与一专家一票约束保留。
F20|16图上限不能证明所有8任务|NOT_REPRODUCED_LISTED_TOPOLOGIES|CHARACTERIZATION_PASS_NOT_EXHAUSTIVE|RESEARCH|E4/E5共72控制，70个代表合法拓扑，图节点11–14，上限16；无进展有界终止；不宣称穷尽所有DAG或调度后的真实模型响应不变。
F21|见证基础设施工作负载限制|DOCUMENTED_DISABLED_CAPABILITY|REMAINS_DISABLED|RESEARCH,UNKNOWN|scratch/native未启用；不重跑第三方见证；G-A仍NO，GP2禁用。
F22|真实独立质量及人工净收益|UNMEASURED_PRODUCT_VALUE|NOT_MEASURED_HUMAN_USER|QUALITY,UNKNOWN|仅36个其他agent软件控制22exact/0wrongstrong/14命名mode未知；不是人类、heldout、accuracy或FPR；真实用户任务和人试点未提供。
""", "issue")

TASKS = rows("""
R00|冻结与复现用户阻断|DIAGNOSTIC_TASK|PARTIAL_BLOCKED_MISSING_USER_INPUT|BASE,UNKNOWN|版本/dirty清单已保存；baseline2684pass是在源编辑并发期间的特征化运行，不是不可变原版本准入。原用户失败需脱敏命令/日志/输入/环境，不猜根因。
R01|最小发行物|ENGINEERING_TASK|RECORDED_CLEAN_INSTALL_PASS|RELEASE,V06|固定wheel/sdist/离线wheelhouse及锁定哈希，仓库外两次解包安装；解释器正负控制齐全，仅限定Linux声明环境。
R02|有效公开端到端样例|ENGINEERING_TASK|OWNED_E2E_PASS_USER_TASK_NOT_PROVIDED|V2,RELEASE|自有SUPPORTED/REFUTED/UNKNOWN/错绑定/解析路径通过；非用户选定的新鲜实际仓库质量任务。
R03|统一源码字节快照|CHARACTERIZATION_AND_EXTENSION|LISTED_CONTROLS_PASS|SNAP|原hash/parse混版假设未复现；封存每文件字节供后续消费者，漂移拒绝与读取错误账本，不承诺全局原子工作树。
R04|操作级身份与位置|REPAIR_AND_EXPLICIT_MIGRATION|LISTED_CONTROLS_PASS|OPS,V2|v2新ID和AST UTF8端点；切片去重，编码/缩进恢复；旧ID未改。
R05|共享性质准入决定|EXTRACT_EXISTING_AUTHORITY|LISTED_CONTROLS_PASS|QUAL,VERIFY|不另造语义分析器；共享只读投影，局部/未知/错subject不能升级，原验证状态保留。
R06|本地记录与摘要解耦|EXPLICIT_V2_FEATURE|LISTED_CONTROLS_PASS|LOCAL,V2,FAULT|完整producer记录先落盘，从全部相关完整记录归并；摘要预算不改变本地真值，依赖缺失不独立可验证。
R07|阶段计数和终态|EXPLICIT_V2_CONTRACT|LISTED_CONTROLS_PASS|V2,FAULT|analysis/persistence/property/delivery分离；修复额外RF04计数校验，阶段失败与取消保留分母；v1契约保留。
R08|公开更新反序列化边界|REPRODUCED_REPAIR|LISTED_CONTROLS_PASS|COPY,SCOPE|公开copy完整构造验证，非法/跨字段输入拒绝；RF06返回v2回执改用不可变ScopeAdmission，旧JSON形状不变。
R09|补上下文输入实际生效|HYPOTHESIS_CHARACTERIZATION|NO_STALE_CACHE_REPRODUCED|VIEW|付费grant新scope实际tool输入变更；重复投递另计且不重执行；不改变授权范围或冻结scope。
R10|可完成的finding动作|PRESENTATION_FEATURE_AND_HUMAN_TASK|MACHINE_PASS_HUMAN_NOT_MEASURED|NAV,DISPLAY,UNKNOWN|机器位置、私有证据、责任/输入/完成条件可核对；两名人工新审阅者独立完成仍未知。
R11|一致不覆盖产物和验证|LOCAL_ENGINEERING_REPAIR|LISTED_LOCAL_CONTROLS_PASS|COMMIT,VERIFY,FAULT|不替换目标，提交前同步，晚completion非权威；verify完整记录+重建AST/candidate+注册静态重放，非外部身份认证。
R12|规模画像与真实资源边界|OWNED_ENGINEERING_MEASUREMENT|MEASURED_SCOPE_LIMITED|RESOURCE,SCALE,DIGEST,DEEPCOPY|100/500/1000生成文本完整v2测量；真实CPU/AS自有进程控制；单次两profile及发行准备同机负载，第三suite未重叠，非授权用户仓库或因果benchmark。
R13|研究边界兼容回归|OFFLINE_COMPATIBILITY|FINAL_FULL_SUITE_PASS|RESEARCH,FINAL|初次15失败已真实修正；最终2941通过；neutral_source边界显式迁移，不弱化公开copy；历史G-A/GP/模型账本未重定义。
R14|独立静态质量|FRESH_AGENT_ENGINEERING_CONTROLS|PARTIAL_AGENT_ONLY|QUALITY|36样本完整保留，22精确状态匹配、0错误强状态、14命名mode不支持；未做人工独立或新鲜授权仓库审查。
R15|真实人工净收益|HUMAN_EVALUATION|NOT_MEASURED_MISSING_TASKS_REVIEWERS|UNKNOWN|没有人类A/B、仓库级质量和人工净时间数据，不用机器时延代替。
R16|发布交接关闭|LIMITED_TRIAL_RELEASE|ENGINEERING_TRIAL_ONLY_PRODUCT_GATES_OPEN|RELEASE,FINAL,UNKNOWN|最终同源码发行和suite可核对；因原用户任务、用户环境、人类价值未测，仅工程试用版，不能整体产品恢复PASS。
R17|可选模型解释|CONDITIONAL_UNAUTHORIZED_TASK|CLOSED_NOT_ENABLED|UNKNOWN|未获单独请求/token授权且静态人工收益未成立；不调用真实模型，不恢复G-A/K5–K8。
""", "task")

CHECKS = rows("""
V01|实际源码版本与缺材料|USER_DIAGNOSTIC|PARTIAL_USER_FAILURE_UNKNOWN|BASE,UNKNOWN|源码和基线可对应；缺原用户实际版本/失败上下文，不写用户bug已复现。
V02|用户失败命令及等价自有输入|USER_DIAGNOSTIC|NOT_RUN_USER_INPUT_MISSING|UNKNOWN|自有故障控制不冒充与用户失败同阶段，原命令/日志未提供。
V03|固定发行物仓库外安装|ENGINEERING_CONTROL|PASS_RECORDED_RELEASE|RELEASE|两次独立解包离线安装及console调用；非用户自己的环境复验。
V04|无测试研究包静态运行|ENGINEERING_CONTROL|PASS_DECLARED_MINIMAL_PACKAGE|RELEASE|pytest/langgraph/evaluation/baselines/provider模块缺席仍doctor/review；11个安装包包含声明解析依赖。
V05|无密钥无模型网络gate|ENGINEERING_CONTROL|PASS_LISTED_STATIC_CONTROLS|RELEASE,RESOURCE|env不继承凭据、产品无provider包；发布及产品review回执模型请求/目标执行/外部网络为0。pytest自有loopback fixture另属离线契约。
V06|已有输出缺依赖解释器不匹配|ENGINEERING_CONTROL|PASS_LISTED_POSITIVE_NEGATIVE_CONTROLS|V06,RELEASE|existing不覆盖；必需能力缺失诊断；已有3.10.12离线同wheel因>=3.12拒绝exit1且未安装，3.13.5正控通过。
V07|常量权限位支持|ENGINEERING_E2E|PASS_OWNED_LITERAL_MODE|V2,RELEASE|公共CLI完整SUPPORTED仅对应选定mode位，不执行目标。
V08|对应常量权限位否定|ENGINEERING_E2E|PASS_OWNED_LITERAL_MODE|V2,RELEASE|REFUTED同一有限性质，application仍NOT_ASSESSED。
V09|动态mode缺信息|ENGINEERING_E2E|PASS_LISTED_UNKNOWN_CONTROLS|V2,QUALITY|分析完成但UNKNOWN，缺已解析mode来源；命名mode不支持不伪造强结论。
V10|同名不同callee绑定|ENGINEERING_E2E|PASS_SHADOWED_BINDING_CONTROL|V2,OPS|shadowed os没有强状态且不执行callee；其他任意动态绑定不由此自动证明。
V11|零候选与解析失败|ENGINEERING_E2E|PASS_LISTED_RUN_STATE_CONTROLS|FAULT|zero/invalid文件COMPLETED/PARTIAL区分，分母保留。
V12|已有事实后取消内部异常|ENGINEERING_FAILURE_CONTROL|PASS_LISTED_V2_FAILURE_CONTROLS|FAULT|v2证据read失败、内部异常及取消保留此前有效事实，后续tools停止；强制kill另见V46。
V13|清单读取后解析前改文件|ENGINEERING_SNAPSHOT_CONTROL|PASS_SEALED_BYTES_CONTROL|SNAP|解析封存字节或后读SOURCE_DRIFT，不混用版本。
V14|helper/import改变|ENGINEERING_SOURCE_BINDING|PASS_LISTED_DRIFT_CONTROLS|SNAP,VIEW,VERIFY,DEPENDENCY|旧记录不能静默绑定新源码；RF05补上tools/identity及注册代码的分析身份依赖；非跨文件活动树全局原子性证明。
V15|读取错误排除目录|ENGINEERING_INVENTORY|PASS_LISTED_ERROR_EXCLUSION_CONTROLS|SNAP|错误、编码、符号链接和明确排除均记账；未遍历余量unknown，不宣称全部文件覆盖。
V16|根外未授权行读取|ENGINEERING_SOURCE_BOUNDARY|PASS_LISTED_ACCESS_CONTROLS|SNAP,VIEW|拒绝symlink/parent traversal/未grant范围；拒绝本身不证明安全。
V17|同一行同规则两操作|ENGINEERING_ID_AND_E2E|PASS_DISTINCT_OPERATION_CONTROLS|OPS,V2|两个精确ID和独立finding，已知同一行两mode分别R/S。
V18|模块函数重叠切片|ENGINEERING_ID|PASS_LISTED_DEDUP_CONTROLS|OPS|同一AST操作只一次，原端点/snippet保留；不是任意语言去重证明。
V19|中文tabCRLF非UTF8|ENGINEERING_LOCATION|PASS_LISTED_ENCODING_CONTROLS|OPS|UTF8 AST列与原编码字节摘要分离，slice/dedent端点恢复。
V20|不同列前提性质不互借|ENGINEERING_BINDING|PASS_LISTED_SUBJECT_CONTROLS|OPS,COPY,QUAL|精确操作、source/property/scenario subject严格匹配；不同操作不能借同一行强证明。
V21|正向完整路径加无关未知|ENGINEERING_REDUCTION|PASS_SUFFICIENT_POSITIVE_CONTROLS|QUAL,LOCAL|独立已知充分正向仍支持，正常UNKNOWN记录不擦除它；material记录缺失是不同完整性错误。
V22|局部否定加范围缺口|ENGINEERING_REDUCTION|PASS_LISTED_SCOPE_CONTROLS|QUAL|局部/窄方法不升级全范围REFUTED或应用SAFE。
V23|同命令记录产品与研究|ENGINEERING_SHARED_QUALIFICATION|PASS_SHARED_DIRECTION_CONTROLS|QUAL|SANITIZED/UNSANITIZED同方向，原UNRESOLVED不变；两侧不支持对照均拒绝。
V24|手写强状态缺方法依赖|ENGINEERING_ADMISSION|PASS_LISTED_REJECTION_CONTROLS|QUAL,VERIFY|pattern/read/truncated/local/wrongsubject不准入；schema或自报hash不是producer权威。
V25|只缩小summary预算|ENGINEERING_V2_BUDGET|PASS_LOCAL_TRUTH_INVARIANCE|V2,DISPLAY|1byte分享不影响已完成本地S/R/U，Hengine独立于Hdelivery；metadata额外开销单列。
V26|正反证仅能投递一份|CONTROLLED_CONSUMER_INJECTION|PASS_FULL_LOCAL_CONFLICT_CONTROL|LOCAL|4000+4000/8192-256池控制仍完整本地CONFLICT；未称原单观察服务默认可达此反例。
V27|顺序交换无关记录|ENGINEERING_REDUCTION|PASS_LISTED_PERMUTATION_CONTROLS|LOCAL,QUAL|两个顺序均CONFLICT； unrelated subject不成为此候选证据，但完整inventory先验证。
V28|producer别名与改变内容|ENGINEERING_PROTOCOL|PASS_ORIGINAL_PRODUCER_CONTROLS|LOCAL|citation alias去重保留原记录；同producer变payload/context明确错误，不按多数票遮盖。
V29|落盘失败必要记录缺失|ENGINEERING_FAILURE_CONTROL|PASS_LISTED_MATERIAL_FAILURE_CONTROLS|LOCAL,FAULT|write/fsync/quota/missing记录拒绝完整性；v2已完成前序事实保留，失败候选无强状态。
V30|摘要分享无完整依据|ENGINEERING_SHARE_CONTRACT|PASS_NOT_VERIFIABLE_CONTROL|V2,RELEASE|share明确NOT_VERIFIABLE且不保留独立强断言；私有包访问需用户授权。
V31|分析完成summary没交付|ENGINEERING_ACCOUNTING|PASS_STAGE_DENOMINATOR_CONTROL|V2|analysis_completed=1、persistence完整，summary1byte不成为analysis_not_started。
V32|S/R/U/冲突失败守恒|ENGINEERING_SCHEMA_AND_CONTROL|PASS_LISTED_PARTITION_CONTROLS|FAULT,LOCAL,DISPLAY|v2阶段计数验证及RF04失败回归；CONFLICT独立于resolved_without_conflict。控制非默认服务多个validator实绩。
V33|多调用和多候选分母|ENGINEERING_ACCOUNTING|PASS_LISTED_COST_CONTROLS|SCALE,LOCAL,VIEW|analysis/replay attempts分别记；100/500/1000候选200/1000/2000总调用不是候选数；重复delivery不增producer执行。
V34|各阶段分别失败|ENGINEERING_FAILURE_CONTROL|PASS_ENUMERATED_STAGE_CONTROLS|FAULT,RESOURCE,SNAP|输入/解析/analysis/record/presentation已枚举失败有阶段原因及前序事实；不宣称所有故障组合穷尽。
V35|公开copy非法更新|REPRODUCED_REPAIR_CONTROL|PASS_VALIDATED_UPDATE_CONTROLS|COPY|非法类型/位置/版本与constructor一致拒绝，跨字段重新验证。
V36|合法copy往返不可变|ENGINEERING_POSITIVE_CONTROL|PASS_ROUNDTRIP_AND_ALIAS_CONTROLS|COPY,SCOPE|合法copy/往返/alias保持；RF06新v2上下文回执别名1failed→37affectedpass→2941全量；未称磁盘包被对象别名改写。
V37|未知字段派生摘要错subject|ENGINEERING_PROTOCOL|PASS_LISTED_SCHEMA_CONTROLS|COPY,VERIFY,FAULT|未知状态/版本/错subject拒绝；派生计数完整性验证，序列化metadata不能替代重建AST绑定。
V38|补helper新输入重分析|HYPOTHESIS_CHARACTERIZATION|PASS_NO_STALE_CACHE_FOUND|VIEW|实际tool paid grant新scope输入改变；不是同一冻结任务偷偷扩大读取。
V39|相同记录重复投递|ENGINEERING_ACCOUNTING|PASS_CACHED_REDELIVERY_CONTROL|VIEW,LOCAL|交付另计，producer保持一次，不物理重执行或重复记独立证据。
V40|未授权内容元数据影响分析|ENGINEERING_SOURCE_BOUNDARY|PASS_LISTED_VIEW_CONTROLS|VIEW,VERIFY|admitted paths限制分析/模型视图；verify由完整封存模块重建绑定。默认全根内部索引另列，不等同模型上下文收费。
V41|新审阅者报告定位|MACHINE_AND_HUMAN_ACCEPTANCE|PARTIAL_MACHINE_PASS_HUMAN_NOT_MEASURED|NAV,OPS|view机器重核source+精确端点可定位同一操作；两名独立新人工审阅者未测。
V42|UNKNOWN行动条件|PRESENTATION_AND_HUMAN_VALUE|PARTIAL_STRUCTURED_ACTION_HUMAN_UNKNOWN|V2,NAV,UNKNOWN|required_input/owner/done_condition齐全；字段齐全不证明人实际完成任务。
V43|分享秘密原始异常|ENGINEERING_PRIVACY|PASS_LISTED_PRIVATE_PUBLIC_CONTROLS|NAV,LOCAL,FAULT|自有fake secret/异常不入公共正文，完整descriptor/原文留.private0600/0700；不推断任意字符串保密均穷尽。
V44|旧source陈旧及展示排序|ENGINEERING_PRESENTATION|PASS_LISTED_DRIFT_AND_ORDER_CONTROLS|NAV,DISPLAY|source变更拒绝SOURCE_DRIFT；实际S/R/U结果反转输入优先报告字节一致、身份/按ID事实/refs/计数不变。
V45|空非空并发目标|REPRODUCED_REPAIR_CONTROL|PASS_ATOMIC_NO_REPLACE_CONTROLS|COMMIT|空/非空/file/symlink/raced目录均不替换；真实旧空目录竞态已先失败。
V46|写盘中止强杀恢复|LOCAL_ENGINEERING_FAILURE|PARTIAL_LISTED_FAILURES_NO_UNIVERSAL_CRASH_CLAIM|COMMIT,RESOURCE,FAULT|precommit失败不发布完整包，worker死亡不伪造分母，私有progress可保守审计；未做电源崩溃或所有FS恢复实验。
V47|缺记录改内容subjectmanifest|ENGINEERING_LOCAL_VERIFICATION|PASS_LISTED_INTEGRITY_REPLAY_CONTROLS|VERIFY,LOCAL,RELEASE|核对全package/material、源码依赖和注册producer静态重放；hash只是本地一致性，非外部认证。
V48|晚completion私有权限|ENGINEERING_COMMIT_AUTHORITY|PASS_LISTED_COMMIT_CONTROLS|COMMIT,RELEASE|completion authoritative=false且不属proof manifest；0600文件0700私有目录；晚写/sync异常不能撤销已提交证明集。
V49|逐级自有规模|OWNED_DESCRIPTIVE_MEASUREMENT|PASS_100_500_1000_OWNED_RUNS|SCALE|最新完整v2三规模完成R、阶段时延/RSS/字节齐全；仅自有constant750生成文本，单次两profile及发行准备负载，第三suite未重叠。
V50|文件节点时间内存超限|OWNED_RESOURCE_CONTROL|PASS_LISTED_LIMIT_CONTROLS|RESOURCE,SNAP|有限配置，genuine owned CPU/AS超限和timeout保持resource原因/未知或未处理分母，不普通语义UNKNOWN。
V51|索引摘要和复制次数|OWNED_INSTRUMENTATION|PASS_DESCRIPTIVE_ENTRIES_NOT_WHOLE_COMPLEXITY|DIGEST,DEEPCOPY|封存摘要一次；copy入口13018/65018/130018（public5614/28014/56014、construct7404/37004/74004）。不计递归/Pydantic/普通集合/bytes，不证明整体线性。
V52|解析分析取消|ENGINEERING_CANCEL_CONTROL|PASS_LISTED_OWNED_BOUNDARY_CONTROLS|RESOURCE,SNAP,FAULT|快照/空根取消、static已有事实后取消及kill/wait owned worker；不继续新工具/外部操作。
V53|研究产品同静态事实|ENGINEERING_COMPATIBILITY|PASS_LISTED_SHARED_SEMANTICS_FINAL_SUITE|QUAL,RESEARCH,FINAL|准入方向共享，原status不变；历史配置/账本机械保留，不新跑模型实验。
V54|晚反证共享引用一专家多task|ENGINEERING_COMPATIBILITY|PASS_PRESERVED_ADMISSION_CONTROLS|RESEARCH,FINAL|原晚到事实重新准入、producer独立数、一专家一票保持，快路径也不能放过已知矛盾。
V55|合法8任务和无进展|ENGINEERING_GRAPH_CHARACTERIZATION|PASS_REPRESENTATIVE_TOPOLOGIES_NOT_EXHAUSTIVE|RESEARCH,FINAL|72控制/70代表拓扑，16限制不改，节点11–14；no-progress有界；不宣称所有DAG穷尽。
V56|静态缺研究环境执行禁用|ENGINEERING_RELEASE_AND_SCOPE|PASS_STATIC_SCOPE_REMAINS_DISABLED|RELEASE,RESEARCH,FINAL|最小wheel没有research/provider仍可静态；scratch/native/model关闭，live gate未旁路。
V57|非实现者正负未知控制|FRESH_AGENT_SOFTWARE_CONTROLS|PARTIAL_AGENT_CONTROLS_NOT_HUMAN_OR_HELDOUT|QUALITY|36全部保留：22精确state、0wrongstrong、14命名mode不支持、0缺重复位置；5S/5R/12U精确。不叫accuracy/FPR或人类独立验收。
V58|授权仓库无负例参考任务|REAL_USER_QUALITY|NOT_RUN_USER_TASK_NOT_PROVIDED|OWNED,UNKNOWN|自有application源码15文件3候选全U只是工程事实，不是新鲜用户任务或质量参考；不报告FPR/accuracy。
V59|人类预登记AB试点|REAL_HUMAN_VALUE|NOT_MEASURED|UNKNOWN|无任务、参考、人reviewer、时间与仓库级净收益；不以agent/CPU墙钟代替。
V60|同发行干净和用户环境复验|USER_ENVIRONMENT_ACCEPTANCE|PARTIAL_CLEAN_ENV_PASS_USER_ENV_UNKNOWN|RELEASE,FINAL,UNKNOWN|最终发行干净独立环境重复安装通过、suite同源码；用户环境/实际任务/人工净收益未验，整体产品价值门槛未闭合。
""", "acceptance_check")

assert [r["id"] for r in ISSUES] == [f"F{i:02}" for i in range(1,23)]
assert [r["id"] for r in TASKS] == [f"R{i:02}" for i in range(18)]
assert [r["id"] for r in CHECKS] == [f"V{i:02}" for i in range(1,61)]
for values in CATALOG.values():
    for ref in values:
        file, _, test = ref.partition("::")
        assert (ROOT/file).is_file(), file
        if test:
            assert f"def {test}(" in (ROOT/file).read_text(), ref

EVIDENCE_HASHES = {p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
                   for p in sorted({p.split("::",1)[0] for v in CATALOG.values() for p in v})}
FINAL = json.loads((OUT/"final-validation-patch2.json").read_text())
RELEASE = json.loads((OUT/"release-final-patch2/bundle-receipt.json").read_text())
QUALITY = json.loads((OUT/"quality-final-patch2/summary.json").read_text())
data = {
 "schema_version":"product-recovery-feedback-acceptance-v1",
 "status":"ENGINEERING_TRIAL_VALIDATED_PRODUCT_USER_HUMAN_GATES_OPEN",
 "feedback":"docs/reports/cv_agent_design_review_and_recovery_2026-10-01.pdf",
 "matrix_totals":{"issues":22,"tasks":18,"acceptance_checks":60},
 "full_suite":{"status":"PASS", "command":"uv run --no-sync pytest", "first_attempt":{"passed":2904,"failed":15,"seconds":427.90,"log":ART+"final_full_pytest_attempt1.log"}, "prior_patch1_attempt":{"passed":2940,"failed":0,"seconds":427.22,"log":ART+"final_full_pytest_attempt2.log","current_source_gate":False},"final_attempt":{"passed":2941,"failed":0,"skipped":0,"xfail":0,"seconds":422.98,"exit_code":0,"log":ART+"final_full_pytest_attempt3.log"},"receipt":AUD+"final-validation-patch2.json"},
 "source_freeze":{"source_and_tests_files":423,"aggregate_sha256":"ddb6e09675dacc8f884ab52f1719b51fe7ad170696406496405b8791a0eae26a","receipt":AUD+"final-source-freeze-patch2.json","unchanged_during_final_checks":True},
 "release":{"scope":"engineering trial only","receipt":AUD+"release-final-patch2/bundle-receipt.json","zip_sha256":"56732ac312e5fc00ab9a3a971ed09b32d0b215565bbad58d64803afbab84c31e","zip_bytes":4719542,"wheel_sha256":"835287e4acc6b2423eb3aaa0d10fb000ce5d2cc8fb6937be041066197336247c","product_source_files":104,"two_isolated_bundle_installs":"PASS","actual_user_environment":"NOT_PROVIDED"},
 "preservation":{"previous_reports_and_sources_unchanged":True,"report_artifact_files":45,"config_script_files_unchanged":True,"config_script_files":73,"receipt":AUD+"final-validation-patch2.json"},
 "baseline":{"passed":2684,"seconds":409.34,"log":ART+"baseline_full_pytest.log","scope":"characterization concurrent with source editing, not immutable source-snapshot admission","immutable_snapshot_gate":False},
 "quality_controls":{"case_count":36,"exact_state_matches":22,"wrong_strong_states":0,"named_mode_unsupported":14,"missing_or_duplicate_locations":0,"exact_supported":5,"exact_refuted":5,"exact_unknown":12,"human_independent":False,"held_out_claim_eligible":False,"accuracy_or_fpr_claim":False,"receipt":AUD+"quality-final-patch2/summary.json","release_embedded_receipt":AUD+"release-final-patch2/quality-controls/results/summary.json"},
 "owned_project_control":{"source_kind":"project_owned_application_directory","source_files":15,"candidate_count":3,"analysis_completed":3,"unknown":3,"sufficient_evidence":0,"run_state":"COMPLETED","fresh_user_quality_claim":False,"receipt":AUD+"owned-application-review-patch2/result.json"},
 "known_open_product_gates":{"original_user_failure":"BLOCKED_MISSING_INPUT","V41_new_human_reviewers":"NOT_MEASURED","V42_human_action_completion":"NOT_MEASURED","V58_authorized_user_quality":"NOT_PROVIDED","V59_human_net_benefit":"NOT_MEASURED","V60_user_environment":"NOT_PROVIDED"},
 "verification_authority":{"scope":"self-generated user-owned local package consistency, dependency integrity and registered static replay","external_producer_authentication":False,"hash_is_independent_execution_proof":False,"active_worktree_globally_atomic_snapshot":False,"universal_filesystem_crash_durability":False,"source_or_target_execution":False},
 "history":{"G_A":"NO","GP2":"NOT_ENABLED","GP3":"NOT_MEASURED","GP4":"NOT_MEASURED","R17":"CLOSED_NOT_ENABLED","K5_K8":"NOT_STARTED","history_redefined":False},
 "actual_project_model_requests":0,
 "matrix_evidence_version":"PATCH2_FINAL_SAME_SOURCE_VERIFIED",
 "prior_patch1_audit":{"acceptance":"prior-patch1-acceptance.json","verification":"prior-patch1-verification.md","current_source_gate":False},
 "fresh_additional_reviewer":{"status":"NOT_COMPLETED","independent_review_pass_claim":False,"receipt":AUD+"final-validation-patch2.json"},
 "additional_reproduced_repairs":[
  {"id":"RF01","bug":"v2读取完整证据失败丢弃此前已完成结果包","before":ART+"v2_stage_failures_before.log","test":"tests/test_recovery_v2_failures.py::test_complete_evidence_read_failure_retains_earlier_fact_without_strong_second_state","after":ART+"final_v2_controls.log"},
  {"id":"RF02","bug":"v2内部异常后继续启动后续分析","before":ART+"v2_stage_failures_before.log","test":"tests/test_recovery_v2_failures.py::test_unexpected_internal_failure_preserves_first_and_stops_later_tools","after":ART+"final_v2_controls.log"},
  {"id":"RF03","bug":"presentation阶段失败被误归类为generic worker失败","before":ART+"v2_presentation_failure_before.log","test":"tests/test_recovery_v2_failures.py::test_public_artifact_failure_has_presentation_stage_and_keeps_private_material","after":ART+"final_v2_controls.log"},
  {"id":"RF04","bug":"错误persisted候选计数和不完整verified阶段仍可通过公开模型验证","before":ART+"v2_stage_count_before.log","test":"tests/test_recovery_v2_failures.py::test_public_copy_rejects_false_persisted_denominator_and_incomplete_verified_stage","after":ART+"final_v2_controls.log"},
  {"id":"RF05","bug":"analysis身份未绑定tools/identity.py和tools/validation/registry.py相关字节","before":ART+"dependency_binding_before.log","before_failed":2,"tests":["tests/test_recovery_dependency_binding.py::test_subject_helper_bytes_are_bound_to_analyzer_identity","tests/test_recovery_dependency_binding.py::test_static_tool_registration_bytes_are_bound_to_analyzer_identity"],"after":ART+"dependency_cli_layout_after.log","after_passed":31,"final_suite_passed":2941},
  {"id":"RF06","bug":"Returned public v2 context billing receipt aliases could rewrite completed scope_admissions in memory","before":ART+"scope_receipt_before.log","before_failed":1,"after":ART+"scope_receipt_after.log","after_passed":37,"after_seconds":5.32,"test":"tests/test_recovery_scope_receipt.py::test_public_scope_receipts_cannot_rewrite_completed_context_accounting","fix":"Existing immutable ScopeAdmission models preserve the serialized JSON shape","persisted_package_mutation_claim":False,"final_suite_passed":2941}],
 "issues":ISSUES,"tasks":TASKS,"acceptance_checks":CHECKS,"evidence_catalog":CATALOG,"evidence_sha256":EVIDENCE_HASHES,
 "final_receipts_pending":[],
 "remaining_user_inputs":["脱敏原失败命令和日志、输入、运行版本及环境","授权的新鲜用户源码审查任务与独立参考","不参与实现的两名人类审阅者及预登记人工试点","在用户环境运行同一固定发行物的回执"],
}
for group in (ISSUES,TASKS,CHECKS):
    for row in group:
        row["current_source_binding"]="PATCH2_FINAL_SAME_SOURCE_VERIFIED"
assert data["full_suite"]["final_attempt"]["passed"] == FINAL["full_pytest"]["passed"]
assert data["full_suite"]["final_attempt"]["seconds"] == FINAL["full_pytest"]["seconds"]
assert data["source_freeze"]["aggregate_sha256"] == FINAL["source_tests_freeze_sha256"]
assert data["release"]["zip_sha256"] == RELEASE["sha256"] == FINAL["fixed_trial_release"]["sha256"]
assert data["release"]["zip_bytes"] == RELEASE["bytes"]
assert data["quality_controls"]["case_count"] == QUALITY["case_count"]
assert data["quality_controls"]["exact_state_matches"] == QUALITY["exact_state_matches"]
assert data["quality_controls"]["wrong_strong_states"] == QUALITY["wrong_strong_states"]
(OUT/"acceptance.json").write_text(json.dumps(data,ensure_ascii=False,indent=2)+"\n")
lines=["# 2026-10-01 产品恢复：逐项验收与边界", "",
 "工程试用验证完成，实际用户与人工价值门槛仍未闭合。逐项列出全部 **F01–F22、R00–R17、V01–V60**；`PASS` 仅表示已列软件控制或限定工程验收，不表示任意程序安全、用户原失败已修复或产品净收益成立。", "",
 "前置 baseline 的 **2684 passed，409.34 s** 与团队源编辑并发，是特征化运行，不能当作不可变旧快照的准入门禁。完整修后 suite 首次 **15 failed / 2904 passed，427.90 s**；patch1 **2940 passed，427.22 s** 为历史快照验证，之后 RF06 新回执别名问题被复现并修复。当前最终 patch2 为 **2941 passed，422.98 s，exit 0，无 fail/skip/xfail**。最终 423 项 src/tests 的封存指纹保持不变：`ddb6e09675dacc8f884ab52f1719b51fe7ad170696406496405b8791a0eae26a`。见 [最终回执](final-validation-patch2.json) 和 [源码封存](final-source-freeze-patch2.json)。", "",
 "当前离线工程试用 ZIP：`56732ac312e5fc00ab9a3a971ed09b32d0b215565bbad58d64803afbab84c31e`，4,719,542 bytes；104 项产品源码与同一封存树一致，两次独立解包安装已核对。旧发行快照及失败回执保留；不能用旧 wheel 的安装成绩替代当前源版本。见 [发行回执](release-final-patch2/bundle-receipt.json)。", "",
 "原用户脱敏失败命令、日志、实际输入与环境未提供。机器 `view` 可核对精确操作，但两名新人工审阅者定位与行动完成、人类 A/B 净收益、授权新鲜用户仓库质量和用户环境复验都未测量或未提供。R16 只交付工程试用版，R17 仍关闭。", "",
 "`verify` 核对用户自生成本地包的完整性、源码依赖、重新构造 AST 绑定/候选清单，并重放注册静态工具；它不认证外部 producer 身份，自报 producer 与哈希不是独立执行证明。每文件封存不等于活动工作树全局原子快照；本地 Linux `renameat2`/fsync 控制不等于所有网络文件系统或断电恢复的保证。", "",
 "原 G-A 为 **NO**；GP2 未启用、GP3/GP4 未测。历史 K/E 结果与模型用量账本未重定义；本轮真实项目模型请求为 0。最终机械核对 45 项旧报告/来源及 73 项 config/script 字节保持不变；harness-check 通过。发布及产品review不开外部网络、不执行目标源码，pytest 自有 loopback/Java 等控制仍按 TEST_CONTRACT 运行，不冒充真实第三方实验。", "",
 "## 反馈问题 F01–F22", "", "|编号|证据属性|结果|实际发现及限度|证据组|", "|---|---|---|---|---|"]
for row in ISSUES:
    lines.append(f"|{row['id']} {row['title']}|{row['classification']}|{row['status']}|{row['finding']}|{', '.join(row['evidence_groups'])}|")
for title,group in (("任务卡 R00–R17",TASKS),("验收类别 V01–V60",CHECKS)):
    lines += ["",f"## {title}","","|编号|证据属性|结果|实际发现及限度|证据组|","|---|---|---|---|---|"]
    for row in group:
        lines.append(f"|{row['id']} {row['title']}|{row['classification']}|{row['status']}|{row['finding']}|{', '.join(row['evidence_groups'])}|")
lines += ["","## 额外复现的边界修复","","这些是实现期间实际发现的 RF01–RF06，不能反过来将原报告所有‘待核验’假设改写成已确认 bug。RF01–RF04 有失败控制、保留正控及修后 `final_v2_controls.log` 的 99 passed in 6.68 s；RF05 是独立 2 failed→31 passed；RF06 是独立 1 failed→37 affected passed in5.32s，返回对象改用既有不可变 ScopeAdmission，不称磁盘已提交包被此别名改写。全部再经最终完整 2941 passed，不将六项都冒称为那 99 项。"]
for row in data["additional_reproduced_repairs"]:
    test = row.get("test", ", ".join(row.get("tests", ())))
    lines += ["",f"- {row['id']}：{row['bug']}。失败日志 `{row['before']}`；回归 `{test}`；修后 `{row['after']}`。"]
lines += ["","## 数值分析的有效范围","",
 "36 个另一 agent 设计的自有软件控制：5 个支持、5 个否定、12 个未知精确匹配，共 22/36；7 个预期支持和 7 个预期否定得到 UNKNOWN，均涉及当前不支持的命名 mode。错误强状态为 0，缺失/重复操作位置为 0。全部 36 样本保留，没有从分母删除失败项。该集合不是人类独立、未暴露 held-out 或真实仓库任务，不报告 accuracy/FPR，不据 0 错强状态外推误报概率。", "",
 "该质量回执绑定最终 patch2 的 `quality-final-patch2/summary.json` 及发行内 `release-final-patch2/quality-controls/results/summary.json`，不用旧版本同数值成绩替代。自有项目 application 实际审查15文件、3候选全部UNKNOWN、完整分析3而充分依据0，显示当前覆盖仍窄；它不是新鲜用户仓库任务，不能闭合 V58。额外 fresh-context 终审在 final-validation 中仍为 NOT_COMPLETED，不宣称有独立审查 PASS。", "",
 "最终 100/500/1000 文件的自有 constant-mode750 完整 v2 各运行一次，均 COMPLETED/REFUTED（只指 mode 位）；墙钟 4.023529/18.660626/44.472654 s，RSS 53,727,232/97,116,160/149,364,736 bytes，总 tool attempts 200/1000/2000，分开记 analysis 和 replay。两份审计 profile 与发行安装/准备同机并行；第三轮完整 pytest 在两 profile 完成后才启动，观测为描述性工程数据，不能解释成因果 speedup 或真实仓库规模收益。RLIMIT_AS 限虚拟地址空间，RSS 不是它的剩余额度。", "",
 "最终 profile 的普通规模记录完成于 UTC02:08:04.629691，copy 完成于02:07:56.509690，第三轮 pytest 在02:09:39才启动，pytest_overlap=false。原 measurement/instrumentation 中错误并发标签保留历史，按两份 workload-correction.json 仅更正负载表述；数值和源码 SHA 不变，没有重跑。", "",
 "摘要热点的自有 1000 消费者控制：旧可变索引进行 1,000,000 次文档序列化、1000 次 JSON 序列化、342,001,000 bytes；封存索引进行 1000 次文档序列化、一次 JSON、342,001 bytes，构建成本纳入 index_seconds。可变索引修改、伪造属性和 subclass 不沿用缓存。", "",
 "实际完整 v2 copy 入口计数（100/500/1000）：13,018/65,018/130,018，其中 public reads 5,614/28,014/56,014，construction 7,404/37,004/74,004。插桩只数 domain deepcopy 别名入口，未数递归、Pydantic、普通集合和 bytes；不能据这些入口近似线性就证明整体算法线性或内存边界。", "",
 "E4/E5 72 个控制中有 70 个代表合法八任务拓扑，图节点 11–14，business limit16 没有放宽；无进展另有有限终止控制。不宣称所有 DAG 已穷尽，更不宣称改变模型调度后真实响应相同。", "",
 "## 证据索引", "", "下列组名在每行展开到实际路径与测试名；JSON 另保存每个证据文件的 SHA256。测试名是范围索引，不是以一项测试替代整个类别。"]
for name,refs in CATALOG.items():
    lines += ["",f"### {name}",""]
    lines += [f"- `{ref}`" for ref in refs]
lines += ["","## 尚需用户材料","",
 "- 脱敏原失败命令、日志、输入、运行版本和环境，以复现 R00/V01–V02。",
 "- 新鲜授权用户审查任务与独立参考，以核对 V58。",
 "- 两名不参与实现的人类审阅者及预登记人工试点，以核对 V41/V42/V59。",
 "- 用户环境对同一固定发行物的运行回执，以核对 V60。", "",
 "这些缺项不阻止已授权工程修复和试用封包，但阻止把整体产品恢复、实际用户任务或人类净收益标为通过。"]
(OUT/"verification.md").write_text("\n".join(lines)+"\n")
print(json.dumps({"written":["acceptance.json","verification.md"],"F":len(ISSUES),"R":len(TASKS),"V":len(CHECKS),"evidence_files":len(EVIDENCE_HASHES)}))
