from cv_agent.baselines.experts import AuthorizationExpert, FlowRefutationExpert, ScanExpert, TaintExpert
from cv_agent.domain.types import Candidate, Evidence


def _candidate() -> Candidate:
    return Candidate(
        candidate_id="case",
        case_id="case",
        repository_id="repo",
        path="handler.py",
        line=1,
        query="handler",
    )


def _evidence(text: str, evidence_id: str = "graph:handler.py") -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        path=evidence_id.removeprefix("graph:"),
        text=text,
        retrieval="graph",
        score=1.0,
    )


def test_scanner_abstains_when_limited_rules_find_no_sink():
    vote = ScanExpert().evaluate(_candidate(), [_evidence("return value")])
    assert vote.label == "ABSTAIN"


def test_taint_requires_ordered_same_function_evidence():
    vote = TaintExpert().evaluate(
        _candidate(),
        [
            _evidence(
                "value = request.args['cmd']\nsubprocess.run(value, shell=True)\nsanitize(other)",
            )
        ],
    )
    assert vote.label == "VULNERABLE"


def test_taint_accepts_only_an_intervening_sanitizer_as_safe_evidence():
    vote = TaintExpert().evaluate(
        _candidate(),
        [
            _evidence(
                "value = request.args['cmd']\nvalue = sanitize(value)\nsubprocess.run(value, shell=True)",
            )
        ],
    )
    assert vote.label == "SAFE"


def test_taint_tracks_java_helper_source_to_sql_sink():
    vote = TaintExpert().evaluate(
        _candidate(),
        [
            _evidence(
                'String param = scr.getTheParameter("vector");\n'
                'String sql = "SELECT * FROM users WHERE name=\'" + param + "\'";\n'
                "statement.executeQuery(sql);"
            )
        ],
    )

    assert vote.label == "VULNERABLE"


def test_taint_does_not_treat_overwritten_java_constant_as_source_flow():
    vote = TaintExpert().evaluate(
        _candidate(),
        [
            _evidence(
                'String param = request.getHeader("vector");\n'
                'String bar = "safe";\n'
                'String filter = "(&(uid=" + bar + "))";\n'
                "ctx.search(base, filter, sc);"
            )
        ],
    )

    assert vote.label == "SAFE"


def test_taint_propagates_java_collection_round_trip():
    vote = TaintExpert().evaluate(
        _candidate(),
        [
            _evidence(
                'String[] values = request.getParameterValues("vector");\n'
                "String param = values[0];\n"
                "map.put(\"key\", param);\n"
                'String bar = (String) map.get("key");\n'
                'String filter = "(&(uid=" + bar + "))";\n'
                "ctx.search(base, filter, sc);"
            )
        ],
    )

    assert vote.label == "VULNERABLE"


def test_taint_tracks_java_collection_keys_independently():
    safe = TaintExpert().evaluate(
        _candidate(),
        [
            _evidence(
                'String param = request.getHeader("vector");\n'
                "map.put(\"keyA\", \"safe\");\n"
                'map.put("keyB", param);\n'
                'String bar = (String) map.get("keyA");\n'
                'String sql = "SELECT * FROM users WHERE name=\'" + bar + "\'";\n'
                "statement.execute(sql);"
            )
        ],
    )
    vulnerable = TaintExpert().evaluate(
        _candidate(),
        [
            _evidence(
                'String param = request.getHeader("vector");\n'
                "map.put(\"keyA\", \"safe\");\n"
                'map.put("keyB", param);\n'
                'String bar = (String) map.get("keyB");\n'
                'String sql = "SELECT * FROM users WHERE name=\'" + bar + "\'";\n'
                "statement.execute(sql);"
            )
        ],
    )

    assert safe.label == "SAFE"
    assert vulnerable.label == "VULNERABLE"


def test_taint_tracks_java_parameter_map_source():
    vote = TaintExpert().evaluate(
        _candidate(),
        [
            _evidence(
                "java.util.Map<String,String[]> map = request.getParameterMap();\n"
                'String[] values = map.get("vector");\n'
                'String param = "";\n'
                "if (values != null) param = values[0];\n"
                'String sql = "SELECT * FROM users WHERE name=\'" + param + "\'";\n'
                "statement.execute(sql);"
            )
        ],
    )

    assert vote.label == "VULNERABLE"


def test_taint_tracks_cookie_value_and_parameter_name_sources():
    cookie = TaintExpert().evaluate(
        _candidate(),
        [
            _evidence(
                'String param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");\n'
                'String sql = "SELECT * FROM users WHERE name=\'" + param + "\'";\n'
                "statement.execute(sql);"
            )
        ],
    )
    parameter_name = TaintExpert().evaluate(
        _candidate(),
        [
            _evidence(
                "java.util.Enumeration<String> names = request.getParameterNames();\n"
                "String name = (String) names.nextElement();\n"
                "String param = name;\n"
                'String sql = "SELECT * FROM users WHERE name=\'" + param + "\'";\n'
                "statement.execute(sql);"
            )
        ],
    )

    assert cookie.label == "VULNERABLE"
    assert parameter_name.label == "VULNERABLE"


def test_taint_tracks_multiline_java_string_assignment():
    vote = TaintExpert().evaluate(
        _candidate(),
        [
            _evidence(
                "java.util.Map<String,String[]> map = request.getParameterMap();\n"
                'String[] values = map.get("vector");\n'
                'String param = "";\n'
                "if (values != null) param = values[0];\n"
                "String sql = \"SELECT * FROM users WHERE name='\"\n"
                "    + param + \"'\";\n"
                "statement.execute(sql);"
            )
        ],
    )

    assert vote.label == "VULNERABLE"


def test_taint_evaluates_simple_java_ternary_constant_branch():
    vote = TaintExpert().evaluate(
        _candidate(),
        [
            _evidence(
                'String param = request.getHeader("vector");\n'
                "int num = 106;\n"
                'String bar = (7*18) + num > 200 ? "safe" : param;\n'
                "String fileName = baseDir + bar;\n"
                "new FileInputStream(fileName);"
            )
        ],
    )

    assert vote.label == "SAFE"


def test_taint_evaluates_simple_java_if_tainted_branch():
    vote = TaintExpert().evaluate(
        _candidate(),
        [
            _evidence(
                'String param = request.getHeader("vector");\n'
                "int num = 196;\n"
                "if ( (500/42) + num > 200 )\n"
                "   bar = param;\n"
                'else bar = "safe";\n'
                'String sql = "SELECT * FROM users WHERE name=\'" + bar + "\'";\n'
                "statement.execute(sql);"
            )
        ],
    )

    assert vote.label == "VULNERABLE"


def test_taint_evaluates_constant_java_switch_branch():
    vulnerable = TaintExpert().evaluate(
        _candidate(),
        [
            _evidence(
                'String param = request.getHeader("vector");\n'
                'String bar;\n'
                'String guess = "ABC";\n'
                "char switchTarget = guess.charAt(2);\n"
                "switch (switchTarget) {\n"
                "case 'A':\n"
                "    bar = param;\n"
                "    break;\n"
                "case 'B':\n"
                '    bar = "safe";\n'
                "    break;\n"
                "case 'C':\n"
                "case 'D':\n"
                "    bar = param;\n"
                "    break;\n"
                "default:\n"
                '    bar = "safe";\n'
                "    break;\n"
                "}\n"
                'String sql = "SELECT * FROM users WHERE name=\'" + bar + "\'";\n'
                "statement.execute(sql);"
            )
        ],
    )
    safe = TaintExpert().evaluate(
        _candidate(),
        [
            _evidence(
                'String param = request.getHeader("vector");\n'
                'String bar;\n'
                'String guess = "ABC";\n'
                "char switchTarget = guess.charAt(1);\n"
                "switch (switchTarget) {\n"
                "case 'A':\n"
                "    bar = param;\n"
                "    break;\n"
                "case 'B':\n"
                '    bar = "safe";\n'
                "    break;\n"
                "case 'C':\n"
                "case 'D':\n"
                "    bar = param;\n"
                "    break;\n"
                "default:\n"
                '    bar = "safe";\n'
                "    break;\n"
                "}\n"
                'String sql = "SELECT * FROM users WHERE name=\'" + bar + "\'";\n'
                "statement.execute(sql);"
            )
        ],
    )

    assert vulnerable.label == "VULNERABLE"
    assert safe.label == "SAFE"


def test_taint_treats_unknown_helper_result_as_clean_only_when_arguments_are_clean():
    safe = TaintExpert().evaluate(
        _candidate(),
        [
            _evidence(
                'String param = request.getHeader("vector");\n'
                'String g = "constant";\n'
                "String bar = thing.doSomething(g);\n"
                'String sql = "SELECT * FROM users WHERE name=\'" + bar + "\'";\n'
                "statement.execute(sql);"
            )
        ],
    )
    vulnerable = TaintExpert().evaluate(
        _candidate(),
        [
            _evidence(
                'String param = request.getHeader("vector");\n'
                "String bar = thing.doSomething(param);\n"
                'String sql = "SELECT * FROM users WHERE name=\'" + bar + "\'";\n'
                "statement.execute(sql);"
            )
        ],
    )

    assert safe.label == "SAFE"
    assert vulnerable.label == "VULNERABLE"


def test_taint_uses_retrieved_constant_return_helper_summary():
    vote = TaintExpert().evaluate(
        _candidate(),
        [
            _evidence(
                'String param = scr.getTheValue(request.getHeader("vector"));\n'
                'String sql = "SELECT " + param;\n'
                "statement.execute(sql);"
            ),
            _evidence(
                'String getTheValue(String key) { return "constant"; }',
                "graph:helpers/SeparateClassRequest.java::SeparateClassRequest.getTheValue@1",
            ),
        ],
    )

    assert vote.label == "SAFE"


def test_taint_rejects_ambiguous_constant_return_helper_summary():
    vote = TaintExpert().evaluate(
        _candidate(),
        [
            _evidence(
                'String param = scr.getTheValue(request.getHeader("vector"));\n'
                'String sql = "SELECT " + param;\n'
                "statement.execute(sql);"
            ),
            _evidence(
                'String getTheValue(String key) { return "constant"; }',
                "graph:helpers/Safe.java::Safe.getTheValue@1",
            ),
            _evidence(
                "String getTheValue(String key) { return key; }",
                "graph:helpers/Unsafe.java::Unsafe.getTheValue@1",
            ),
        ],
    )

    assert vote.label == "VULNERABLE"


def test_taint_uses_proven_clean_nonstandard_sink_argument_name():
    vote = TaintExpert().evaluate(
        _candidate(),
        [
            _evidence(
                'String param = scr.getTheValue("vector");\n'
                'String[] args = {"sh", "-c", "echo " + param};\n'
                "ProcessBuilder pb = new ProcessBuilder(args);"
            ),
            _evidence(
                'String getTheValue(String key) { return "constant"; }',
                "graph:helpers/SeparateClassRequest.java::SeparateClassRequest.getTheValue@1",
            ),
        ],
    )

    assert vote.label == "SAFE"


def test_taint_does_not_treat_ldap_filters_array_as_clean_filter():
    vote = TaintExpert().evaluate(
        _candidate(),
        [
            _evidence(
                'String param = request.getHeaders("vector").nextElement();\n'
                "[... omitted non-adjacent context ...]\n"
                'Object[] filters = new Object[]{"constant"};\n'
                "idc.search(base, filter, filters, sc);"
            )
        ],
    )

    assert vote.label == "VULNERABLE"


def test_authorization_guard_must_precede_operation_in_same_function():
    guarded = AuthorizationExpert().evaluate(
        _candidate(),
        [_evidence("require_permission(actor)\ndatabase.delete(user_id)")],
    )
    unguarded = AuthorizationExpert().evaluate(
        _candidate(),
        [
            _evidence("database.delete(user_id)"),
            _evidence("require_permission(actor)", "graph:unrelated.py"),
        ],
    )
    assert guarded.label == "SAFE"
    assert unguarded.label == "VULNERABLE"


def test_flow_refutation_proves_constant_ternary_sink_value():
    vote = FlowRefutationExpert().evaluate(
        _candidate(),
        [
            _evidence(
                'String param = request.getHeader("vector");\n'
                "int num = 106;\n"
                'String bar = (7*18) + num > 200 ? "safe" : param;\n'
                "String fileName = org.example.Paths.baseDir + bar;\n"
                "new FileInputStream(fileName);"
            )
        ],
    )

    assert vote.label == "SAFE"


def test_flow_refutation_uses_retrieved_constant_helper_summary():
    vote = FlowRefutationExpert().evaluate(
        _candidate(),
        [
            _evidence(
                'String param = scr.getTheValue("vector");\n'
                'String sql = "SELECT " + param;\n'
                "statement.execute(sql);"
            ),
            _evidence(
                'String getTheValue(String key) { return "constant"; }',
                "graph:helpers/SeparateClassRequest.java::SeparateClassRequest.getTheValue@1",
            ),
        ],
    )

    assert vote.label == "SAFE"


def test_flow_refutation_requires_all_helper_implementations_to_preserve_clean_args():
    sink = _evidence(
        'String clean = "constant";\n'
        "String bar = new Test().doSomething(clean);\n"
        'String sql = "SELECT " + bar;\n'
        "statement.execute(sql);"
    )
    preserving = [
        _evidence(
            "String doSomething(String value) { return value; }",
            "graph:helpers/Thing1.java::Thing1.doSomething@1",
        ),
        _evidence(
            "String doSomething(String value) {\n"
            "String copy = new StringBuilder(value).toString();\n"
            "return copy;\n"
            "}",
            "graph:helpers/Thing2.java::Thing2.doSomething@1",
        ),
    ]
    ambient_source = _evidence(
        'String doSomething(String value) { return request.getHeader("vector"); }',
        "graph:helpers/Thing3.java::Thing3.doSomething@1",
    )

    safe = FlowRefutationExpert().evaluate(_candidate(), [sink, *preserving])
    unresolved = FlowRefutationExpert().evaluate(
        _candidate(),
        [sink, *preserving, ambient_source],
    )

    assert safe.label == "SAFE"
    assert unresolved.label == "ABSTAIN"


def test_flow_refutation_does_not_turn_unresolved_taint_into_vulnerability():
    vote = FlowRefutationExpert().evaluate(
        _candidate(),
        [
            _evidence(
                'String param = request.getHeader("vector");\n'
                'String sql = "SELECT " + param;\n'
                "statement.execute(sql);"
            )
        ],
    )

    assert vote.label == "ABSTAIN"


def test_taint_tracks_list_additions_after_constant_if_branch():
    def evaluate(num: int):
        return TaintExpert().evaluate(
            _candidate(),
            [
                _evidence(
                    'String param = request.getHeader("vector");\n'
                    f"int num = {num};\n"
                    "if ((7*42) - num > 200)\n"
                    '    bar = "safe";\n'
                    "else bar = param;\n"
                    "List<String> args = new ArrayList<String>();\n"
                    'args.add("sh");\n'
                    'args.add("echo " + bar);\n'
                    "new ProcessBuilder(args);"
                )
            ],
        )

    assert evaluate(86).label == "SAFE"
    assert evaluate(96).label == "VULNERABLE"


def test_flow_refutation_tracks_list_additions_and_constant_if_branch():
    def evaluate(num: int):
        return FlowRefutationExpert().evaluate(
            _candidate(),
            [
                _evidence(
                    'String param = request.getHeader("vector");\n'
                    f"int num = {num};\n"
                    "if ((7*42) - num > 200)\n"
                    '    bar = "safe";\n'
                    "else bar = param;\n"
                    "List<String> args = new ArrayList<String>();\n"
                    'args.add("sh");\n'
                    'args.add("echo " + bar);\n'
                    "new ProcessBuilder(args);"
                )
            ],
        )

    assert evaluate(86).label == "SAFE"
    assert evaluate(96).label == "ABSTAIN"


def test_flow_refutation_ignores_sink_names_inside_string_literals():
    vote = FlowRefutationExpert().evaluate(
        _candidate(),
        [
            _evidence(
                "ProcessBuilder pb = new ProcessBuilder();\n"
                'System.out.println("ProcessBuilder(java.util.List)");'
            )
        ],
    )

    assert vote.label == "ABSTAIN"


def test_flow_refutation_models_process_builder_command_list():
    safe = FlowRefutationExpert().evaluate(
        _candidate(),
        [
            _evidence(
                "List<String> args = new ArrayList<String>();\n"
                'args.add("echo safe");\n'
                "ProcessBuilder pb = new ProcessBuilder();\n"
                "pb.command(args);"
            )
        ],
    )
    vulnerable = FlowRefutationExpert().evaluate(
        _candidate(),
        [
            _evidence(
                'String param = request.getHeader("vector");\n'
                "List<String> args = new ArrayList<String>();\n"
                "args.add(param);\n"
                "ProcessBuilder pb = new ProcessBuilder();\n"
                "pb.command(args);"
            )
        ],
    )

    assert safe.label == "SAFE"
    assert vulnerable.label == "ABSTAIN"


def test_flow_refutation_uses_last_unconditional_definition_only():
    straight_line = FlowRefutationExpert().evaluate(
        _candidate(),
        [
            _evidence(
                'String param = request.getHeader("vector");\n'
                "String bar = param;\n"
                'bar = "safe";\n'
                'String sql = "SELECT " + bar;\n'
                "statement.execute(sql);"
            )
        ],
    )
    branch_join = FlowRefutationExpert().evaluate(
        _candidate(),
        [
            _evidence(
                'String param = request.getHeader("vector");\n'
                "if (unknown > 0) bar = param;\n"
                'else bar = "safe";\n'
                'String sql = "SELECT " + bar;\n'
                "statement.execute(sql);"
            )
        ],
    )

    assert straight_line.label == "SAFE"
    assert branch_join.label == "ABSTAIN"


def test_flow_refutation_does_not_treat_xpath_document_as_expression():
    vote = FlowRefutationExpert().evaluate(
        _candidate(),
        [
            _evidence(
                'String expression = "/Employees/Employee";\n'
                "NodeList nodes = (NodeList) xp.compile(expression)"
                ".evaluate(xmlDocument, XPathConstants.NODESET);"
            )
        ],
    )

    assert vote.label == "SAFE"
