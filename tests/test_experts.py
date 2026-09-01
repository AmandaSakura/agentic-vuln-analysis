from cv_agent.experts import AuthorizationExpert, ScanExpert, TaintExpert
from cv_agent.types import Candidate, Evidence


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
