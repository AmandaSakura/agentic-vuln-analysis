from cv_agent.python_heldout_pair_config import PythonHeldoutPairExperimentConfig
from cv_agent.python_heldout_pair_source import build_pair_input, document_symbol

from test_python_heldout_pair_config import config_dict


def test_explicit_import_root_links_callers_without_changing_source_paths(tmp_path):
    checkout = tmp_path / "checkout"
    package = checkout / "src/backend/base/example"
    package.mkdir(parents=True)
    (package / "service.py").write_text("# service\ndef remove(key):\n    return key\n")
    (package / "route.py").write_text(
        "from example.service import remove\n"
        "def route(key):\n    return remove(key)\n"
        "from external.service import remove as external_remove\n"
        "def unrelated(key):\n    return external_remove(key)\n"
    )
    data = config_dict()
    pair = data["pairs"][0]
    pair["python_import_root"] = "src/backend/base"
    for case in pair["cases"]:
        case.update(checkout="checkout", file_path="src/backend/base/example/service.py", line_hint=2)
    config = PythonHeldoutPairExperimentConfig.model_validate(data)
    index, candidate, hashes = build_pair_input(tmp_path, config.pairs[0], config.pairs[0].cases[0])
    callers = index.graph_neighbors(candidate.path, direction="reverse")
    assert len(callers) == 1
    assert callers[0].startswith("src/backend/base/example/route.py::route@")
    assert candidate.path.startswith("src/backend/base/example/service.py::remove@")
    assert "src/backend/base/example/service.py" in hashes
    legacy_pair = config.pairs[0].model_copy(update={"python_import_root": None})
    legacy, legacy_candidate, _ = build_pair_input(tmp_path, legacy_pair, legacy_pair.cases[0])
    assert legacy.graph_neighbors(legacy_candidate.path, direction="reverse") == ()


def test_source_builder_selects_span_containing_critical_line(tmp_path):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "example.py").write_text(
        "def harmless():\n"
        "    return 1\n"
        "\n"
        "def risky(value):\n"
        "    return eval(value)\n"
    )
    data = config_dict()
    data["pairs"][0]["cases"][0]["checkout"] = checkout.relative_to(tmp_path).as_posix()
    data["pairs"][0]["cases"][0]["line_hint"] = 5
    data["pairs"][0]["cases"][1]["line_hint"] = 5
    data["pairs"][0]["critical_operation"]["line"] = 5
    config = PythonHeldoutPairExperimentConfig.model_validate(data)

    index, candidate, source_sha256 = build_pair_input(tmp_path, config.pairs[0], config.pairs[0].cases[0])

    assert candidate.case_id == "hp001_a"
    assert candidate.path.startswith("example.py::risky@")
    assert candidate.line == 4
    assert "example.py" in source_sha256
    assert index.documents[candidate.path].repository_id == "hp001_a"


def test_fixed_side_prefers_vulnerable_symbol_over_stale_line_hint(tmp_path):
    vulnerable = tmp_path / "vulnerable"
    fixed = tmp_path / "fixed"
    vulnerable.mkdir()
    fixed.mkdir()
    (vulnerable / "example.py").write_text(
        "def target(value):\n"
        "    return eval(value)\n"
        "\n"
        "def other(value):\n"
        "    return value\n"
    )
    (fixed / "example.py").write_text(
        "def other(value):\n"
        "    return value\n"
        "\n"
        "def target(value):\n"
        "    return value\n"
    )
    data = config_dict()
    data["pairs"][0]["cases"][0]["checkout"] = vulnerable.relative_to(tmp_path).as_posix()
    data["pairs"][0]["cases"][1]["checkout"] = fixed.relative_to(tmp_path).as_posix()
    data["pairs"][0]["cases"][0]["line_hint"] = 2
    data["pairs"][0]["cases"][1]["line_hint"] = 2
    config = PythonHeldoutPairExperimentConfig.model_validate(data)

    _, vulnerable_candidate, _ = build_pair_input(tmp_path, config.pairs[0], config.pairs[0].cases[0])
    _, fixed_candidate, _ = build_pair_input(
        tmp_path,
        config.pairs[0],
        config.pairs[0].cases[1],
        preferred_symbol=document_symbol(vulnerable_candidate.path),
    )

    assert vulnerable_candidate.path.startswith("example.py::target@")
    assert fixed_candidate.path.startswith("example.py::target@")
    assert fixed_candidate.line == 4


def test_source_builder_indexes_security_config_files_for_retrieval(tmp_path):
    checkout = tmp_path / "checkout"
    auth_dir = checkout / "mlflow/server/auth"
    auth_dir.mkdir(parents=True)
    (auth_dir / "__init__.py").write_text(
        "def _before_request():\n"
        "    if sender_is_admin():\n"
        "        return\n"
    )
    (auth_dir / "basic_auth.ini").write_text(
        "[mlflow]\n"
        "admin_username = admin\n"
        "admin_password = password\n"
    )
    data = config_dict()
    pair = data["pairs"][0]
    pair["vulnerability_title"] = "Hardcoded default admin password"
    pair["source_scope"] = (
        "default credentials at mlflow/server/auth/basic_auth.ini:3; "
        "guard at mlflow/server/auth/__init__.py:2"
    )
    pair["analysis_scope"] = "Entry point code: admin_password = password."
    pair["cases"][0]["checkout"] = checkout.relative_to(tmp_path).as_posix()
    pair["cases"][0]["file_path"] = "mlflow/server/auth/__init__.py"
    pair["cases"][0]["line_hint"] = 2
    pair["cases"][1]["file_path"] = "mlflow/server/auth/__init__.py"
    pair["critical_operation"]["file"] = "mlflow/server/auth/__init__.py"
    config = PythonHeldoutPairExperimentConfig.model_validate(data)

    index, candidate, source_sha256 = build_pair_input(tmp_path, config.pairs[0], config.pairs[0].cases[0])
    hits = index.text_search(candidate.query, top_k=5)

    assert "mlflow/server/auth/basic_auth.ini" in source_sha256
    config_doc = index.document("mlflow/server/auth/basic_auth.ini::<file>@1-3")
    assert config_doc is not None
    assert config_doc.language == "text"
    assert config_doc.adapter_tier == "fallback"
    assert any(item.path == config_doc.path for item in hits)


def test_source_builder_keeps_rich_query_but_neutralizes_model_scope(tmp_path):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "example.py").write_text(
        "def delete_api_key(api_key, user_id):\n"
        "    if api_key.user_id != user_id:\n"
        "        raise ValueError('not found')\n"
        "    return session.delete(api_key)\n"
    )
    data = config_dict()
    pair = data["pairs"][0]
    pair["vulnerability_title"] = "CVE advisory IDOR exploit title"
    pair["source_scope"] = "IDOR at example.py:4; entry example.py:1"
    pair["analysis_scope"] = "Assess the advisory vulnerability and CVE details."
    pair["entry_point"] = {
        "file": "example.py",
        "line": 1,
        "code": "def delete_api_key(api_key, user_id):",
        "desc": "entry",
    }
    pair["critical_operation"] = {
        "file": "example.py",
        "line": 4,
        "code": "session.delete(api_key)",
        "desc": "operation",
    }
    pair["cases"][0]["checkout"] = checkout.relative_to(tmp_path).as_posix()
    pair["cases"][0]["file_path"] = "example.py"
    pair["cases"][0]["line_hint"] = 4
    pair["cases"][1]["file_path"] = "example.py"
    config = PythonHeldoutPairExperimentConfig.model_validate(data)

    _, candidate, _ = build_pair_input(tmp_path, config.pairs[0], config.pairs[0].cases[0])

    assert "CVE advisory IDOR exploit title" in candidate.query
    assert candidate.analysis_scope is not None
    assert "CVE" not in candidate.analysis_scope
    assert "IDOR" not in candidate.analysis_scope
    assert "advisory" not in candidate.analysis_scope
    assert "example.py:4" not in candidate.analysis_scope
    assert "session.delete(api_key)" in candidate.analysis_scope
    assert "tool-readable paths" in candidate.analysis_scope


def test_source_builder_skips_large_fallback_text_assets(tmp_path):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "example.py").write_text("def entry():\n    return 1\n")
    (checkout / "settings.ini").write_text("[auth]\nowner_check = true\n")
    (checkout / "component_index.json").write_text(
        "{\"entries\":\"" + ("delete api key " * 6000) + "\"}\n"
    )
    data = config_dict()
    pair = data["pairs"][0]
    pair["cases"][0]["checkout"] = checkout.relative_to(tmp_path).as_posix()
    pair["cases"][0]["file_path"] = "example.py"
    pair["cases"][0]["line_hint"] = 2
    pair["cases"][1]["file_path"] = "example.py"
    pair["critical_operation"]["file"] = "example.py"
    pair["critical_operation"]["line"] = 2
    config = PythonHeldoutPairExperimentConfig.model_validate(data)

    index, candidate, source_sha256 = build_pair_input(tmp_path, config.pairs[0], config.pairs[0].cases[0])
    hits = index.text_search("delete api key", top_k=5)

    assert "settings.ini" in source_sha256
    assert "component_index.json" not in source_sha256
    assert not any(item.path.startswith("component_index.json::") for item in hits)
