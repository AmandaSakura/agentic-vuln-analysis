from pathlib import Path

from cv_agent.code_adapters import load_code_repository
from cv_agent.retrieval import RepositoryIndex
from cv_agent.types import Candidate


def _candidate(span) -> Candidate:
    return Candidate(
        candidate_id=span.document.path,
        case_id=span.document.path,
        repository_id=span.document.repository_id,
        path=span.document.path,
        line=span.start_line,
        query=" ".join([*span.document.defines, *span.document.calls]),
    )


def test_typescript_ast_resolves_named_import_alias_across_files(tmp_path: Path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "controller.ts").write_text(
        "import { runCommand as execute } from './service';\n"
        "export async function handle(request: Request) {\n"
        "  return execute(request.query.command);\n"
        "}\n",
        encoding="utf-8",
    )
    (source / "service.ts").write_text(
        "export function runCommand(command: string) {\n"
        "  return exec(command);\n"
        "}\n",
        encoding="utf-8",
    )
    distractor = source / "other"
    distractor.mkdir()
    (distractor / "service.ts").write_text(
        "export function runCommand(command: string) {\n"
        "  return unrelated(command);\n"
        "}\n",
        encoding="utf-8",
    )

    repository = load_code_repository("repo", tmp_path)
    entry = repository.locate("src/controller.ts", 2)
    target = repository.locate("src/service.ts", 1)
    unrelated = repository.locate("src/other/service.ts", 1)

    assert repository.parse_error_paths == ()
    assert repository.language_file_counts == {"typescript": 3}
    assert repository.adapter_tier_file_counts == {"ast": 3}
    assert entry is not None
    assert target is not None
    assert unrelated is not None
    assert entry.document.language == "typescript"
    assert "./service" in entry.document.imports
    assert "service.runCommand" in entry.document.calls
    assert "service.runCommand" in target.document.defines

    graph = RepositoryIndex(repository.documents).graph_search(
        _candidate(entry),
        top_k=8,
        max_hops=4,
    )
    assert any(item.path == target.document.path for item in graph)
    assert all(item.path != unrelated.document.path for item in graph)


def test_javascript_default_and_require_member_imports_reach_exact_exports(
    tmp_path: Path,
):
    (tmp_path / "default_controller.js").write_text(
        "import execute from './default_service';\n"
        "export function handle(value) { return execute(value); }\n",
        encoding="utf-8",
    )
    (tmp_path / "default_service.js").write_text(
        "export default function run(value) { return eval(value); }\n",
        encoding="utf-8",
    )
    (tmp_path / "member_controller.js").write_text(
        "const invoke = require('./member_service').run;\n"
        "function handleMember(value) { return invoke(value); }\n",
        encoding="utf-8",
    )
    (tmp_path / "member_service.js").write_text(
        "function run(value) { return eval(value); }\n"
        "exports.run = run;\n",
        encoding="utf-8",
    )

    repository = load_code_repository("repo", tmp_path)
    default_entry = repository.locate("default_controller.js", 2)
    default_target = repository.locate("default_service.js", 1)
    member_entry = repository.locate("member_controller.js", 2)
    member_target = repository.locate("member_service.js", 1)

    assert default_entry is not None
    assert default_target is not None
    assert member_entry is not None
    assert member_target is not None
    assert "default_service.default" in default_entry.document.calls
    assert "default_service.default" in default_target.document.defines
    assert "member_service.run" in member_entry.document.calls
    assert "member_service.run" in member_target.document.defines

    index = RepositoryIndex(repository.documents)
    default_graph = index.graph_search(
        _candidate(default_entry),
        top_k=8,
        max_hops=4,
    )
    member_graph = index.graph_search(
        _candidate(member_entry),
        top_k=8,
        max_hops=4,
    )
    assert any(item.path == default_target.document.path for item in default_graph)
    assert any(item.path == member_target.document.path for item in member_graph)


def test_javascript_function_ids_are_unique_for_same_line_route_callbacks(
    tmp_path: Path,
):
    (tmp_path / "routes.js").write_text(
        "router.get('/a', () => one()); router.get('/b', () => two());\n",
        encoding="utf-8",
    )

    repository = load_code_repository("repo", tmp_path)
    route_documents = [
        document for document in repository.documents if document.routes
    ]

    assert len(route_documents) == 2
    assert len({document.path for document in route_documents}) == 2
    RepositoryIndex(repository.documents)


def test_javascript_object_and_class_field_arrows_and_named_routes(
    tmp_path: Path,
):
    (tmp_path / "handlers.js").write_text(
        "const handlers = { run: (value) => dangerous(value) };\n"
        "class Controller { field = (value) => dangerous(value); }\n"
        "function namedHandler(req) { return handlers.run(req.body); }\n"
        "router.post('/named', namedHandler);\n",
        encoding="utf-8",
    )

    repository = load_code_repository("repo", tmp_path)
    object_arrow = repository.locate("handlers.js", 1)
    class_arrow = repository.locate("handlers.js", 2)
    named_handler = repository.locate("handlers.js", 3)

    assert object_arrow is not None
    assert class_arrow is not None
    assert named_handler is not None
    assert "run" in object_arrow.document.defines
    assert "Controller.field" in class_arrow.document.defines
    assert named_handler.document.routes == ("POST:/named",)


def test_javascript_ast_indexes_express_route_guard_and_commonjs_edge(tmp_path: Path):
    (tmp_path / "controller.js").write_text(
        "const { run: execute } = require('./service');\n"
        "router.post('/run', async (req, res) => {\n"
        "  authorize(req.user);\n"
        "  return execute(req.body.command);\n"
        "});\n",
        encoding="utf-8",
    )
    (tmp_path / "service.js").write_text(
        "function run(command) {\n"
        "  return eval(command);\n"
        "}\n"
        "module.exports = { run };\n",
        encoding="utf-8",
    )

    repository = load_code_repository("repo", tmp_path)
    entry = repository.locate("controller.js", 3)
    target = repository.locate("service.js", 1)

    assert entry is not None
    assert target is not None
    assert entry.document.routes == ("POST:/run",)
    assert "authorize" in entry.document.guards
    assert "service.run" in entry.document.calls
    assert "service.run" in target.document.defines

    graph = RepositoryIndex(repository.documents).graph_search(
        _candidate(entry),
        top_k=8,
        max_hops=4,
    )
    assert any(item.path == target.document.path for item in graph)


def test_go_ast_resolves_import_alias_and_typed_receiver_calls(tmp_path: Path):
    controller = tmp_path / "controller"
    service = tmp_path / "service"
    controller.mkdir()
    service.mkdir()
    (controller / "handler.go").write_text(
        "package controller\n\n"
        "import svc \"example.com/project/service\"\n\n"
        "func Handle(value string) error {\n"
        "  return svc.Run(value)\n"
        "}\n\n"
        "func Dispatch(service *svc.Service, value string) error {\n"
        "  return service.Execute(value)\n"
        "}\n\n"
        "func Build(value string) error {\n"
        "  service := svc.NewService()\n"
        "  return service.Execute(value)\n"
        "}\n",
        encoding="utf-8",
    )
    (service / "service.go").write_text(
        "package service\n\n"
        "type Service struct{}\n\n"
        "func Run(value string) error {\n"
        "  return dangerous(value)\n"
        "}\n\n"
        "func (service *Service) Execute(value string) error {\n"
        "  return Run(value)\n"
        "}\n\n"
        "func Dispatch(service *Service, value string) error {\n"
        "  return service.Execute(value)\n"
        "}\n",
        encoding="utf-8",
    )

    repository = load_code_repository("repo", tmp_path)
    entry = repository.locate("controller/handler.go", 5)
    qualified_dispatch = repository.locate("controller/handler.go", 9)
    constructed_dispatch = repository.locate("controller/handler.go", 13)
    target = repository.locate("service/service.go", 5)
    dispatch = repository.locate("service/service.go", 13)
    method = repository.locate("service/service.go", 9)

    assert repository.parse_error_paths == ()
    assert repository.language_file_counts == {"go": 2}
    assert entry is not None
    assert qualified_dispatch is not None
    assert constructed_dispatch is not None
    assert target is not None
    assert dispatch is not None
    assert method is not None
    assert "service.Run" in entry.document.calls
    assert "service.Run" in target.document.defines
    assert "Service.Execute" in qualified_dispatch.document.calls
    assert "Service.Execute" in constructed_dispatch.document.calls
    assert "Service.Execute" in dispatch.document.calls
    assert "Service.Execute" in method.document.defines

    graph = RepositoryIndex(repository.documents).graph_search(
        _candidate(entry),
        top_k=8,
        max_hops=4,
    )
    qualified_graph = RepositoryIndex(repository.documents).graph_search(
        _candidate(qualified_dispatch),
        top_k=8,
        max_hops=4,
    )
    constructed_graph = RepositoryIndex(repository.documents).graph_search(
        _candidate(constructed_dispatch),
        top_k=8,
        max_hops=4,
    )
    assert any(item.path == target.document.path for item in graph)
    assert any(item.path == method.document.path for item in qualified_graph)
    assert any(item.path == method.document.path for item in constructed_graph)


def test_fallback_files_are_labeled_and_never_described_as_ast(tmp_path: Path):
    (tmp_path / "policy.yaml").write_text(
        "admin:\n  can_delete: true\n",
        encoding="utf-8",
    )
    (tmp_path / "component.jsx").write_text(
        "export const Button = () => <button />;\n",
        encoding="utf-8",
    )

    repository = load_code_repository("repo", tmp_path)
    span = repository.locate("policy.yaml", 2)
    jsx = repository.locate("component.jsx", 1)

    assert span is not None
    assert jsx is not None
    assert span.language == "yaml"
    assert span.adapter_tier == "fallback"
    assert span.document.adapter_tier == "fallback"
    assert jsx.language == "jsx"
    assert jsx.adapter_tier == "fallback"
    assert repository.language_file_counts == {"jsx": 1, "yaml": 1}
    assert repository.adapter_tier_file_counts == {"fallback": 2}


def test_loader_excludes_dependency_and_build_directories(tmp_path: Path):
    (tmp_path / "main.ts").write_text(
        "export function main() { return 1; }\n",
        encoding="utf-8",
    )
    dependency = tmp_path / "node_modules" / "package"
    dependency.mkdir(parents=True)
    (dependency / "hidden.ts").write_text(
        "export function hidden() { return 2; }\n",
        encoding="utf-8",
    )

    repository = load_code_repository("repo", tmp_path)

    assert repository.source_file_count == 1
    assert all("node_modules" not in span.relative_path for span in repository.spans)


def test_parse_failures_remain_in_language_and_tier_denominators(tmp_path: Path):
    (tmp_path / "broken.py").write_text(
        "def broken(:\n    pass\n",
        encoding="utf-8",
    )

    repository = load_code_repository("repo", tmp_path)

    assert repository.source_file_count == 1
    assert repository.parse_error_paths == ("broken.py",)
    assert repository.language_file_counts == {"python": 1}
    assert repository.adapter_tier_file_counts == {"ast": 1}
    assert sum(repository.language_file_counts.values()) == repository.source_file_count
    assert sum(repository.adapter_tier_file_counts.values()) == repository.source_file_count
