from __future__ import annotations

from .retrieval import RepositoryIndex
from .types import Candidate, CodeDocument


def cross_file_fixture() -> tuple[RepositoryIndex, Candidate]:
    documents = [
        CodeDocument(
            repository_id="cross-file",
            path="controller.py",
            text="def handle(request):\n    command = request.args['cmd']\n    return run_command(command)\n",
            defines=("handle",),
            calls=("run_command",),
        ),
        CodeDocument(
            repository_id="cross-file",
            path="service.py",
            text="import subprocess\ndef run_command(command):\n    return subprocess.run(command, shell=True)\n",
            defines=("run_command",),
            calls=(),
        ),
    ]
    candidate = Candidate(
        candidate_id="cross-file-1",
        case_id="cross-file-1",
        repository_id="cross-file",
        path="controller.py",
        line=1,
        query="request handler",
    )
    return RepositoryIndex(documents), candidate


def guarded_delete_fixture() -> tuple[RepositoryIndex, Candidate]:
    document = CodeDocument(
        repository_id="guarded-delete",
        path="admin.py",
        text="def delete_user(actor, user_id):\n    require_permission(actor, 'delete_user')\n    return database.delete(user_id)\n",
        defines=("delete_user",),
        calls=(),
    )
    candidate = Candidate(
        candidate_id="guarded-delete-1",
        case_id="guarded-delete-1",
        repository_id="guarded-delete",
        path="admin.py",
        line=1,
        query="delete user admin",
    )
    return RepositoryIndex([document]), candidate
