# DeepSeek abstention audit, 2026-09-21

Reviewed run artifacts/python_heldout_pair_gate_v2/773dbc44ddc445df811b72a5c4452645. Offline only; no source changes or new API requests.

## Langflow hp002_a and hp002_b

Both E5 runs had one material scan vote and abstaining taint/authz votes. The authz tool saw only the service span. The fixed span visibly checks api_key.user_id != user_id before deletion; the vulnerable span lacks that local check. The route's identity binding was unavailable to the experts.

Two independent coverage limitations were confirmed:

1. python_ast._module_names removes at most the src prefix. For src/backend/base/langflow/services/database/models/api_key/crud.py it produces src.backend.base.langflow... and backend.base.langflow... definitions, whereas the route calls langflow.services.database.models.api_key.crud.delete_api_key. The qualified edge is absent. A two-file offline parse of the actual vulnerable route and service reproduced this mismatch. Parsing the same source with paths relative to src/backend/base restored the reverse edge to delete_api_key_route. Repository source files were not altered.
2. RepositoryIndex.retrieve_with_budget calls graph_search with its default forward direction. The candidate is the service, and the route is its caller. Even with correct package resolution, forward search will not retrieve this route; the minimal reproduction had an empty service forward adjacency and a nonempty reverse adjacency after package normalization.

These findings justify package-root-aware symbol resolution and an explicitly versioned retrieval policy that admits upstream callers within the existing budget. Arbitrary suffix matching could create false cross-package edges and must not be used. Changing graph direction changes the experiment protocol, so results need new protocol identification rather than an implicit alteration of the frozen run.

## MLflow hp003_a

Both command inspector calls returned helper status UNSANITIZED, but the actual subprocess.Popen sink and aggregate status were AMBIGUOUS. Taint tracing returned NOT_ESTABLISHED. The scan expert made an UNRESOLVED vulnerability prediction; the taint expert abstained because sink reachability was not established. The authz expert considered the candidate outside its specialty.

The supplied tool evidence therefore does not justify forcing a second vulnerability vote or claiming concrete confirmation. The next investigation should isolate the command interpreter's unknown bindings/branch handling using a minimal reproduction, preserving sanitized and unrelated-helper controls. This audit does not establish a specific interpreter bug as the cause.

## Interpretation

The gate's abstentions expose evidence coverage and bounded-analysis limitations, not merely JSON formatting. The fixed Langflow guard may support SAFE/UNRESOLVED, but the expert's concern about the caller's principal binding is not disproved by the present context. Keep two-vote quorum and permit abstention. Do not tune the prompt toward known labels. Past runs remain unchanged and non-accepted.
