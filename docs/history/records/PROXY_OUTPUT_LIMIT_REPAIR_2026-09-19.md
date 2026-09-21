# CLIProxyAPI output limit repair — reviewable deployment

## Prepared implementation

Base: CLIProxyAPI v7.3.6, commit `8c664b2fede5c83b919be1df9b01057ec4e4c950`.
Patch: `docs/patches/cliproxyapi-v7.3.6-preserve-output-limit.patch`.
Build: `artifacts/proxy_output_limit_repair_2026-09-19/cli-proxy-api`.
Build version: `7.3.6-cv-agent-output-limit`.

The executor capped the requested output limit against the model registry, then
deleted it in both non-Claude branches. The patch removes only those deletions.
It preserves the registry cap, schema processing and Claude handling. Regression
tests cover Gemini and Claude, tools and no tools, and omitted limits.

Verified offline with isolated Go 1.26.0 downloaded from go.dev and checked
against the published SHA256. New Gemini preservation tests fail on the original
executor and pass after repair. All `TestAntigravityBuildRequest*` tests pass;
`go build ./cmd/server` succeeds. These are targeted tests and a build, not a
claim that the entire proxy test suite or Google acceptance has been verified.
Logs and `SHA256SUMS` are beside the binary. The original executable was backed
up and the prepared build installed; systemd reports active, and its installed
SHA256 matches the staged artifact. No model calls were made to verify upstream.

## Completed deployment and available rollback

Artifact verification, completed from the cv_agent repository root:

```sh
sha256sum --check artifacts/proxy_output_limit_repair_2026-09-19/SHA256SUMS
```

Completed installation commands, preserved as a record (do not overwrite the backup):

```sh
# test ! -e /home/joker/.local/share/cliproxyapi/cli-proxy-api.before-output-limit-20260919
# cp -p /home/joker/.local/share/cliproxyapi/cli-proxy-api /home/joker/.local/share/cliproxyapi/cli-proxy-api.before-output-limit-20260919
# install -m 755 artifacts/proxy_output_limit_repair_2026-09-19/cli-proxy-api /home/joker/.local/share/cliproxyapi/cli-proxy-api.new
# mv /home/joker/.local/share/cliproxyapi/cli-proxy-api.new /home/joker/.local/share/cliproxyapi/cli-proxy-api
# systemctl --user restart cliproxyapi
# systemctl --user is-active cliproxyapi
```

Rollback uses the preserved binary, with no credential/configuration changes:

```sh
set -e
install -m 755 /home/joker/.local/share/cliproxyapi/cli-proxy-api.before-output-limit-20260919 /home/joker/.local/share/cliproxyapi/cli-proxy-api.restore
mv /home/joker/.local/share/cliproxyapi/cli-proxy-api.restore /home/joker/.local/share/cliproxyapi/cli-proxy-api
systemctl --user restart cliproxyapi
```

Service liveness is not model validation. A separately authorized bounded live
check must show the requested limit in the correlated native request, valid
structured responses and usage. The existing 1,200-token setting may truncate
some multi-step responses once it actually reaches upstream; do not silently
raise it or reinterpret old runs as having that enforced budget.

Google `OTHER` filtering is a separate issue. No safety setting or filter is
changed by this patch, and no promise is made that it removes such blocks.
