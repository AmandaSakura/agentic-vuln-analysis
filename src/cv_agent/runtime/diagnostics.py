"""Read local CLIProxyAPI evidence without exporting raw headers or message bodies."""
import json
from pathlib import Path
import re
import time

LOG_WAIT_SECONDS = 2.0
BLOCK_REASONS = {'SAFETY', 'OTHER', 'BLOCKLIST', 'PROHIBITED_CONTENT', 'IMAGE_SAFETY',
                 'MODEL_ARMOR', 'JAILBREAK', 'SPII'}


def native_records(text):
    records = []
    generation = {}
    for section in re.split(r'^=== ', text, flags=re.MULTILINE):
        if not section.startswith(('API REQUEST', 'API RESPONSE')) or '\nBody:\n' not in section:
            continue
        payload, _ = json.JSONDecoder().raw_decode(section.split('\nBody:\n', 1)[1].strip())
        if section.startswith('API REQUEST'):
            generation = payload.get('request', {}).get('generationConfig', {})
            continue
        native = payload.get('response', {})
        response_id = native.get('responseId')
        if not isinstance(response_id, str) or not response_id:
            continue
        reason = native.get('promptFeedback', {}).get('blockReason')
        if reason == 'BLOCK_REASON_UNSPECIFIED':
            reason = None
        # Export an enum, not arbitrary provider text that could contain credentials.
        reason = reason if reason in BLOCK_REASONS else ('UNKNOWN' if reason else None)
        usage = native.get('usageMetadata', {})
        numeric = lambda value: value if type(value) is int and value >= 0 else None
        records.append(dict(response_id=response_id, block_reason=reason,
            upstream_candidate_count=len(native.get('candidates', [])),
            upstream_total_tokens=numeric(usage.get('totalTokenCount')),
            upstream_reasoning_tokens=numeric(usage.get('thoughtsTokenCount')),
            upstream_max_output_tokens=numeric(generation.get('maxOutputTokens'))))
    return records


def collect_diagnostic(directory, request_id, response_id, started_at=0):
    """Bounded wait for the current request's asynchronously written local log."""
    unavailable = dict(diagnosis='native_evidence_unavailable', request_id=request_id)
    if not isinstance(response_id, str) or not response_id:
        return unavailable
    deadline = time.monotonic() + LOG_WAIT_SECONDS
    header = re.compile(r'^X-Cv-Agent-Request-Id:\s*' + re.escape(request_id) + r'\s*$',
                        re.MULTILINE | re.IGNORECASE)
    while True:
        matches = []
        try:
            for path in Path(directory).glob('*v1-chat-completions-*.log'):
                # Filesystem timestamps can round below the request's wall-clock start.
                # This is only a scan optimization; both IDs establish the binding.
                try:
                    if path.stat().st_mtime < started_at - 1:
                        continue
                    text = path.read_text()
                except (OSError, UnicodeError):
                    # Rotation or an unrelated unreadable file must not hide
                    # another file that contains the current request's evidence.
                    continue
                request_section = text.split('=== API REQUEST', 1)[0].split('=== API RESPONSE', 1)[0]
                request_headers = request_section.split('=== REQUEST BODY', 1)[0]
                if not header.search(request_headers) or '\n=== RESPONSE ===' not in text:
                    continue
                try:
                    matches.extend(record for record in native_records(text)
                                   if record['response_id'] == response_id)
                except (ValueError, TypeError, AttributeError):
                    # Incomplete log writes are not upstream evidence.
                    continue
        except (OSError, UnicodeError):
            return unavailable
        if matches:
            if any(record != matches[0] for record in matches[1:]):
                return dict(unavailable, diagnosis='native_evidence_conflict')
            return dict(matches[0], request_id=request_id,
                        diagnosis='upstream_blocked' if matches[0]['block_reason'] else 'upstream_response')
        if time.monotonic() >= deadline:
            return unavailable
        time.sleep(0.05)
