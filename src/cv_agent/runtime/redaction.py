"""Display-only redaction; authoritative source bytes and hashes stay intact."""
import re


_LABELED_SECRET = re.compile(
    r"(?i)((?:api[_ -]?key|password|access[_ -]?token|secret|authorization)\s*[:=]\s*)"
    r"(?:Bearer\s+)?(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)


def redact_public_text(text: str) -> str:
    return _LABELED_SECRET.sub(lambda matched: matched.group(1) + "[REDACTED]", text)
