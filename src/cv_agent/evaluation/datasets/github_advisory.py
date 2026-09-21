from __future__ import annotations

import html
import re
import time
import urllib.request
from pathlib import Path

from cv_agent.evaluation.datasets.heldout_manifest import repository_key


def fetch_advisory_html(report_id: str, source_link: str, cache_directory: Path) -> str:
    cache_directory.mkdir(parents=True, exist_ok=True)
    path = cache_directory / f"{report_id.lower()}.html"
    if path.exists():
        return path.read_text(errors="ignore")
    request = urllib.request.Request(source_link, headers={"User-Agent": "cv-agent-heldout-pair-freeze"})
    with urllib.request.urlopen(request, timeout=30) as response:
        text = response.read().decode("utf-8", errors="ignore")
    path.write_text(text)
    time.sleep(0.2)
    return text


def advisory_commit_urls(repository_url: str, html_text: str) -> tuple[str, ...]:
    urls: list[str] = []
    for pattern in (
        r'href="(https://github\.com/[^/]+/[^/]+/commit/([0-9a-f]{40}))"',
        r'href="(/[^/]+/[^/]+/commit/([0-9a-f]{40}))"',
    ):
        for match in re.finditer(pattern, html_text, re.IGNORECASE):
            url = html.unescape(match.group(1))
            if url.startswith("/"):
                url = "https://github.com" + url
            if url not in urls:
                urls.append(url)
    prefix = repository_key(repository_url).lower() + "/commit/"
    return tuple(url for url in urls if url.lower().startswith(prefix))


def advisory_versions(html_text: str) -> dict[str, str | None]:
    text = html.unescape(re.sub(r"<[^>]+>", " ", html_text))
    compact = re.sub(r"\s+", " ", text)
    affected = re.search(r"Affected versions\s+(.{0,160}?)\s+Patched versions", compact, re.I)
    patched = re.search(r"Patched versions\s+(.{0,160}?)\s+Description", compact, re.I)
    return {
        "affected_versions": affected.group(1).strip() if affected else None,
        "patched_versions": patched.group(1).strip() if patched else None,
    }
