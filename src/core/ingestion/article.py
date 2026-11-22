"""Full-article text (ING-04, ING-08): hidden content is removed first, then trafilatura picks the main body."""

from __future__ import annotations

import trafilatura

from core.ingestion.cleaning import CleanedText, clean_html, clean_plain, visible_markup


def extract_article(page_html: str) -> CleanedText | None:
    """Cleaned main text of an article page, or None when no article body is found.

    Injection markers are looked for in the whole page, hidden text included (SEG-03).
    """
    suspicious_page = clean_html(page_html).is_suspicious
    body = trafilatura.extract(
        visible_markup(page_html), include_comments=False, include_tables=False, favor_precision=True
    )
    if not body:
        return None
    cleaned = clean_plain(body)
    return CleanedText(text=cleaned.text, is_suspicious=cleaned.is_suspicious or suspicious_page)
