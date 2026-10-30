"""Report ingestion: read .txt / .md / .html / .pdf and split into chunks for Agent 1."""
from __future__ import annotations

import html
import io
import re
from pathlib import Path


def html_to_text(raw: str) -> str:
    raw = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", raw)
    raw = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</li>|</h[1-6]>|</tr>", "\n", raw)
    raw = re.sub(r"<[^>]+>", " ", raw)
    text = html.unescape(raw)
    return re.sub(r"[ \t]+", " ", re.sub(r"\n\s*\n+", "\n\n", text)).strip()


def pdf_to_text(data: bytes) -> str:
    from pypdf import PdfReader
    reader = PdfReader(io.BytesIO(data))
    return "\n\n".join((page.extract_text() or "") for page in reader.pages).strip()


def read_document(path: str | Path | None = None, data: bytes | None = None, filename: str = "") -> str:
    if path is not None:
        path = Path(path)
        data = path.read_bytes()
        filename = filename or path.name
    if data is None:
        raise ValueError("no document data")
    name = filename.lower()
    if name.endswith(".pdf") or data[:5] == b"%PDF-":
        return pdf_to_text(data)
    text = data.decode("utf-8", errors="ignore")
    if name.endswith((".html", ".htm")) or re.search(r"(?i)<html|<body|<p>", text[:2000]):
        return html_to_text(text)
    return text.strip()


def chunk_text(text: str, max_chars: int = 2500, overlap: int = 200) -> list[str]:
    """Split on paragraph boundaries into chunks of at most ~max_chars, with a small overlap."""
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    chunks: list[str] = []
    current = ""
    for para in paragraphs:
        while len(para) > max_chars:                       # very long paragraph: hard split
            head, para = para[:max_chars], para[max_chars - overlap:]
            if current:
                chunks.append(current)
                current = ""
            chunks.append(head)
        if len(current) + len(para) + 2 <= max_chars:
            current = f"{current}\n\n{para}" if current else para
        else:
            if current:
                chunks.append(current)
            tail = current[-overlap:] if current and overlap else ""
            current = f"{tail}\n\n{para}".strip() if tail else para
    if current:
        chunks.append(current)
    return chunks or [text[:max_chars]]
