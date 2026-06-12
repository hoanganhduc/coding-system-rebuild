"""Translation Server client with auto-detect for DOI/arXiv/URL/ISBN."""

import re
import json
import subprocess

import requests

# Patterns for input type detection
DOI_PATTERN = re.compile(r"^10\.\d{4,9}/[^\s]+$")
DOI_URL_PATTERN = re.compile(r"https?://(?:dx\.)?doi\.org/(10\.\d{4,9}/[^\s]+)")
ARXIV_PATTERN = re.compile(r"^(?:arXiv:)?(\d{4}\.\d{4,5}(?:v\d+)?)$", re.IGNORECASE)
ARXIV_URL_PATTERN = re.compile(r"https?://arxiv\.org/(?:abs|pdf)/(\d{4}\.\d{4,5}(?:v\d+)?)")
ARXIV_OLD_PATTERN = re.compile(r"^(?:arXiv:)?([a-z-]+/\d{7}(?:v\d+)?)$", re.IGNORECASE)
ISBN_PATTERN = re.compile(r"^(?:ISBN[:\s-]?)?([\d-]{10,17}[X]?)$", re.IGNORECASE)
URL_PATTERN = re.compile(r"^https?://")


def detect_input_type(identifier):
    """Detect input type and normalize. Returns (type, normalized_value).

    Types: 'doi', 'arxiv', 'isbn', 'url'
    """
    identifier = identifier.strip()

    # DOI URL → extract DOI
    m = DOI_URL_PATTERN.match(identifier)
    if m:
        return "doi", m.group(1)

    # arXiv URL → extract ID
    m = ARXIV_URL_PATTERN.match(identifier)
    if m:
        return "arxiv", m.group(1)

    # Bare DOI
    if DOI_PATTERN.match(identifier):
        return "doi", identifier

    # arXiv ID (new format: 2301.12345)
    m = ARXIV_PATTERN.match(identifier)
    if m:
        return "arxiv", m.group(1)

    # arXiv ID (old format: math/0601001)
    m = ARXIV_OLD_PATTERN.match(identifier)
    if m:
        return "arxiv", m.group(1)

    # ISBN
    m = ISBN_PATTERN.match(identifier)
    if m:
        isbn = re.sub(r"[^0-9X]", "", m.group(1).upper())
        return "isbn", isbn

    # Generic URL
    if URL_PATTERN.match(identifier):
        return "url", identifier

    # Fallback: try as DOI if it contains a slash
    if "/" in identifier and not identifier.startswith("http"):
        return "doi", identifier

    return "unknown", identifier


def fetch_metadata(identifier, translation_server="http://localhost:1969"):
    """Fetch Zotero-native metadata via Translation Server.

    Returns (metadata_dict, input_type, normalized_id) or raises.
    """
    input_type, normalized = detect_input_type(identifier)

    # Build the URL to send to Translation Server
    if input_type == "doi":
        lookup_url = f"https://doi.org/{normalized}"
    elif input_type == "arxiv":
        lookup_url = f"https://arxiv.org/abs/{normalized}"
    elif input_type == "isbn":
        lookup_url = f"https://www.worldcat.org/isbn/{normalized}"
    elif input_type == "url":
        lookup_url = normalized
    else:
        raise ValueError(f"Cannot determine identifier type for: {identifier}")

    # Health check (try configured URL, fall back to localhost if host.docker.internal fails)
    server_ok = False
    try:
        requests.get(translation_server, timeout=5)
        server_ok = True
    except (requests.ConnectionError, ConnectionError):
        if "host.docker.internal" in translation_server:
            fallback = translation_server.replace("host.docker.internal", "localhost")
            try:
                requests.get(fallback, timeout=5)
                translation_server = fallback
                server_ok = True
            except (requests.ConnectionError, ConnectionError):
                pass
    if not server_ok:
        raise ConnectionError(
            f"Translation Server unreachable at {translation_server}. "
            "Run on host: cd ~/.openclaw/workspace/skills/zotero && docker compose up -d"
        )

    # Fetch metadata
    headers = {"Content-Type": "text/plain"}
    try:
        resp = requests.post(
            f"{translation_server}/web",
            data=lookup_url,
            headers=headers,
            timeout=30,
        )
    except requests.Timeout:
        raise TimeoutError(f"Translation Server timed out for {lookup_url}")

    if resp.status_code == 501:
        raise ValueError(f"Translation Server could not process: {lookup_url} (no translator found)")
    if resp.status_code != 200:
        raise RuntimeError(f"Translation Server returned {resp.status_code} for {lookup_url}")

    items = resp.json()
    if not items:
        raise ValueError(f"Translation Server returned empty result for {lookup_url}")

    metadata = items[0]

    # Extract DOI and arXiv ID from metadata if present
    doi = metadata.get("DOI", "")
    arxiv_id = ""
    if input_type == "arxiv":
        arxiv_id = normalized
    elif doi and doi.startswith("10.48550/arXiv."):
        arxiv_id = doi.replace("10.48550/arXiv.", "")

    # Normalize itemType: preprints, manuscripts, author self-published → "Manuscript"
    item_type = metadata.get("itemType", "")
    if item_type == "preprint" or input_type == "arxiv":
        metadata["itemType"] = "manuscript"

    metadata["_input_type"] = input_type
    metadata["_normalized_id"] = normalized
    metadata["_arxiv_id"] = arxiv_id

    return metadata, input_type, normalized


# ---------------------------------------------------------------------------
# Auto DOI extraction from PDF via getscipapers CLI
# ---------------------------------------------------------------------------

_DOI_OUTPUT_RE = re.compile(r"Extracted DOI from PDF:\s*(\S+)")


def extract_doi_from_pdf(pdf_path, timeout=30):
    """Extract DOI from a PDF via getscipapers CLI.

    Shells out to ``getscipapers getpapers --extract-doi-from-pdf`` with a
    timeout.  Returns the DOI string or None.
    """
    try:
        result = subprocess.run(
            ["getscipapers", "getpapers", "--extract-doi-from-pdf", pdf_path],
            capture_output=True, text=True, timeout=timeout,
        )
        for line in result.stdout.splitlines():
            m = _DOI_OUTPUT_RE.search(line)
            if m:
                return m.group(1).rstrip(".")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return None


# CrossRef type → Zotero itemType
_CROSSREF_TYPE_MAP = {
    "journal-article": "journalArticle",
    "proceedings-article": "conferencePaper",
    "book": "book",
    "book-chapter": "bookSection",
    "monograph": "book",
    "reference-book": "book",
    "posted-content": "manuscript",
    "report": "report",
    "dissertation": "thesis",
    "dataset": "document",
    "peer-review": "journalArticle",
    "edited-book": "book",
    "reference-entry": "encyclopediaArticle",
}

_JATS_TAG_RE = re.compile(r"</?jats:[^>]+>")


def crossref_to_zotero(data):
    """Convert a CrossRef works response (the *message* dict) to Zotero metadata."""
    # itemType
    cr_type = data.get("type", "")
    item_type = _CROSSREF_TYPE_MAP.get(cr_type, "journalArticle")
    if item_type == "manuscript" or cr_type == "posted-content":
        item_type = "manuscript"

    # title
    titles = data.get("title") or []
    title = titles[0] if titles else "Unknown"

    # creators
    creators = []
    for author in data.get("author") or []:
        given = author.get("given", "")
        family = author.get("family", "")
        if given and family:
            creators.append({"creatorType": "author", "firstName": given, "lastName": family})
        elif family:
            creators.append({"creatorType": "author", "name": family})

    # date
    date = ""
    parts = (data.get("issued") or {}).get("date-parts") or []
    if parts and parts[0]:
        dp = parts[0]
        if len(dp) >= 3:
            date = f"{dp[0]}-{dp[1]:02d}-{dp[2]:02d}"
        elif len(dp) >= 2:
            date = f"{dp[0]}-{dp[1]:02d}"
        elif len(dp) >= 1:
            date = str(dp[0])

    # container / publication
    containers = data.get("container-title") or []
    publication = containers[0] if containers else ""

    # abstract (strip JATS XML tags)
    abstract = data.get("abstract") or ""
    if abstract:
        abstract = _JATS_TAG_RE.sub("", abstract).strip()

    meta = {
        "itemType": item_type,
        "title": title,
        "creators": creators,
        "date": date,
        "DOI": data.get("DOI", ""),
        "abstractNote": abstract,
        "publicationTitle": publication,
        "volume": data.get("volume", ""),
        "issue": data.get("issue", ""),
        "pages": data.get("page", ""),
        "url": data.get("URL", ""),
        "language": data.get("language", ""),
    }

    # Optional fields
    issns = data.get("ISSN") or []
    if issns:
        meta["ISSN"] = issns[0]
    isbns = data.get("ISBN") or []
    if isbns:
        meta["ISBN"] = isbns[0]
    if data.get("publisher"):
        meta["publisher"] = data["publisher"]

    return meta


def fetch_metadata_for_pdf(pdf_path, translation_server="http://localhost:1969"):
    """Auto-extract DOI from a PDF and fetch rich metadata.

    Returns ``(metadata_dict, doi_string)`` or ``(None, None)`` when DOI
    extraction fails entirely.  If the DOI is found but metadata cannot be
    fetched, returns ``(None, doi)``.
    """
    doi = extract_doi_from_pdf(pdf_path)
    if not doi:
        return None, None

    # Primary path: Translation Server
    try:
        metadata, _input_type, _normalized = fetch_metadata(doi, translation_server)
        return metadata, doi
    except (ConnectionError, ValueError, RuntimeError, TimeoutError):
        pass

    # Fallback: CrossRef API directly
    try:
        from getscipapers_hoanganhduc.getpapers import fetch_crossref_data
        from getscipapers_hoanganhduc import configuration as gsp_config
        gsp_config.load_credentials(interactive=False)
        cr_data = fetch_crossref_data(doi)
        if cr_data:
            return crossref_to_zotero(cr_data), doi
    except Exception:
        pass

    return None, doi
