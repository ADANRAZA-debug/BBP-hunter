#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║          ZERO-DAY BUG BOUNTY PROGRAM DISCOVERY ENGINE  v2.0                ║
║          Senior OSINT Automation Pipeline — Production Grade               ║
║                                                                              ║
║  Architecture:                                                               ║
║    Stage 1 → Multi-Engine Search (Google CSE + Bing + DuckDuckGo scrape)   ║
║    Stage 2 → Wayback Machine CDX Age Filter                                 ║
║    Stage 3 → Weighted Scoring Engine (NLP-style signal extraction)          ║
║    Stage 4 → Structural DOM Validator (policy page heuristics)              ║
║    Stage 5 → State Manager (flat-file dedup + bloom-filter-like logic)      ║
║    Stage 6 → Discord Rich Embed Alerting                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

Author  : Zero-Day OSINT Engine
License : MIT
Python  : 3.10+
"""

import os
import re
import sys
import json
import time
import hashlib
import logging
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

import requests
from bs4 import BeautifulSoup
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("bounty-engine")

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS & CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

# State file path — committed back to repo by GitHub Actions
STATE_FILE = Path("processed_urls.txt")

# Confidence score threshold — must reach this to send alert
CONFIDENCE_THRESHOLD = 2

# Wayback Machine age boundary (days) for "genuinely new" classification
WAYBACK_NEW_THRESHOLD_DAYS = 30

# Maximum pages of Google results to fetch per run
GOOGLE_MAX_PAGES = 3  # 10 results/page → up to 30 results

# Request timeouts
HTTP_TIMEOUT = 15  # seconds

# ─────────────────────────────────────────────────────────────────────────────
# BROWSER USER-AGENT ROTATION  (avoids bot-detection on content fetch)
# ─────────────────────────────────────────────────────────────────────────────
USER_AGENTS = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Version/17.4.1 Safari/605.1.15"
    ),
    (
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) "
        "Gecko/20100101 Firefox/125.0"
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0"
    ),
]

_ua_index = 0

def get_user_agent() -> str:
    """Round-robin user-agent rotation."""
    global _ua_index
    ua = USER_AGENTS[_ua_index % len(USER_AGENTS)]
    _ua_index += 1
    return ua


def get_headers(referer: str = "https://www.google.com/") -> dict:
    """Return realistic browser-like HTTP headers."""
    return {
        "User-Agent": get_user_agent(),
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;"
            "q=0.9,image/avif,image/webp,*/*;q=0.8"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": referer,
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": "max-age=0",
    }


# ─────────────────────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SearchResult:
    url: str
    title: str
    snippet: str
    source: str  # "google" | "bing" | "ddg"


@dataclass
class VerifiedProgram:
    url: str
    title: str
    snippet: str
    search_source: str
    wayback_status: str           # "Genuinely New" | "Historically Seen" | "Not Archived"
    wayback_first_seen: Optional[str]
    confidence_score: int
    matched_positive: list[str]
    matched_negative: list[str]
    page_title: str


# ─────────────────────────────────────────────────────────────────────────────
# WEIGHTED SCORING ENGINE — SIGNAL TABLES
# ─────────────────────────────────────────────────────────────────────────────

# (pattern, points, human_label)
POSITIVE_SIGNALS: list[tuple[str, int, str]] = [
    # High-confidence policy markers  (+2 pts)
    (r"mailto\s*:\s*security@",                2, "security@ email"),
    (r"\bpgp\s*key\b",                         2, "PGP key"),
    (r"\bsubmit\s+a\s+report\b",               2, "submit a report"),
    (r"\bbounty\s+table\b",                    2, "bounty table"),
    (r"\bhall\s+of\s+fame\b",                  2, "hall of fame"),
    (r"\breward\s+guidelines?\b",              2, "reward guidelines"),
    (r"\bsecurity\s+advisories?\b",            2, "security advisory"),
    (r"\bdisclosure\s+policy\b",               2, "disclosure policy"),
    (r"\breporting\s+a\s+vulnerability\b",     2, "reporting a vulnerability"),
    (r"\bbounty\s+program\b",                  2, "bounty program"),
    (r"\bvdp\b",                               2, "VDP abbreviation"),
    (r"\bcoordinated\s+disclosure\b",          2, "coordinated disclosure"),
    # Medium-confidence markers (+1 pt)
    (r"\bout\s+of\s+scope\b",                  1, "out of scope"),
    (r"\bin\s+scope\b",                        1, "in scope"),
    (r"\bsafe\s+harbor\b",                     1, "safe harbor"),
    (r"\beligibility\b",                        1, "eligibility"),
    (r"\bvulnerability\s+disclosure\b",        1, "vulnerability disclosure"),
    (r"\bresponsible\s+disclosure\b",          1, "responsible disclosure"),
    (r"\bcvss\b",                              1, "CVSS score"),
    (r"\bbug\s+bounty\b",                      1, "bug bounty"),
    (r"\bsecurity\s+researcher\b",             1, "security researcher"),
    (r"\bsecurity@",                           1, "security@ reference"),
    (r"\bmonetary\s+reward\b",                 1, "monetary reward"),
    (r"\bcash\s+reward\b",                     1, "cash reward"),
    (r"\bswag\b",                              1, "swag reward"),
    (r"\bsecurity\s+team\b",                   1, "security team"),
    (r"\breport\s+a\s+(bug|vulnerability|issue)\b", 1, "report a bug/vuln"),
    (r"\bfirst\s+response\b",                  1, "first response SLA"),
    (r"\bpayment\s+method\b",                  1, "payment method"),
    (r"\bpaypal\b|\bbank\s+transfer\b",        1, "payment channel"),
    (r"\bseverity\s+level\b",                  1, "severity levels"),
    (r"\bscope\s+of\s+the\s+program\b",        1, "program scope"),
]

NEGATIVE_SIGNALS: list[tuple[str, int, str]] = [
    # Strong false-positive killers (-3 pts)
    (r"\bmin\s+read\b|\bminute\s+read\b",      -3, "article read-time marker"),
    (r"\bread\s+time\b",                       -3, "read time marker"),
    (r"\bauthor\s*:",                          -3, "author: label"),
    (r"\bpress\s+release\b",                   -3, "press release"),
    (r"\bnews\s+categor",                      -3, "news category"),
    (r"\bannounced\s+today\b",                 -3, "announced today"),
    (r"\bpublished\s+on\b",                    -3, "published on"),
    (r"\bwritten\s+by\b",                      -3, "written by"),
    # Weaker false-positive killers (-1 pt)
    (r"\bshare\s+this\s+article\b",            -1, "share this article"),
    (r"\brelated\s+articles?\b",               -1, "related articles"),
    (r"\bsubscribe\s+to\s+newsletter\b",       -1, "newsletter subscribe"),
    (r"\bcomments?\s+\(\d+\)",                 -1, "comment count"),
    (r"\btags\s*:",                            -1, "article tags"),
    (r"\bcategory\s*:",                        -1, "category label"),
    (r"\bsocial\s+media\b",                   -1, "social media mention"),
    (r"\bfiled\s+under\b",                     -1, "filed under"),
]

# Structural DOM signals (applied to page structure, not raw text)
DOM_STRUCTURAL_SIGNALS: list[tuple[str, int, str]] = [
    # A <form> with method=post on a security page is a strong positive
    (r"action.*report|report.*action",         2, "report submission form"),
    # A table with $ or reward amounts
    (r"\$\d+|\d+\s*usd|\d+\s*eur",            1, "monetary amount in table"),
]


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 1-A: GOOGLE CUSTOM SEARCH
# ─────────────────────────────────────────────────────────────────────────────

# The precise OSINT dork — excludes all known aggregators & noise sources
GOOGLE_DORK = (
    'intitle:"bug bounty" OR intitle:"vulnerability disclosure" '
    '"reward" OR "swag" OR "responsible disclosure" '
    '-site:hackerone.com -site:bugcrowd.com -site:intigriti.com '
    '-site:yeswehack.com -site:github.com -site:medium.com '
    '-site:reddit.com -site:openbugbounty.org -site:firebounty.com '
    '-site:twitter.com -site:x.com -site:linkedin.com '
    '-site:bleepingcomputer.com -site:securityweek.com '
    '-site:threatpost.com -site:darkreading.com -site:zdnet.com '
    '-site:thehackernews.com -site:krebsonsecurity.com '
    '-site:techcrunch.com -site:wired.com -site:forbes.com '
    '-site:infosecurity-magazine.com -site:csoonline.com'
)


@retry(
    retry=retry_if_exception_type((HttpError, Exception)),
    stop=stop_after_attempt(4),
    wait=wait_exponential(multiplier=2, min=3, max=30),
    before_sleep=before_sleep_log(log, logging.WARNING),
    reraise=False,
)
def _google_search_page(service, cse_id: str, start: int) -> list[SearchResult]:
    """Fetch a single page of Google Custom Search results."""
    results = []
    try:
        response = (
            service.cse()
            .list(
                q=GOOGLE_DORK,
                cx=cse_id,
                num=10,
                start=start,
                dateRestrict="d1",  # Only pages indexed in the last 24h
                safe="off",
            )
            .execute()
        )
        items = response.get("items", [])
        for item in items:
            results.append(
                SearchResult(
                    url=item.get("link", ""),
                    title=item.get("title", ""),
                    snippet=item.get("snippet", ""),
                    source="google",
                )
            )
    except HttpError as e:
        if e.resp.status in (429, 503):
            log.warning(f"Google API rate limit/503: {e}")
            raise  # tenacity will retry
        log.error(f"Google API HttpError: {e}")
    except Exception as e:
        log.warning(f"Google search page error (start={start}): {e}")
        raise
    return results


def stage1_google_search(api_key: str, cse_id: str) -> list[SearchResult]:
    """Run the Google Custom Search across multiple pages."""
    log.info("STAGE 1-A: Google Custom Search Engine")
    service = build("customsearch", "v1", developerKey=api_key)
    all_results: list[SearchResult] = []

    for page in range(GOOGLE_MAX_PAGES):
        start = page * 10 + 1
        log.info(f"  → Fetching page {page + 1} (start={start})")
        results = _google_search_page(service, cse_id, start)
        if not results:
            log.info(f"  → No more results at page {page + 1}, stopping.")
            break
        all_results.extend(results)
        time.sleep(1.2)  # Polite rate limiting

    log.info(f"  ✓ Google returned {len(all_results)} raw results")
    return all_results


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 1-B: BING WEB SEARCH (Free tier via scraping headers — no key needed)
# ─────────────────────────────────────────────────────────────────────────────

BING_DORK = (
    'intitle:"bug bounty" OR intitle:"vulnerability disclosure" '
    '"reward" OR "responsible disclosure" '
    '-site:hackerone.com -site:bugcrowd.com -site:intigriti.com '
    '-site:yeswehack.com -site:github.com -site:medium.com '
    '-site:reddit.com -site:twitter.com -site:linkedin.com'
)


@retry(
    retry=retry_if_exception_type(requests.exceptions.RequestException),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=2, min=2, max=20),
    before_sleep=before_sleep_log(log, logging.WARNING),
    reraise=False,
)
def stage1_bing_search() -> list[SearchResult]:
    """
    Bing search via the public HTML interface.
    Parses result cards from Bing's SERP HTML.
    No API key required — completely free.
    """
    log.info("STAGE 1-B: Bing HTML Search")
    results = []
    encoded_q = urllib.parse.quote(BING_DORK)

    # Bing supports 'qft=ex1%3a"week"' for recency filtering
    url = (
        f"https://www.bing.com/search?q={encoded_q}"
        f"&filters=ex1%3a%22week%22&count=30&first=1"
    )

    try:
        resp = requests.get(url, headers=get_headers("https://www.bing.com/"), timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")

        # Bing result cards live in <li class="b_algo">
        for card in soup.select("li.b_algo"):
            a_tag = card.select_one("h2 a")
            snippet_tag = card.select_one("div.b_caption p, .b_algoSlug")
            if a_tag and a_tag.get("href"):
                href = a_tag["href"]
                # Skip Bing's internal tracking URLs
                if href.startswith("http"):
                    results.append(
                        SearchResult(
                            url=href,
                            title=a_tag.get_text(strip=True),
                            snippet=snippet_tag.get_text(strip=True) if snippet_tag else "",
                            source="bing",
                        )
                    )
    except requests.exceptions.RequestException as e:
        log.warning(f"Bing search failed: {e}")
        raise
    except Exception as e:
        log.warning(f"Bing parse error: {e}")

    log.info(f"  ✓ Bing returned {len(results)} raw results")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 1-C: DUCKDUCKGO HTML SEARCH (completely free, no JS needed)
# ─────────────────────────────────────────────────────────────────────────────

DDG_DORK = (
    'intitle:"bug bounty" OR intitle:"vulnerability disclosure" '
    '"reward" OR "responsible disclosure" '
    '-site:hackerone.com -site:bugcrowd.com -site:intigriti.com '
    '-site:yeswehack.com -site:github.com -site:medium.com '
    '-site:reddit.com -site:twitter.com -site:linkedin.com'
)


def stage1_ddg_search() -> list[SearchResult]:
    """
    DuckDuckGo HTML search — no API key, completely free.
    Uses the lite HTML endpoint which is stable and scrapeable.
    """
    log.info("STAGE 1-C: DuckDuckGo HTML Search")
    results = []

    url = "https://html.duckduckgo.com/html/"
    data = {
        "q": DDG_DORK,
        "df": "w",  # Past week
        "kl": "us-en",
    }

    try:
        resp = requests.post(
            url,
            data=data,
            headers=get_headers("https://duckduckgo.com/"),
            timeout=HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")

        for result in soup.select(".result"):
            link_tag = result.select_one(".result__a")
            snippet_tag = result.select_one(".result__snippet")

            if link_tag:
                # DDG encodes the actual URL in the href
                raw_href = link_tag.get("href", "")
                # Extract real URL from DDG redirect
                parsed = urllib.parse.urlparse(raw_href)
                qs = urllib.parse.parse_qs(parsed.query)
                real_url = qs.get("uddg", [raw_href])[0]

                if real_url.startswith("http"):
                    results.append(
                        SearchResult(
                            url=real_url,
                            title=link_tag.get_text(strip=True),
                            snippet=snippet_tag.get_text(strip=True) if snippet_tag else "",
                            source="ddg",
                        )
                    )
    except Exception as e:
        log.warning(f"DuckDuckGo search failed: {e}")

    log.info(f"  ✓ DuckDuckGo returned {len(results)} raw results")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# DEDUPLICATION ACROSS SEARCH ENGINES
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_url(url: str) -> str:
    """
    Normalize URL for deduplication:
    - Lowercase scheme + host
    - Remove trailing slash
    - Remove common tracking params (utm_*, fbclid, etc.)
    - Remove URL fragments
    """
    try:
        parsed = urllib.parse.urlparse(url.strip().lower())
        # Remove fragment
        parsed = parsed._replace(fragment="")
        # Parse and clean query params
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)
        # Strip tracking parameters
        tracking = {
            "utm_source", "utm_medium", "utm_campaign", "utm_term",
            "utm_content", "fbclid", "gclid", "ref", "source",
        }
        clean_qs = {k: v for k, v in qs.items() if k not in tracking}
        clean_query = urllib.parse.urlencode(clean_qs, doseq=True)
        parsed = parsed._replace(query=clean_query)
        return urllib.parse.urlunparse(parsed).rstrip("/")
    except Exception:
        return url.strip().lower().rstrip("/")


def deduplicate_results(results: list[SearchResult]) -> list[SearchResult]:
    """Remove duplicate URLs across all search engines, keeping first occurrence."""
    seen: set[str] = set()
    unique: list[SearchResult] = []
    for r in results:
        norm = _normalize_url(r.url)
        if norm not in seen:
            seen.add(norm)
            unique.append(r)
    log.info(f"  ✓ After dedup: {len(unique)} unique URLs (from {len(results)} total)")
    return unique


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 2: WAYBACK MACHINE CDX API FILTER
# ─────────────────────────────────────────────────────────────────────────────

CDX_API = "http://web.archive.org/cdx/search/cdx"
WAYBACK_DATE_FMT = "%Y%m%d%H%M%S"


@retry(
    retry=retry_if_exception_type(requests.exceptions.RequestException),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    before_sleep=before_sleep_log(log, logging.WARNING),
    reraise=False,
)
def _cdx_lookup(url: str) -> Optional[dict]:
    """Query the Wayback Machine CDX API for a URL's archive history."""
    params = {
        "url": url,
        "output": "json",
        "limit": "1",          # Oldest capture only
        "fl": "timestamp,statuscode",
        "filter": "statuscode:200",  # Only successful captures
    }
    try:
        resp = requests.get(
            CDX_API,
            params=params,
            headers=get_headers("https://archive.org/"),
            timeout=HTTP_TIMEOUT,
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        data = resp.json()
        # data is [[header_row], [result_row], ...]
        # After filtering the header, first real row is index 1
        if len(data) >= 2:
            row = data[1]  # [timestamp, statuscode]
            return {"timestamp": row[0], "statuscode": row[1]}
        return None
    except requests.exceptions.RequestException as e:
        log.debug(f"CDX lookup error for {url}: {e}")
        raise
    except Exception as e:
        log.debug(f"CDX parse error for {url}: {e}")
        return None


def stage2_wayback_check(url: str) -> tuple[str, Optional[str]]:
    """
    Returns:
        (wayback_status, first_seen_date_str)
        wayback_status: "Genuinely New" | "Historically Seen" | "Not Archived"
    """
    cdx_data = _cdx_lookup(url)
    if cdx_data is None:
        return "Not Archived", None

    raw_ts = cdx_data.get("timestamp", "")
    if not raw_ts:
        return "Not Archived", None

    try:
        capture_dt = datetime.strptime(raw_ts, WAYBACK_DATE_FMT).replace(tzinfo=timezone.utc)
        age_days = (datetime.now(tz=timezone.utc) - capture_dt).days
        human_date = capture_dt.strftime("%Y-%m-%d")

        if age_days <= WAYBACK_NEW_THRESHOLD_DAYS:
            return "Genuinely New", human_date
        else:
            return "Historically Seen", human_date
    except ValueError:
        return "Not Archived", None


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 3: CONTENT DOWNLOAD + WEIGHTED SCORING ENGINE
# ─────────────────────────────────────────────────────────────────────────────

@retry(
    retry=retry_if_exception_type(requests.exceptions.RequestException),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    before_sleep=before_sleep_log(log, logging.WARNING),
    reraise=False,
)
def _fetch_page(url: str) -> Optional[requests.Response]:
    """Download a page with browser-like headers."""
    resp = requests.get(
        url,
        headers=get_headers(),
        timeout=HTTP_TIMEOUT,
        allow_redirects=True,
        verify=True,
    )
    if resp.status_code == 200:
        return resp
    return None


def _extract_text_and_structure(html: str) -> tuple[str, BeautifulSoup]:
    """Parse HTML and return (lowercase_full_text, soup)."""
    soup = BeautifulSoup(html, "html.parser")
    # Remove script, style, nav, footer noise
    for tag in soup(["script", "style", "nav", "footer", "header", "noscript"]):
        tag.decompose()
    text = soup.get_text(separator=" ", strip=True).lower()
    return text, soup


def stage3_score(url: str, html: str) -> tuple[int, list[str], list[str], str]:
    """
    Run the weighted scoring engine against page content.

    Returns:
        (score, matched_positives, matched_negatives, page_title)
    """
    text, soup = _extract_text_and_structure(html)
    page_title = soup.title.string.strip() if soup.title and soup.title.string else "No Title"

    score = 0
    matched_pos: list[str] = []
    matched_neg: list[str] = []

    # Score positive signals
    for pattern, points, label in POSITIVE_SIGNALS:
        if re.search(pattern, text, re.IGNORECASE):
            score += points
            matched_pos.append(f"+{points}: {label}")

    # Score negative signals
    for pattern, points, label in NEGATIVE_SIGNALS:
        if re.search(pattern, text, re.IGNORECASE):
            score += points  # points are already negative
            matched_neg.append(f"{points}: {label}")

    # DOM structural bonus signals — check on actual HTML string
    html_lower = html.lower()
    for pattern, points, label in DOM_STRUCTURAL_SIGNALS:
        if re.search(pattern, html_lower, re.IGNORECASE):
            score += points
            matched_pos.append(f"+{points}: {label} [DOM]")

    # Extra: does the page have a <form action="...report..."> or similar?
    forms = soup.find_all("form")
    for form in forms:
        action = (form.get("action") or "").lower()
        if any(kw in action for kw in ["report", "submit", "disclosure", "vulnerability"]):
            score += 2
            matched_pos.append("+2: submission form detected [DOM]")
            break

    # Extra: does the URL path itself signal a policy page?
    url_lower = url.lower()
    url_path_signals = [
        "security/policy", "security-policy", "bug-bounty", "bugbounty",
        "vulnerability-disclosure", "responsible-disclosure", "vdp",
        "security/disclosure", "hackerone", "security-disclosure",
    ]
    for sig in url_path_signals:
        if sig in url_lower:
            score += 1
            matched_pos.append(f"+1: policy URL path ({sig})")
            break

    return score, matched_pos, matched_neg, page_title


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 4: STATE MANAGER
# ─────────────────────────────────────────────────────────────────────────────

def load_processed_urls() -> set[str]:
    """Load all previously processed URL hashes from state file."""
    if not STATE_FILE.exists():
        return set()
    hashes = set()
    with STATE_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                hashes.add(line)
    log.info(f"  ✓ Loaded {len(hashes)} known URL hashes from state file")
    return hashes


def mark_url_processed(url: str, processed_set: set[str]) -> None:
    """Append the URL hash to the state file and in-memory set."""
    url_hash = hashlib.sha256(_normalize_url(url).encode()).hexdigest()
    if url_hash not in processed_set:
        processed_set.add(url_hash)
        with STATE_FILE.open("a", encoding="utf-8") as f:
            f.write(url_hash + "\n")


def is_url_processed(url: str, processed_set: set[str]) -> bool:
    url_hash = hashlib.sha256(_normalize_url(url).encode()).hexdigest()
    return url_hash in processed_set


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 5: DISCORD WEBHOOK ALERTING
# ─────────────────────────────────────────────────────────────────────────────

# Discord embed color palette
COLOR_NEW = 0x00FF88      # Bright green — genuinely new
COLOR_SEEN = 0xFFAA00     # Amber — historically seen but interesting
COLOR_NOT_ARCHIVED = 0x4488FF  # Blue — unknown history

WAYBACK_COLORS = {
    "Genuinely New": COLOR_NEW,
    "Historically Seen": COLOR_SEEN,
    "Not Archived": COLOR_NOT_ARCHIVED,
}

WAYBACK_EMOJIS = {
    "Genuinely New": "🆕",
    "Historically Seen": "📜",
    "Not Archived": "🔍",
}


def _build_discord_embed(program: VerifiedProgram) -> dict:
    """Build a rich Discord embed payload for a verified bug bounty program."""
    color = WAYBACK_COLORS.get(program.wayback_status, COLOR_NOT_ARCHIVED)
    wb_emoji = WAYBACK_EMOJIS.get(program.wayback_status, "❓")

    # Format matched signals
    pos_lines = "\n".join(f"  ✅ {m}" for m in program.matched_positive[:8]) or "  None"
    neg_lines = "\n".join(f"  ❌ {m}" for m in program.matched_negative[:5]) or "  None"

    # Truncate snippet
    snippet = (program.snippet[:250] + "…") if len(program.snippet) > 250 else program.snippet

    # Score bar (visual confidence)
    score = program.confidence_score
    bar = "█" * min(score, 10) + "░" * max(0, 10 - score)
    score_display = f"`{bar}` {score}/10+"

    wayback_detail = (
        f"{wb_emoji} **{program.wayback_status}**"
        + (f"\nFirst Seen: `{program.wayback_first_seen}`" if program.wayback_first_seen else "")
    )

    embed = {
        "title": f"🎯 {program.page_title[:200]}",
        "url": program.url,
        "color": color,
        "description": (
            f"**A new bug bounty / VDP has been discovered!**\n\n"
            f"📝 *{snippet}*"
        ),
        "fields": [
            {
                "name": "🔗 URL",
                "value": f"```{program.url[:500]}```",
                "inline": False,
            },
            {
                "name": "🕰️ Wayback Machine",
                "value": wayback_detail,
                "inline": True,
            },
            {
                "name": "📊 Confidence Score",
                "value": score_display,
                "inline": True,
            },
            {
                "name": "🔎 Search Source",
                "value": f"`{program.search_source.upper()}`",
                "inline": True,
            },
            {
                "name": "✅ Positive Signals",
                "value": f"```\n{pos_lines}\n```",
                "inline": False,
            },
            {
                "name": "⚠️ Noise Signals Detected",
                "value": f"```\n{neg_lines}\n```",
                "inline": False,
            },
        ],
        "footer": {
            "text": "Zero-Day Bug Bounty Discovery Engine • " + datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        },
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
    return embed


@retry(
    retry=retry_if_exception_type(requests.exceptions.RequestException),
    stop=stop_after_attempt(4),
    wait=wait_exponential(multiplier=2, min=2, max=15),
    before_sleep=before_sleep_log(log, logging.WARNING),
    reraise=False,
)
def send_discord_alert(webhook_url: str, program: VerifiedProgram) -> bool:
    """Send a rich embed to the Discord webhook."""
    embed = _build_discord_embed(program)
    payload = {
        "username": "BountyBot 🔐",
        "avatar_url": "https://i.imgur.com/4M34hi2.png",
        "embeds": [embed],
    }
    resp = requests.post(
        webhook_url,
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=10,
    )
    if resp.status_code in (200, 204):
        log.info(f"  ✓ Discord alert sent for: {program.url}")
        return True
    else:
        log.warning(f"  ✗ Discord webhook returned {resp.status_code}: {resp.text[:200]}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# MAIN PIPELINE ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

def run_pipeline() -> None:
    log.info("=" * 70)
    log.info("  ZERO-DAY BUG BOUNTY DISCOVERY ENGINE — PIPELINE START")
    log.info("=" * 70)

    # ── Load secrets from environment ──────────────────────────────────────
    google_api_key = os.environ.get("GOOGLE_API_KEY", "")
    search_engine_id = os.environ.get("SEARCH_ENGINE_ID", "")
    discord_webhook = os.environ.get("DISCORD_WEBHOOK_URL", "")

    if not discord_webhook:
        log.error("DISCORD_WEBHOOK_URL not set. Exiting.")
        sys.exit(1)

    google_enabled = bool(google_api_key and search_engine_id)
    if not google_enabled:
        log.warning("GOOGLE_API_KEY or SEARCH_ENGINE_ID not set — skipping Google CSE.")

    # ── Stage 4: Load State ────────────────────────────────────────────────
    log.info("\n[STAGE 4] Loading URL state...")
    processed_set = load_processed_urls()

    # ── Stage 1: Multi-Engine Search ───────────────────────────────────────
    log.info("\n[STAGE 1] Multi-Engine Search")
    all_results: list[SearchResult] = []

    if google_enabled:
        try:
            google_results = stage1_google_search(google_api_key, search_engine_id)
            all_results.extend(google_results)
        except Exception as e:
            log.error(f"Google search pipeline failed: {e}")

    try:
        bing_results = stage1_bing_search()
        all_results.extend(bing_results)
    except Exception as e:
        log.warning(f"Bing search failed entirely: {e}")

    try:
        ddg_results = stage1_ddg_search()
        all_results.extend(ddg_results)
    except Exception as e:
        log.warning(f"DuckDuckGo search failed entirely: {e}")

    # Deduplicate across engines
    unique_results = deduplicate_results(all_results)

    # Filter already-processed URLs
    fresh_results = [r for r in unique_results if not is_url_processed(r.url, processed_set)]
    log.info(f"\n  ✓ {len(fresh_results)} URLs to process (after state filter)")

    if not fresh_results:
        log.info("  → No new URLs to process. Pipeline complete.")
        return

    # ── Stages 2 + 3 + 5: Verify each URL ────────────────────────────────
    verified_programs: list[VerifiedProgram] = []
    alert_count = 0

    for idx, result in enumerate(fresh_results, 1):
        url = result.url
        log.info(f"\n[{idx}/{len(fresh_results)}] Processing: {url}")

        # ── Mark as processed immediately (even if it fails, don't reprocess) ──
        mark_url_processed(url, processed_set)

        # ── Stage 2: Wayback Machine ──────────────────────────────────────
        log.info("  [STAGE 2] Wayback CDX check...")
        try:
            wayback_status, wayback_date = stage2_wayback_check(url)
            log.info(f"  → Status: {wayback_status} (first seen: {wayback_date})")
        except Exception as e:
            log.warning(f"  → Wayback check error: {e}")
            wayback_status, wayback_date = "Not Archived", None

        # ── Stage 3: Fetch + Score ────────────────────────────────────────
        log.info("  [STAGE 3] Fetching and scoring content...")
        try:
            resp = _fetch_page(url)
            if resp is None:
                log.info("  → Page returned non-200. Skipping.")
                continue
        except Exception as e:
            log.info(f"  → Fetch failed: {e}. Skipping.")
            continue

        try:
            score, matched_pos, matched_neg, page_title = stage3_score(url, resp.text)
        except Exception as e:
            log.warning(f"  → Scoring error: {e}. Skipping.")
            continue

        log.info(f"  → Score: {score} | Positives: {len(matched_pos)} | Negatives: {len(matched_neg)}")

        if score < CONFIDENCE_THRESHOLD:
            log.info(f"  ✗ Below threshold ({score} < {CONFIDENCE_THRESHOLD}). Discarded.")
            continue

        # ── Verified! ──────────────────────────────────────────────────────
        log.info(f"  ✓ VERIFIED — Score {score} ≥ {CONFIDENCE_THRESHOLD}")

        program = VerifiedProgram(
            url=url,
            title=result.title,
            snippet=result.snippet,
            search_source=result.source,
            wayback_status=wayback_status,
            wayback_first_seen=wayback_date,
            confidence_score=score,
            matched_positive=matched_pos,
            matched_negative=matched_neg,
            page_title=page_title,
        )
        verified_programs.append(program)

        # ── Stage 5: Discord Alert ────────────────────────────────────────
        log.info("  [STAGE 5] Sending Discord alert...")
        try:
            sent = send_discord_alert(discord_webhook, program)
            if sent:
                alert_count += 1
        except Exception as e:
            log.error(f"  → Discord alert failed: {e}")

        # Polite delay between content fetches
        time.sleep(2.5)

    # ── Summary ───────────────────────────────────────────────────────────
    log.info("\n" + "=" * 70)
    log.info(f"  PIPELINE COMPLETE")
    log.info(f"  Total URLs found    : {len(all_results)}")
    log.info(f"  After dedup         : {len(unique_results)}")
    log.info(f"  New (unprocessed)   : {len(fresh_results)}")
    log.info(f"  Verified programs   : {len(verified_programs)}")
    log.info(f"  Discord alerts sent : {alert_count}")
    log.info("=" * 70)


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    run_pipeline()
