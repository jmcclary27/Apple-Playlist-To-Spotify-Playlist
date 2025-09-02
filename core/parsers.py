import re
import json
import time
import html
import urllib.parse
from typing import List, Dict, Any

import requests
from bs4 import BeautifulSoup

# --- URL validation ---------------------------------------------------
APPLE_PLAYLIST_RE = re.compile(r'^https?://(music|geo)\.apple\.com/[^/]+/playlist/')

def is_apple_playlist_url(url: str) -> bool:
    return bool(APPLE_PLAYLIST_RE.match((url or "").strip().lower()))

# --- HTTP helpers (bounded) -------------------------------------------
_DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
}

def _with_cache_buster(url: str) -> str:
    # append ts to force fresh HTML
    u = urllib.parse.urlsplit(url)
    q = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
    q.append(("_ts", str(int(time.time()))))
    nq = urllib.parse.urlencode(q)
    return urllib.parse.urlunsplit((u.scheme, u.netloc, u.path, nq, u.fragment))

def _http_get_html(url: str, timeout=8, retries=1) -> str:
    session = requests.Session()
    session.headers.update(_DEFAULT_HEADERS)
    last_err = None
    for attempt in range(retries + 1):
        try:
            resp = session.get(_with_cache_buster(url), timeout=timeout, allow_redirects=True)
            # Some geolocated pages 302 to "geo.apple.com" — allow that.
            resp.raise_for_status()
            return resp.text
        except Exception as e:
            last_err = e
            time.sleep(0.25)
    raise RuntimeError(f"Failed to fetch Apple playlist page: {last_err}")

# --- Extraction strategies --------------------------------------------
_SONG_META_SELECTOR = {"property": "music:song"}           # old pages
_JSONLD_SELECTOR    = {"type": "application/ld+json"}      # newer pages

# Fallback for anchor URLs that contain '/song/' and a numeric id
_ANCHOR_SONG_RE = re.compile(r'/song/[^/]+/id(\d+)')
_QS_ID_PARAM    = "i"  # many links are ...?i=<trackId>

def _extract_ids_from_jsonld(soup: BeautifulSoup) -> List[str]:
    ids: List[str] = []
    for tag in soup.find_all("script", _JSONLD_SELECTOR):
        try:
            payload = json.loads(tag.string or tag.text or "{}")
        except Exception:
            continue
        # Accept either an array of ItemList or a single object
        candidates = payload if isinstance(payload, list) else [payload]
        for obj in candidates:
            # 1) schema.org ItemList
            items = obj.get("itemListElement") if isinstance(obj, dict) else None
            if isinstance(items, list):
                for it in items:
                    url = None
                    # "url" directly or inside "item"
                    if isinstance(it, dict):
                        url = it.get("url") or (it.get("item") or {}).get("url")
                    if isinstance(url, str):
                        tid = _track_id_from_url(url)
                        if tid:
                            ids.append(tid)
            # 2) sometimes tracks array lives under "track"/"tracks"
            for key in ("track", "tracks"):
                arr = obj.get(key)
                if isinstance(arr, list):
                    for t in arr:
                        url = None
                        if isinstance(t, dict):
                            url = t.get("url")
                        if isinstance(url, str):
                            tid = _track_id_from_url(url)
                            if tid:
                                ids.append(tid)
    return _dedup(ids)

def _extract_ids_from_meta(soup: BeautifulSoup) -> List[str]:
    urls = [m.get("content") for m in soup.find_all("meta", _SONG_META_SELECTOR) if m.get("content")]
    ids = [tid for u in urls if (tid := _track_id_from_url(u))]
    return _dedup(ids)

def _extract_ids_from_anchors(soup: BeautifulSoup) -> List[str]:
    ids: List[str] = []
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if "/song/" not in href:
            continue
        tid = _track_id_from_url(href)
        if tid:
            ids.append(tid)
    return _dedup(ids)

def _track_id_from_url(url: str) -> str | None:
    # Try query param ?i=<id>
    q = urllib.parse.urlparse(url).query
    params = urllib.parse.parse_qs(q)
    if _QS_ID_PARAM in params and params[_QS_ID_PARAM]:
        val = params[_QS_ID_PARAM][0]
        if val.isdigit():
            return val
    # Try /song/.../id<digits>
    m = _ANCHOR_SONG_RE.search(url)
    if m:
        return m.group(1)
    # Try last numeric segment
    parts = [p for p in urllib.parse.urlparse(url).path.split('/') if p]
    if parts and parts[-1].isdigit():
        return parts[-1]
    return None

def _dedup(seq: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out

# --- iTunes lookup (bounded + chunked) -------------------------------
def _lookup_tracks_itunes(ids: List[str], timeout=6) -> Dict[str, Dict[str, Any]]:
    """
    Apple iTunes lookup API supports multiple IDs; we chunk to 50
    and tolerate partial failures (never hangs).
    """
    out: Dict[str, Dict[str, Any]] = {}
    if not ids:
        return out

    session = requests.Session()
    session.headers.update({"User-Agent": _DEFAULT_HEADERS["User-Agent"]})

    CHUNK = 50
    for i in range(0, len(ids), CHUNK):
        chunk = ids[i:i+CHUNK]
        url = "https://itunes.apple.com/lookup?id=" + ",".join(chunk)
        try:
            r = session.get(url, timeout=timeout)
            r.raise_for_status()
            data = r.json()
            for item in data.get("results", []):
                tid = str(item.get("trackId") or "")
                if tid:
                    out[tid] = item
        except Exception:
            # tolerate a failing chunk; continue with what we have
            continue
    return out

# --- Normalization (same interface as before) ------------------------
import unicodedata

PARENS_RE      = re.compile(r"\s*[\(\[][^)\]]*[\)\]]\s*")
SUFFIXES_RE    = re.compile(
    r"\s*-\s*(?:remaster(?:ed)?(?:\s*\d{2,4})?|live|mono|stereo|single version|radio edit|deluxe|explicit)\b.*",
    re.I,
)
FEAT_TRAIL_RE  = re.compile(r"\s+(?:feat|ft)\.?\s+.*$", re.I)
WHITESPACE_RE  = re.compile(r"\s+")

def _deaccent(s: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))

def _unify(s: str) -> str:
    return (s.replace("’", "'")
             .replace("‘", "'")
             .replace("“", '"')
             .replace("”", '"')
             .replace("—", " ")
             .replace("–", " ")
             .replace("-", " "))

def normalize_title(title: str) -> str:
    if not title:
        return ""
    t = _unify(title)
    t = _deaccent(t)
    t = PARENS_RE.sub(" ", t)
    t = FEAT_TRAIL_RE.sub(" ", t)
    t = SUFFIXES_RE.sub("", t)
    t = t.lower()
    t = re.sub(r"[^a-z0-9\s'&]", " ", t)
    t = WHITESPACE_RE.sub(" ", t).strip()
    return t

def normalize_artist(artist: str) -> str:
    if not artist:
        return ""
    a = _unify(artist)
    a = _deaccent(a)
    a = FEAT_TRAIL_RE.sub(" ", a)
    a = a.lower()
    a = re.sub(r"[^a-z0-9\s'&]", " ", a)
    a = WHITESPACE_RE.sub(" ", a).strip()
    return a

# --- Public API -------------------------------------------------------
def parse_apple_playlist_from_url(url: str):
    """
    Returns list[dict] with keys:
      raw_title, raw_artist, raw_album, raw_isrc, norm_title, norm_artist
    Raises ValueError on an obviously bad URL, RuntimeError on fetch/parse issues.
    """
    if not is_apple_playlist_url(url):
        raise ValueError("That doesn't look like an Apple Music playlist link.")

    html_text = _http_get_html(url, timeout=8, retries=1)
    soup = BeautifulSoup(html_text, "html.parser")

    # Priority 1: JSON-LD
    ids = _extract_ids_from_jsonld(soup)
    # Priority 2: meta tags
    if not ids:
        ids = _extract_ids_from_meta(soup)
    # Priority 3: anchors
    if not ids:
        ids = _extract_ids_from_anchors(soup)

    if not ids:
        # Give caller a clear message; your view turns this into a flash error
        raise RuntimeError("Couldn’t find any song IDs on that page.")

    itunes_map = _lookup_tracks_itunes(ids)

    rows = []
    for tid in ids:
        meta = itunes_map.get(tid, {})
        title  = meta.get("trackName", "")
        artist = meta.get("artistName", "")
        album  = meta.get("collectionName", "")
        isrc   = meta.get("isrc", "")

        rows.append({
            "raw_title": title,
            "raw_artist": artist,
            "raw_album": album,
            "raw_isrc": isrc,
            "norm_title": normalize_title(title),
            "norm_artist": normalize_artist(artist),
        })
    return rows
