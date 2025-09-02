# parsers.py
import re
import json
import time
import html
import unicodedata
import urllib.parse
import requests
from bs4 import BeautifulSoup

# -------------------------
# URL recognition
# -------------------------
APPLE_PLAYLIST_RE = re.compile(r'^https?://(music|geo)\.apple\.com/[^/]+/playlist/')

def is_apple_playlist_url(url: str) -> bool:
    return bool(APPLE_PLAYLIST_RE.match((url or "").strip().lower()))

def normalize_apple_url(url: str) -> str:
    """Keep as-is, but strip spaces/fragments; Apple is picky about storefront."""
    if not url:
        return url
    url = url.strip()
    # Remove fragment to avoid weird anchors that sometimes hide content
    parts = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))

# -------------------------
# HTTP fetch (no-cache)
# -------------------------
def _http_get(url: str, timeout=15) -> str:
    # Bust caches (CDN/proxy) with a timestamp query param
    sep = "&" if "?" in url else "?"
    url = f"{url}{sep}_ts={int(time.time()*1000)}"
    headers = {
        # Pretend to be a normal real browser
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }
    r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
    r.raise_for_status()
    return r.text

# -------------------------
# Extraction helpers
# -------------------------
def _extract_song_urls_from_playlist_html(html_text: str):
    """Strategy A: OG tags <meta property='music:song' content='...'>"""
    soup = BeautifulSoup(html_text, 'html.parser')
    metas = soup.find_all('meta', {"property": "music:song"})
    urls = [m.get("content") for m in metas if m.get("content")]
    return urls

def _extract_ids_from_urls(urls):
    out = []
    seen = set()
    for u in urls or []:
        tid = _extract_track_id_from_song_url(u)
        if tid and tid not in seen:
            seen.add(tid)
            out.append(tid)
    return out

def _extract_track_id_from_song_url(url: str):
    """Pull the ?i= track id; else try last numeric path segment."""
    if not url:
        return None
    # Handle &amp; in HTML
    url = html.unescape(url)
    q = urllib.parse.urlparse(url).query
    params = urllib.parse.parse_qs(q)
    if 'i' in params and params['i']:
        return params['i'][0]
    # fallback: last numeric path segment
    parts = [p for p in urllib.parse.urlparse(url).path.split('/') if p]
    if parts and parts[-1].isdigit():
        return parts[-1]
    return None

def _extract_song_ids_from_jsonld(html_text: str):
    """Strategy B: JSON-LD blocks that describe the playlist and tracks."""
    ids = []
    seen = set()
    soup = BeautifulSoup(html_text, 'html.parser')
    for node in soup.find_all("script", {"type": "application/ld+json"}):
        try:
            data = json.loads(node.string or node.text or "{}")
        except Exception:
            continue
        # Some pages have an array of JSON-LD docs
        docs = data if isinstance(data, list) else [data]
        for doc in docs:
            # MusicPlaylist with 'track' list
            track_list = []
            if isinstance(doc, dict):
                if doc.get("@type") in ("MusicPlaylist", "Playlist"):
                    t = doc.get("track")
                    if isinstance(t, list):
                        track_list.extend(t)
                # Sometimes Apple nests itemListElement / ListItem with urls
                if isinstance(doc.get("itemListElement"), list):
                    for li in doc["itemListElement"]:
                        url = None
                        if isinstance(li, dict):
                            if "url" in li and isinstance(li["url"], str):
                                url = li["url"]
                            elif "item" in li and isinstance(li["item"], dict):
                                url = li["item"].get("url")
                        if url:
                            tid = _extract_track_id_from_song_url(url)
                            if tid and tid not in seen:
                                seen.add(tid); ids.append(tid)
                # Parse 'track' entries with 'url' fields
                for t in track_list:
                    if isinstance(t, dict):
                        url = t.get("url") or t.get("@id")
                        if isinstance(url, str):
                            tid = _extract_track_id_from_song_url(url)
                            if tid and tid not in seen:
                                seen.add(tid); ids.append(tid)
    return ids

def _extract_song_ids_by_regex(html_text: str):
    """Strategy C: Regex sweep through raw HTML (lots of Apple variants)."""
    ids = []
    seen = set()

    # ?i=123456 or &amp;i=123456
    for m in re.finditer(r'(?:[?&]|&amp;)i=(\d{4,})', html_text):
        tid = m.group(1)
        if tid not in seen:
            seen.add(tid); ids.append(tid)

    # "songId":123456  OR  "trackId":"123456"
    for m in re.finditer(r'(?:"songId"|"trackId")\s*:\s*"?(\d{4,})"?', html_text):
        tid = m.group(1)
        if tid not in seen:
            seen.add(tid); ids.append(tid)

    # Occasionally Apple serializes ids as {"id":"123456","type":"songs"}
    for m in re.finditer(r'"id"\s*:\s*"(\d{4,})"\s*,\s*"type"\s*:\s*"songs"', html_text):
        tid = m.group(1)
        if tid not in seen:
            seen.add(tid); ids.append(tid)

    return ids

# -------------------------
# iTunes lookup (chunked)
# -------------------------
def _lookup_tracks_itunes_chunked(ids, chunk_size=50, timeout=12):
    """
    Lookup many track IDs using iTunes Lookup API in chunks to avoid
    URL-too-long and partial result issues.
    """
    out = {}
    ids = [str(x) for x in ids or []]
    if not ids:
        return out

    base = "https://itunes.apple.com/lookup"
    for i in range(0, len(ids), chunk_size):
        chunk = ids[i:i+chunk_size]
        params = {"id": ",".join(chunk)}
        try:
            r = requests.get(base, params=params, timeout=timeout)
            r.raise_for_status()
            data = r.json()
        except Exception:
            continue
        for item in data.get("results", []):
            tid = str(item.get("trackId") or "")
            if tid:
                out[tid] = item
    return out

# -------------------------
# Normalizers
# -------------------------
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

# -------------------------
# Public API
# -------------------------
def parse_apple_playlist_from_url(url: str):
    """
    Return rows of tracks:
      {
        'raw_title', 'raw_artist', 'raw_album', 'raw_isrc',
        'norm_title', 'norm_artist'
      }
    Uses multiple extraction strategies to survive Apple markup variance.
    """
    if not is_apple_playlist_url(url):
        raise ValueError("That doesn't look like an Apple Music playlist link.")

    url = normalize_apple_url(url)
    html_text = _http_get(url)

    # Try A) OG meta
    song_urls = _extract_song_urls_from_playlist_html(html_text)
    ids = _extract_ids_from_urls(song_urls)

    # Try B) JSON-LD
    if not ids:
        ids = _extract_song_ids_from_jsonld(html_text)

    # Try C) Regex sweep
    if not ids:
        ids = _extract_song_ids_by_regex(html_text)

    # Still nothing? Surface a clear error back to the UI.
    if not ids:
        # Let the caller show this in 'flash_error'
        raise ValueError("No track IDs found on that Apple Music page. "
                         "The playlist may be private, empty, or Apple changed the markup.")

    # iTunes metadata (chunked)
    itunes_map = _lookup_tracks_itunes_chunked(ids)

    rows = []
    seen = set()
    for tid in ids:
        if tid in seen:
            continue
        seen.add(tid)
        meta = itunes_map.get(tid, {})
        title = meta.get('trackName', '')
        artist = meta.get('artistName', '')
        album = meta.get('collectionName', '')
        isrc = meta.get('isrc', '')

        rows.append({
            'raw_title': title,
            'raw_artist': artist,
            'raw_album': album,
            'raw_isrc': isrc,
            'norm_title': normalize_title(title),
            'norm_artist': normalize_artist(artist),
        })
    return rows
