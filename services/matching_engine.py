# services/matching_engine.py
from __future__ import annotations
from typing import Dict, Any, List, Optional, Tuple
import re
import time
import logging
import requests
from rapidfuzz import fuzz, process

logger = logging.getLogger(__name__)

SPOTIFY_SEARCH_URL = "https://api.spotify.com/v1/search"
SPOTIFY_TRACK_URL  = "https://api.spotify.com/v1/tracks"

# ---------- Normalization helpers ----------

PARENS_RE = re.compile(r"\s*[\(\[][^)\]]*[\)\]]\s*")
SUFFIXES_RE = re.compile(r"\s*-\s*(remaster(ed)?(\s*\d{2,4})?|live|mono|stereo|single version|radio edit|deluxe|explicit)\b.*", re.I)
FEAT_RE = re.compile(r"\s*\bfeat\.?.*|\s*\bft\.?.*", re.I)
WHITESPACE_RE = re.compile(r"\s+")

def normalize_title(title: str) -> str:
    if not title:
        return ""
    t = title
    t = PARENS_RE.sub(" ", t)            # drop things in parentheses
    t = FEAT_RE.sub(" ", t)              # drop “feat. …”
    t = SUFFIXES_RE.sub("", t)           # drop “- remaster”, “- live”, etc.
    t = t.replace("—", " ").replace("-", " ")
    t = WHITESPACE_RE.sub(" ", t).strip().lower()
    return t

def normalize_artist(artist: str) -> str:
    if not artist:
        return ""
    a = artist
    a = FEAT_RE.sub("", a)
    a = WHITESPACE_RE.sub(" ", a).strip().lower()
    return a

def canonical_key(title: str, artist: str) -> str:
    return f"{normalize_title(title)}|{normalize_artist(artist)}"

# ---------- Spotify API helpers ----------

class SpotifyClient:
    def __init__(self, access_token: str, per_call_sleep: float = 0.15):
        self.access_token = access_token
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {access_token}"})
        self.per_call_sleep = per_call_sleep

    def _request(self, method: str, url: str, params: dict) -> dict:
        while True:
            resp = self.session.request(method, url, params=params, timeout=20)
            if resp.status_code == 429:
                retry = int(resp.headers.get("Retry-After", "1"))
                logger.info("Hit rate limit. Sleeping %s sec", retry)
                time.sleep(retry)
                continue
            if not resp.ok:
                logger.warning("Spotify API error %s: %s", resp.status_code, resp.text[:300])
                return {}
            # gentle throttle between requests to be nice to the API
            if self.per_call_sleep:
                time.sleep(self.per_call_sleep)
            return resp.json()

    def search_by_isrc(self, isrc: str) -> Optional[dict]:
        if not isrc:
            return None
        data = self._request("GET", SPOTIFY_SEARCH_URL, {"q": f"isrc:{isrc}", "type": "track", "limit": 5})
        items = (data or {}).get("tracks", {}).get("items", [])
        return items[0] if items else None

    def search_by_query(self, title: str, artist: str) -> List[dict]:
        # Use field filters. track: and artist:
        q_title = normalize_title(title)
        q_artist = normalize_artist(artist)
        if not q_title and not q_artist:
            return []
        # Prefer structured query, then fall back to raw if needed
        q = " ".join([f'track:"{q_title}"' if q_title else "", f'artist:"{q_artist}"' if q_artist else ""]).strip()
        params = {"q": q or (title + " " + artist), "type": "track", "limit": 10}
        data = self._request("GET", SPOTIFY_SEARCH_URL, params)
        return (data or {}).get("tracks", {}).get("items", [])

# ---------- Fuzzy scoring ----------

def score_candidate(apple_title: str, apple_artist: str, sp: dict) -> Tuple[int, Dict[str, Any]]:
    sp_title = sp.get("name", "")
    sp_artists = ", ".join([a["name"] for a in sp.get("artists", [])]) if sp.get("artists") else ""
    nt_a = normalize_title(apple_title)
    na_a = normalize_artist(apple_artist)
    nt_s = normalize_title(sp_title)
    na_s = normalize_artist(sp_artists)

    title_score = fuzz.token_set_ratio(nt_a, nt_s)
    artist_score = fuzz.token_set_ratio(na_a, na_s)
    # Weighted blend favors title slightly
    overall = round(0.6 * title_score + 0.4 * artist_score)

    debug = {
        "apple_title_norm": nt_a,
        "apple_artist_norm": na_a,
        "spotify_title_norm": nt_s,
        "spotify_artist_norm": na_s,
        "title_score": title_score,
        "artist_score": artist_score,
        "overall": overall,
    }
    return overall, debug

# ---------- Matching pipeline per track ----------

def match_one_track(
    sp: SpotifyClient,
    track: Dict[str, Any],
    cache: Dict[str, Any],
    fuzzy_threshold: int = 85,
) -> Dict[str, Any]:
    """
    Inputs:
      - sp: SpotifyClient (handles auth/throttle)
      - track: dict with at least Title/Artist; ideally Album, ISRC, duration_ms
      - cache: dict shared across a job (for ISRC and query results)
      - fuzzy_threshold: score boundary for 'fuzzy_matched' (default 85)

    Returns:
      {
        "status": "matched"|"fuzzy_matched"|"not_found",
        "spotify_id": str|None,
        "method": "isrc"|"query_exact_norm"|"fuzzy"|"none",
        "score": int,
        "debug": {...}
      }
    """
    title   = _get(track, "Title", "title")
    artist  = _get(track, "Artist", "artist")
    album   = _get(track, "Album", "album")
    isrc    = _get(track, "ISRC", "isrc").strip()
    dur_ms  = track.get("duration_ms")

    # normalized fields (uses your precomputed Norm Title/Artist if present)
    nt, na, nb = normalized_triplet_from_track(track)

    # ---------------- 1) ISRC fast path ----------------
    if isrc:
        key = f"isrc:{isrc}"
        cand = cache.get(key)
        if cand is None:
            cand = sp.search_by_isrc(isrc)
            cache[key] = cand
        if cand:
            return {
                "status": "matched",
                "spotify_id": cand["id"],
                "method": "isrc",
                "score": 100,
                "debug": {
                    "reason": "isrc exact",
                    "spotify_name": cand.get("name"),
                    "artists": [a["name"] for a in cand.get("artists", [])],
                    "album": cand.get("album", {}).get("name"),
                },
            }

    # ---------------- 2) Structured query (normalized) ----------------
    qkey = f"q:{nt}|{na}|{nb}"
    candidates = cache.get(qkey)
    if candidates is None:
        # build fielded query; include album if available
        parts = []
        if nt: parts.append(f'track:"{nt}"')
        if na: parts.append(f'artist:"{na}"')
        if nb: parts.append(f'album:"{nb}"')
        q = " ".join(parts).strip()
        if not q:
            q = " ".join(x for x in [title, artist, album] if x).strip()
        data = sp._request("GET", SPOTIFY_SEARCH_URL, {"q": q, "type": "track", "limit": 10})
        candidates = (data or {}).get("tracks", {}).get("items", [])
        cache[qkey] = candidates

    # Quick normalized exact-ish check (title+artist match after normalization)
    if candidates:
        for c in candidates:
            if normalize_title(c.get("name", "")) == nt:
                sp_art = ", ".join(a["name"] for a in c.get("artists", []))
                if normalize_artist(sp_art) == na:
                    return {
                        "status": "matched",
                        "spotify_id": c["id"],
                        "method": "query_exact_norm",
                        "score": 98,
                        "debug": {
                            "reason": "normalized title and artist match",
                            "spotify_name": c.get("name"),
                            "artists": [a["name"] for a in c.get("artists", [])],
                            "album": c.get("album", {}).get("name"),
                        },
                    }

    # ---------------- 3) Fuzzy ranking with album + duration tie-breaks ----------------
    if candidates:
        best = None
        best_score = -1
        best_dbg: Dict[str, Any] = {}

        for c in candidates:
            sp_title   = c.get("name", "")
            sp_artists = ", ".join(a["name"] for a in c.get("artists", [])) if c.get("artists") else ""
            sp_album   = c.get("album", {}).get("name", "")
            sp_dur     = c.get("duration_ms")

            s_title  = fuzz.token_set_ratio(nt, normalize_title(sp_title))
            s_artist = fuzz.token_set_ratio(na, normalize_artist(sp_artists))
            s_album  = fuzz.token_set_ratio(nb, normalize_album(sp_album)) if nb else 0

            # Weighted blend: title 55%, artist 35%, album 10%
            overall = round(0.55 * s_title + 0.35 * s_artist + 0.10 * s_album)

            # tiny duration bonus if within ±3s
            dur_bonus = 0
            if isinstance(dur_ms, int) and isinstance(sp_dur, int) and abs(dur_ms - sp_dur) <= 3000:
                dur_bonus = 3
                overall += dur_bonus

            # tie-break on (overall, album score, closer duration)
            dur_delta = abs((dur_ms or 10**9) - (sp_dur or 10**9))
            current_key = (overall, s_album, -dur_delta)

            prev_key = (
                best_score,
                best_dbg.get("album_score", -1),
                -best_dbg.get("duration_delta_ms", 10**9),
            )

            if (best is None) or (current_key > prev_key):
                best = c
                best_score = overall
                best_dbg = {
                    "apple_title_norm": nt,
                    "apple_artist_norm": na,
                    "apple_album_norm": nb,
                    "spotify_title_norm": normalize_title(sp_title),
                    "spotify_artist_norm": normalize_artist(sp_artists),
                    "spotify_album_norm": normalize_album(sp_album),
                    "title_score": s_title,
                    "artist_score": s_artist,
                    "album_score": s_album,
                    "overall": overall,
                    "duration_delta_ms": None if (dur_ms is None or sp_dur is None) else abs(dur_ms - sp_dur),
                    "duration_bonus": dur_bonus,
                }

        if best:
            status = "matched" if best_score >= 95 else ("fuzzy_matched" if best_score >= fuzzy_threshold else "not_found")
            return {
                "status": status,
                "spotify_id": best["id"] if status != "not_found" else None,
                "method": "fuzzy",
                "score": best_score,
                "debug": {
                    "spotify_name": best.get("name"),
                    "artists": [a["name"] for a in best.get("artists", [])],
                    "album": best.get("album", {}).get("name"),
                    **best_dbg,
                },
            }

    # ---------------- Fallback: nothing found ----------------
    return {
        "status": "not_found",
        "spotify_id": None,
        "method": "none",
        "score": 0,
        "debug": {"reason": "no viable candidates"},
    }

# --- add helper to read multiple possible keys (case/space tolerant) ---
def _get(d, *names, default=""):
    for n in names:
        if n in d:            # exact match first
            return d[n] if d[n] is not None else default
    # try relaxed lookup (case + spaces)
    lower = {k.lower().replace(" ", ""): k for k in d.keys()}
    for n in names:
        key = n.lower().replace(" ", "")
        if key in lower:
            v = d[lower[key]]
            return v if v is not None else default
    return default

def normalize_album(album: str) -> str:
    if not album:
        return ""
    a = album
    a = PARENS_RE.sub(" ", a)
    a = SUFFIXES_RE.sub("", a)
    a = a.replace("—", " ").replace("-", " ")
    a = WHITESPACE_RE.sub(" ", a).strip().lower()
    return a

# --- helper: combine title/artist/album normalization in one place ---
def normalized_triplet_from_track(track: Dict[str, Any]) -> tuple[str, str, str]:
    """
    Returns (nt, na, nb) = normalized title, artist, album.
    Prefers your precomputed columns 'Norm Title' and 'Norm Artist' if present/non-empty.
    Falls back to normalize_* helpers otherwise.
    """
    # prefer your precomputed columns if they exist and are non-empty
    nt_pre = _get(track, "Norm Title", "norm_title", default=None)
    na_pre = _get(track, "Norm Artist", "norm_artist", default=None)

    title_raw  = _get(track, "Title", "title")
    artist_raw = _get(track, "Artist", "artist")
    album_raw  = _get(track, "Album", "album")

    nt = nt_pre.strip().lower() if isinstance(nt_pre, str) and nt_pre.strip() else normalize_title(title_raw)
    na = na_pre.strip().lower() if isinstance(na_pre, str) and na_pre.strip() else normalize_artist(artist_raw)
    nb = normalize_album(album_raw)

    return nt, na, nb

# ---------- Batch runner with throttling and caching ----------

def match_tracks(
    access_token: str,
    apple_tracks: List[Dict[str, Any]],
    fuzzy_threshold: int = 85,
) -> Dict[str, Any]:
    """
    apple_tracks: list of dicts with title, artist, isrc, album, duration_ms
    returns summary with buckets and per-track results
    """
    client = SpotifyClient(access_token)
    cache: Dict[str, Any] = {}
    results: List[Dict[str, Any]] = []

    for t in apple_tracks:
        try:
            res = match_one_track(client, t, cache, fuzzy_threshold=fuzzy_threshold)
            results.append({**t, **res})
        except Exception as e:
            logger.exception("Error matching track: %s", t)
            results.append({**t, "status": "not_found", "spotify_id": None, "method": "error", "score": 0, "debug": {"exception": str(e)}})

    # Bucket summary
    buckets = {"matched": 0, "fuzzy_matched": 0, "not_found": 0}
    for r in results:
        buckets[r["status"]] = buckets.get(r["status"], 0) + 1

    return {"summary": buckets, "results": results}
