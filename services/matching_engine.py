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

import re, unicodedata

def normalize_title(s: str) -> str:
    s = (s or "").lower()
    s = unicodedata.normalize("NFKD", s)
    s = s.replace("’", "'")
    # m.a.a.d -> m a a d ; also handle middle dot
    s = re.sub(r"[.\u00B7]", " ", s)
    # drop (feat ...)/(with ...) in the title itself
    s = re.sub(r"\s*\((feat|with)[^)]+\)", "", s)
    s = re.sub(r"[^a-z0-9'\s]+", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s

def normalize_artist(artist: str) -> str:
    if not artist:
        return ""
    a = artist
    a = FEAT_RE.sub("", a)
    a = WHITESPACE_RE.sub(" ", a).strip().lower()
    return a

import re, unicodedata

ALBUM_STRIP_RE = re.compile(
    (
        r"\s*[([{]\s*(?:"
        r"deluxe|expanded|bonus|remaster(?:ed)?(?:\s+\d{2,4})?|"
        r"anniversary|edition|single|explicit|clean|commentary|instrumental|"
        r"live|demo|reissue|super\s*deluxe|special\s*edition"
        r")[^)\]}]*[)\]}]"
    ),
    flags=re.IGNORECASE,
)

def normalize_album(s: str) -> str:
    if not s:
        return ""
    s = unicodedata.normalize("NFKC", s)
    s = ALBUM_STRIP_RE.sub("", s)
    s = re.sub(r"\s+", " ", s).strip().lower()
    return s

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
    
WHITESPACE_RE = re.compile(r"\s+")

def _unify(s: str) -> str:
    """
    Light-weight normalization for raw comparisons:
    - keep apostrophes
    - normalize curly quotes/dashes
    - collapse whitespace
    """
    if not s:
        return ""
    s = (s.replace("’", "'")
         .replace("‘", "'")
         .replace("“", '"')
         .replace("”", '"')
         .replace("—", " ")
         .replace("–", " ")
         .replace("-", " "))
    return WHITESPACE_RE.sub(" ", s).strip()
    
def _field_clause(field: str, value: str) -> str:
    if not value: return ""
    v = value.replace('"', " ").strip()  # strip embedded double quotes
    return f'{field}:"{v}"' if v else ""

_SEP_RE = re.compile(r"\s*(?:,|&|/|;|\+| x | × | with | and | vs\.?)\s*", re.I)
def _artist_variants(artist_raw: str) -> list[str]:
    base = (artist_raw or "").strip()
    out, seen = [], set()
    if base:
        n = normalize_artist(base)
        if n and n not in seen:
            seen.add(n); out.append(base)
    trimmed = re.sub(r"\s+(?:feat|ft)\.?\s+.*$", "", base, flags=re.I).strip()
    if trimmed and normalize_artist(trimmed) not in seen:
        seen.add(normalize_artist(trimmed)); out.append(trimmed)
    for piece in _SEP_RE.split(trimmed or base):
        p = piece.strip()
        if not p: continue
        n = normalize_artist(p)
        if n and n not in seen:
            seen.add(n); out.append(p)
    return out[:5]

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

def _primary_in_artists(apple_artist_norm: str, sp_artists: list) -> bool:
    # sp_artists is the Spotify "artists" array
    sp_names = ", ".join(a["name"] for a in (sp_artists or []) if a.get("name"))
    a_set = set((apple_artist_norm or "").split())
    sp_set = set(normalize_artist(sp_names).split())
    return bool(a_set) and a_set.issubset(sp_set)

# ---------- Matching pipeline per track ----------

def match_one_track(
    sp: SpotifyClient,
    track: Dict[str, Any],
    cache: Dict[str, Any],
    fuzzy_threshold: int = 85,
) -> Dict[str, Any]:
    """
    Matching pipeline for a single Apple track dict.
    Expects keys like: Title/title, Artist/artist, Album/album, ISRC/isrc, duration_ms.
    Returns: {status, spotify_id, method, score, debug}
    """
    import re
    from typing import List, Tuple

    # --- local helpers (safe if globals don't exist) ---
    WHITESPACE_RE = re.compile(r"\s+")
    SEP_RE = re.compile(r"\s*(?:,|&|/|;|\+| x | × | with | and | vs\.?)\s*", re.I)

    def __unify_local(s: str) -> str:
        """Light 'raw' unify: keep apostrophes, normalize quotes/dashes, turn dots into spaces, collapse ws."""
        if not s:
            return ""
        try:
            # if a global _unify exists, use it but also fix dotted acronyms
            return _unify(s.replace(".", " "))
        except Exception:
            pass
        s = (s.replace("’", "'").replace("‘", "'")
               .replace("“", '"').replace("”", '"')
               .replace("—", " ").replace("–", " ").replace("-", " ")
               .replace(".", " "))
        return WHITESPACE_RE.sub(" ", s).strip()

    def _field_clause_local(field: str, value: str) -> str:
        """Build Spotify fielded clause like track:"..."; strip internal double quotes (keep apostrophes)."""
        if not value:
            return ""
        v = str(value).replace('"', " ").strip()
        return f'{field}:"{v}"' if v else ""

    def _artist_variants_local(artist_raw: str) -> list[str]:
        """Return plausible artist strings: original, no 'feat.', then split pieces."""
        base = (artist_raw or "").strip()
        out, seen = [], set()
        if base:
            n = normalize_artist(base)
            if n and n not in seen:
                seen.add(n); out.append(base)

        trimmed = re.sub(r"\s+(?:feat|ft)\.?\s+.*$", "", base, flags=re.I).strip()
        if trimmed and normalize_artist(trimmed) not in seen:
            seen.add(normalize_artist(trimmed)); out.append(trimmed)

        for piece in SEP_RE.split(trimmed or base):
            p = piece.strip()
            if not p:
                continue
            n = normalize_artist(p)
            if n and n not in seen:
                seen.add(n); out.append(p)

        return out[:5]

    def _norm_album_local(s: str) -> str:
        try:
            return normalize_album(s)
        except Exception:
            # fallback: album normalized similar to title
            return normalize_title(s)

    # --- raw fields (preserve punctuation for search strength) ---
    title  = _get(track, "Title", "title")
    artist = _get(track, "Artist", "artist")
    album  = _get(track, "Album", "album")
    isrc   = (_get(track, "ISRC", "isrc") or "").strip()
    dur_ms = track.get("duration_ms")

    # --- normalized triplet (uses your helpers / Norm columns if present) ---
    nt, na, nb = normalized_triplet_from_track(track)

    # ---------------- 1) ISRC fast path ----------------
    if isrc:
        k = f"isrc:{isrc}"
        cand = cache.get(k)
        if cand is None:
            cand = sp.search_by_isrc(isrc)
            cache[k] = cand
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
                    "album": (cand.get("album") or {}).get("name"),
                },
            }

    # ---------------- 2) Structured search (RAW first, multi-artist aware) ----------------
    raw_title, raw_artist, raw_album = title, artist, album
    candidates: List[dict] = []
    query_trace: List[Tuple[str, int]] = []  # optional for debugging

    def do_search(q: str, limit: int = 50) -> List[dict]:
        base = {"q": q, "type": "track", "limit": limit}
        attempts = [  # client-credentials safe first
            {},                 # no market (works with app-only tokens)
            {"market": "US"},   # explicit country fallback
            # {"market": "from_token"},  # only enable if you KNOW you have a user token
        ]
        last_err = None
        for extra in attempts:
            try:
                data = sp._request("GET", SPOTIFY_SEARCH_URL, {**base, **extra})
                items = (data or {}).get("tracks", {}).get("items", []) or []
                if items:
                    return items
            except Exception as e:
                last_err = str(e)[:120]
                # swallow and try the next attempt
                continue
        # attach a tiny hint to query_trace if present (safe no-op if absent)
        try:
            query_trace.append((f"err:{last_err or 'no_items'}", 0))
        except Exception:
            pass
        return []


    artist_try = _artist_variants_local(raw_artist)
    if not artist_try:
        artist_try = [raw_artist] if raw_artist else []

    query_variants: List[Tuple[str, str]] = []

    # Per-artist passes (best-first)
    for a_raw in artist_try:
        # 1) RAW title+artist
        q = " ".join(x for x in [_field_clause_local("track", raw_title), _field_clause_local("artist", a_raw)] if x)
        if q: query_variants.append((f"q:raw_t+a:{a_raw}", q))

        # 2) NORMALIZED title+artist
        a_norm = normalize_artist(a_raw)
        q = " ".join(x for x in [_field_clause_local("track", nt), _field_clause_local("artist", a_norm)] if x)
        if q: query_variants.append((f"q:norm_t+a:{a_norm}", q))

        # 3) RAW track-only (artist omitted)
        q = _field_clause_local("track", raw_title)
        if q: query_variants.append(("q:raw_t_only", q))

    # Album-aware passes (after per-artist tries)
    q = " ".join(x for x in [_field_clause_local("track", raw_title), _field_clause_local("artist", raw_artist), _field_clause_local("album", raw_album)] if x)
    if q: query_variants.append(("q:raw_t+a+b", q))

    q = " ".join(x for x in [_field_clause_local("track", nt), _field_clause_local("artist", na), _field_clause_local("album", nb)] if x)
    if q: query_variants.append(("q:norm_t+a+b", q))

    # Free-text fallback
    ft = " ".join(x for x in [raw_title, raw_artist] if x).strip()
    if ft: query_variants.append(("q:raw_free", ft))

    # Execute with per-variant cache; merge & dedupe
    seen: set = set()
    for key_prefix, q in query_variants:
        qkey = f"{key_prefix}|{q}"
        got = cache.get(qkey)
        if got is None:
            got = do_search(q, limit=50)
            cache[qkey] = got
        query_trace.append((key_prefix, len(got or [])))

        if got:
            for c in got:
                cid = c.get("id")
                if cid and cid not in seen:
                    seen.add(cid)
                    candidates.append(c)
        if len(candidates) >= 15:
            break

    # ---------------- 2a) RAW exact short-circuit (prefer precise versions) ----------------
    if candidates:
        u_raw_title  = __unify_local(raw_title or "").lower()
        u_raw_artist = normalize_artist(raw_artist or "")
        u_raw_album  = __unify_local(raw_album or "").lower()

        for c in candidates:
            u_sp_title = __unify_local(c.get("name", "")).lower()
            if u_sp_title == u_raw_title:
                sp_art = ", ".join(a["name"] for a in c.get("artists", []) if a.get("name"))
                if normalize_artist(sp_art) == u_raw_artist:
                    sp_album = (c.get("album") or {}).get("name", "")
                    if not u_raw_album or __unify_local(sp_album).lower() == u_raw_album:
                        return {
                            "status": "matched",
                            "spotify_id": c["id"],
                            "method": "query_exact_raw",
                            "score": 99,
                            "debug": {
                                "reason": "raw title/artist (and album) exact",
                                "spotify_name": c.get("name"),
                                "artists": [a["name"] for a in c.get("artists", [])],
                                "album": (c.get("album") or {}).get("name"),
                                "query_trace": query_trace,
                            },
                        }

    # ---------------- 2b) Quick normalized exact-ish check ----------------
    if candidates:
        for c in candidates:
            if normalize_title(c.get("name", "")) == nt:
                sp_art = ", ".join(a["name"] for a in c.get("artists", []) if a.get("name"))
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
                            "album": (c.get("album") or {}).get("name"),
                            "query_trace": query_trace,
                        },
                    }

    # ---------------- 3) Fuzzy ranking with SAFE tie-breaks + primary-artist rule ----------------
    if candidates:
        best = None
        best_score = -1
        best_dbg = {}

        # for acceptance and bonus we need Apple primary artist
        primary_apple = (_artist_variants_local(artist)[:1] or [""])[0]
        primary_apple_norm = normalize_artist(primary_apple)

        for c in candidates:
            sp_title   = c.get("name", "") or ""
            sp_artists = ", ".join(a["name"] for a in (c.get("artists") or []) if a.get("name"))
            sp_album   = (c.get("album") or {}).get("name", "") or ""
            sp_dur     = c.get("duration_ms")  # may be None

            s_title  = fuzz.token_set_ratio(nt, normalize_title(sp_title))
            s_artist = fuzz.token_set_ratio(na, normalize_artist(sp_artists))
            s_album  = fuzz.token_set_ratio(nb, _norm_album_local(sp_album)) if nb else 0
            
            primary_present = _primary_in_artists(na, c.get("artists"))

            # If the primary artist is present, don't let extra features tank us
            if primary_present and s_artist < 95:
                s_artist = max(s_artist, 95)

            # weighted overall score
            overall = round(0.55 * s_title + 0.35 * s_artist + 0.10 * s_album)
            
            # Tiny bonus when the title is essentially exact and primary is present
            if s_title >= 99 and primary_present:
                overall += 3

            # tiny bonus if normalized titles match exactly
            if normalize_title(sp_title) == nt:
                overall += 1

            # primary artist presence bonus (handles "feat. X" / multiple artists)
            sp_artists_norm = normalize_artist(sp_artists)
            primary_present = bool(primary_apple_norm) and (primary_apple_norm in sp_artists_norm)
            if primary_present:
                overall += 3

            # duration delta (safe)
            dur_delta_ms = None if (dur_ms is None or sp_dur is None) else abs(dur_ms - sp_dur)
            dur_bonus = 3 if isinstance(dur_delta_ms, int) and dur_delta_ms <= 3000 else 0
            overall += dur_bonus

            # SAFE tie-break values
            album_score_for_tie = s_album if isinstance(s_album, (int, float)) else 0
            dur_delta_for_tie   = dur_delta_ms if isinstance(dur_delta_ms, int) else 10**9
            tie_key = (overall, album_score_for_tie, -dur_delta_for_tie)

            prev_album_score = best_dbg.get("album_score", 0) or 0
            prev_dur_delta   = best_dbg.get("duration_delta_ms", 10**9)
            if not isinstance(prev_dur_delta, int):
                prev_dur_delta = 10**9
            prev_key = (best_score, prev_album_score, -prev_dur_delta)

            if (best is None) or (tie_key > prev_key):
                best = c
                best_score = overall
                best_dbg = {
                    "apple_title_norm": nt,
                    "apple_artist_norm": na,
                    "apple_album_norm": nb,
                    "spotify_title_norm": normalize_title(sp_title),
                    "spotify_artist_norm": normalize_artist(sp_artists),
                    "spotify_album_norm": _norm_album_local(sp_album),
                    "primary_present": primary_present,
                    "title_score": s_title,
                    "artist_score": s_artist,
                    "album_score": s_album,
                    "overall": overall,
                    "duration_delta_ms": dur_delta_ms,
                    "duration_bonus": dur_bonus,
                    "primary_present": primary_present,
                }

        if best:
            # acceptance rule: if title is ~perfect and primary artist present, accept as matched
            best_sp_artists = ", ".join(a["name"] for a in (best.get("artists") or []) if a.get("name"))
            best_sp_artists_norm = normalize_artist(best_sp_artists)
            primary_present = bool(primary_apple_norm) and (primary_apple_norm in best_sp_artists_norm)

            status = "matched" if (best_score >= 95) else (
                "matched" if (primary_present and best_dbg.get("title_score", 0) >= 96) else (
                    "fuzzy_matched" if best_score >= fuzzy_threshold else "not_found"
                )
            )

            return {
                "status": status,
                "spotify_id": best["id"] if status != "not_found" else None,
                "method": "fuzzy",
                "score": best_score,
                "debug": {
                    "spotify_name": best.get("name"),
                    "artists": [a["name"] for a in best.get("artists", [])],
                    "album": (best.get("album") or {}).get("name"),
                    "query_trace": query_trace,
                    **best_dbg,
                },
            }

    # ---------------- Fallback: nothing found ----------------
    return {
        "status": "not_found",
        "spotify_id": None,
        "method": "none",
        "score": 0,
        "debug": {"reason": "no viable candidates", "query_trace": query_trace},
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
