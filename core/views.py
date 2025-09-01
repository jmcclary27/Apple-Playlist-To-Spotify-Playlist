# core/views.py
import os, io, urllib.parse, base64, datetime, math, json, re, time, uuid
from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_POST, require_GET
from django.conf import settings
import requests

from services.matching_engine import match_tracks
from .forms import LinkForm
from .parsers import parse_apple_playlist_from_url
from pymongo import ReturnDocument
from bson.objectid import ObjectId

# ---------------------------------------------------------------------
# Debug: environment / session status
# ---------------------------------------------------------------------
@require_GET
def debug_status(request):
    return JsonResponse({
        "has_user_token": bool(request.session.get("spotify_access_token")),
        "user_token_expires_in": (request.session.get("spotify_expires_at") or 0) - int(time.time()),
        "has_refresh_token": bool(request.session.get("spotify_refresh_token")),
        "has_client_id": bool(os.environ.get("SPOTIFY_CLIENT_ID")),
        "has_client_secret": bool(os.environ.get("SPOTIFY_CLIENT_SECRET")),
        "has_app_token": bool(request.session.get("spotify_app_access_token")),
        "app_token_expires_in": (request.session.get("spotify_app_expires_at") or 0) - int(time.time()),
        "allowed_hosts": settings.ALLOWED_HOSTS,
        "csrf_trusted_origins": getattr(settings, "CSRF_TRUSTED_ORIGINS", []),
    })

# ---------------------------------------------------------------------
# Spotify token helpers
# Prefer a valid user token from session; else fall back to app token.
# (App token = Client Credentials; good for search/matching only.)
# ---------------------------------------------------------------------
SPOTIFY_TOKEN_URL = "https://accounts.spotify.com/api/token"

def _get_user_token_from_session(request):
    """Return a valid user access token if present & not expired; else None."""
    token = request.session.get("spotify_access_token")
    expires_at = request.session.get("spotify_expires_at")  # epoch secs
    if token and (not expires_at or time.time() < (expires_at - 60)):
        return token
    return None

def _get_app_token(request):
    """
    Fetch/cached Client Credentials token in the session.
    Requires SPOTIFY_CLIENT_ID / SPOTIFY_CLIENT_SECRET in env.
    """
    cid = os.environ.get("SPOTIFY_CLIENT_ID")
    csec = os.environ.get("SPOTIFY_CLIENT_SECRET")
    if not (cid and csec):
        return None

    tok = request.session.get("spotify_app_access_token")
    exp = request.session.get("spotify_app_expires_at")
    if tok and isinstance(exp, (int, float)) and time.time() < (exp - 60):
        return tok

    resp = requests.post(
        SPOTIFY_TOKEN_URL,
        data={"grant_type": "client_credentials"},
        auth=(cid, csec),
        timeout=15,
    )
    if not resp.ok:
        # Optional: log resp.text for troubleshooting
        return None

    data = resp.json()
    tok = data.get("access_token")
    expires_in = int(data.get("expires_in", 3600))
    if not tok:
        return None

    request.session["spotify_app_access_token"] = tok
    request.session["spotify_app_expires_at"] = int(time.time()) + expires_in
    request.session.modified = True
    return tok

def _get_any_spotify_token(request):
    """
    Unified getter used by match_view:
    - Prefer a valid user token from session (if you saved one).
    - Else fall back to app token (client credentials).
    Returns token string or None.
    """
    return _get_user_token_from_session(request) or _get_app_token(request)

# ---------------------------------------------------------------------
# Match endpoint (POST only)
# ---------------------------------------------------------------------
@require_POST
def match_view(request):
    access_token = _get_any_spotify_token(request)
    if not access_token:
        return HttpResponseBadRequest(
            "Spotify credentials missing: no valid user token found and app token not available. "
            "Set SPOTIFY_CLIENT_ID/SECRET on Render or complete Spotify login."
        )

    scope = (request.GET.get("scope") or "sample").lower()
    if scope == "all":
        apple_tracks = request.session.get("apple_tracks_all") or []
    else:
        apple_tracks = request.session.get("apple_tracks_sample") or []

    # Optional override via JSON body: {"tracks": [...]}
    if not apple_tracks and request.body:
        try:
            payload = json.loads(request.body.decode("utf-8"))
            if isinstance(payload, dict) and isinstance(payload.get("tracks"), list):
                apple_tracks = payload["tracks"]
        except Exception:
            pass

    if not apple_tracks:
        return HttpResponseBadRequest("No tracks found. Upload first, or POST a JSON body with {'tracks': [...]}.")

    # Run matcher
    data = match_tracks(access_token, apple_tracks, fuzzy_threshold=85)

    # ✅ Save matched Spotify IDs for the create step
    ids = _collect_matched_ids(data)
    request.session["matched_spotify_ids"] = ids
    request.session["matched_scope"] = scope
    if isinstance(data, dict):
        request.session["matched_summary"] = data.get("summary")
    request.session.modified = True

    return JsonResponse(data, safe=False)

# ---------------------------------------------------------------------
# Simple smoke routes
# ---------------------------------------------------------------------
def index(request):
    return HttpResponse("It works! 🎉")

def health(request):
    return HttpResponse("ok")

def _tokens_col():
    from .mongo import get_db
    return get_db().spotify_tokens

# ---------------------------------------------------------------------
# Upload via URL (your existing flow, now saves session flags for buttons)
# ---------------------------------------------------------------------
@ensure_csrf_cookie
def upload_link(request):
    if request.method == 'POST':
        form = LinkForm(request.POST)
        if not form.is_valid():
            return HttpResponseBadRequest("Invalid URL.")

        url = form.cleaned_data['url']
        try:
            rows = parse_apple_playlist_from_url(url)  # list[dict] with Title/Artist/Album/ISRC/...
        except Exception as e:
            return HttpResponseBadRequest(f"Error: {e}")

        request.session["apple_tracks_all"] = rows
        request.session["apple_tracks_sample"] = rows[:50]
        request.session["show_match_buttons"] = True
        request.session["track_count"] = len(rows)
        request.session["last_source"] = "link"
        request.session.modified = True

        return redirect("upload")  # root route named 'upload'

    # GET: render page, preview, and (if flags set) show match buttons
    uploaded_ok = request.session.pop("show_match_buttons", False)
    track_count = request.session.pop("track_count", 0)
    preview = (request.session.get("apple_tracks_all") or [])[:10]

    return render(request, 'upload.html', {
        'form': LinkForm(),
        'preview': preview,
        'count_total': len(request.session.get("apple_tracks_all") or []),
        'filename': request.GET.get('url', ''),
        'uploaded_ok': uploaded_ok,
        'track_count': track_count,
    })

# ---------------------------------------------------------------------
# OAuth + playlist creation helpers (your existing code; unchanged)
# ---------------------------------------------------------------------
def _json_error(message: str, status=400):
    return JsonResponse({"error": message}, status=status)

def spotify_login(request):
    state = uuid.uuid4().hex
    request.session["spotify_oauth_state"] = state

    client_id = os.environ.get("SPOTIFY_CLIENT_ID")
    redirect_uri = os.environ.get("SPOTIFY_REDIRECT_URI")
    scopes = os.environ.get("SPOTIFY_SCOPES", "playlist-modify-public playlist-modify-private user-read-email")

    missing = [k for k, v in {
        "SPOTIFY_CLIENT_ID": client_id,
        "SPOTIFY_REDIRECT_URI": redirect_uri
    }.items() if not v]
    if missing:
        return HttpResponse(f"Missing required env var(s): {', '.join(missing)}", status=500)

    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scopes,
        "state": state,
        "show_dialog": "false",
    }
    url = "https://accounts.spotify.com/authorize?" + urllib.parse.urlencode(params)
    return redirect(url)

def _spotify_token_exchange(code: str):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": os.environ["SPOTIFY_REDIRECT_URI"],
        "client_id": os.environ["SPOTIFY_CLIENT_ID"],
        "client_secret": os.environ["SPOTIFY_CLIENT_SECRET"],
    }
    r = requests.post("https://accounts.spotify.com/api/token", data=data, timeout=20)
    r.raise_for_status()
    return r.json()

def _collect_matched_ids(payload) -> list[str]:
    """
    Extract Spotify track IDs from your matcher output:
      {"summary": {...}, "results": [ { "status": "...", "spotify_id": "..." }, ... ]}
    Keeps only rows with status matched/fuzzy_matched. Dedupe, preserve order.
    """
    ids = []
    iterable = []
    if isinstance(payload, dict) and isinstance(payload.get("results"), list):
        iterable = payload["results"]
    elif isinstance(payload, list):
        iterable = payload

    for row in iterable:
        if not isinstance(row, dict):
            continue
        if row.get("status") in ("matched", "fuzzy_matched"):
            tid = row.get("spotify_id") or row.get("id") or row.get("track_id")
            if isinstance(tid, str) and len(tid) == 22:  # Spotify base62 track id
                ids.append(tid)

    seen, out = set(), []
    for t in ids:
        if t not in seen:
            seen.add(t); out.append(t)
    return out

def _now_ts(): return int(time.time())
_EXP_BUFFER = 60  # refresh 1 min early

def _save_tokens(spotify_user_id: str, access_token: str, refresh_token: str | None, expires_in: int):
    from .mongo import get_db
    expires_at = _now_ts() + int(expires_in) - _EXP_BUFFER
    update = {"$set": {
        "spotify_user_id": spotify_user_id,
        "access_token": access_token,
        "expires_at": expires_at,
        "updated_at": datetime.datetime.utcnow(),
    }}
    if refresh_token:
        update["$set"]["refresh_token"] = refresh_token
    get_db().spotify_tokens.update_one({"spotify_user_id": spotify_user_id}, update, upsert=True)

def _get_tokens(spotify_user_id: str):
    from .mongo import get_db
    return get_db().spotify_tokens.find_one({"spotify_user_id": spotify_user_id})

def _is_expired(doc: dict | None) -> bool:
    if not doc: return True
    return doc.get("expires_at", 0) <= _now_ts()

def _refresh_access_token(spotify_user_id: str) -> str:
    doc = _get_tokens(spotify_user_id)
    if not doc or not doc.get("refresh_token"):
        raise RuntimeError("No refresh token available")
    data = {
        "grant_type": "refresh_token",
        "refresh_token": doc["refresh_token"],
        "client_id": os.environ["SPOTIFY_CLIENT_ID"],
        "client_secret": os.environ["SPOTIFY_CLIENT_SECRET"],
    }
    r = requests.post("https://accounts.spotify.com/api/token", data=data, timeout=20)
    r.raise_for_status()
    payload = r.json()
    new_access = payload["access_token"]
    new_refresh = payload.get("refresh_token") or doc["refresh_token"]
    _save_tokens(spotify_user_id, new_access, new_refresh, payload["expires_in"])
    return new_access

def _get_valid_access_token(spotify_user_id: str) -> str:
    doc = _get_tokens(spotify_user_id)
    if _is_expired(doc):
        return _refresh_access_token(spotify_user_id)
    return doc["access_token"]

def _spotify_api(spotify_user_id: str, method: str, path: str, **kwargs):
    base = "https://api.spotify.com/v1"
    token = _get_valid_access_token(spotify_user_id)
    headers = kwargs.pop("headers", {})
    headers["Authorization"] = f"Bearer {token}"
    r = requests.request(method, base + path, headers=headers, timeout=20, **kwargs)
    if r.status_code == 401:
        token = _refresh_access_token(spotify_user_id)
        headers["Authorization"] = f"Bearer {token}"
        r = requests.request(method, base + path, headers=headers, timeout=20, **kwargs)
    r.raise_for_status()
    return r.json() if r.content else {}

# --- Helpers to extract Spotify IDs from arbitrary match output ---

_SPOTIFY_ID_RE = re.compile(r'\b[0-9A-Za-z]{22}\b')  # typical base62 track id

# --- Robust extractor: finds IDs in dicts, lists, URIs, and URLs ---
_SPOTIFY_ID_RE = re.compile(r'\b[0-9A-Za-z]{22}\b')  # base62 track id (22 chars)

def _iter_scalars(obj):
    """Yield every scalar value (including strings in lists), and dict keys too."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield ("key", k)
            yield from _iter_scalars(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _iter_scalars(v)
    else:
        yield ("value", obj)

def _extract_spotify_ids_from_match_result(match_result) -> list[str]:
    """
    Pull 22-char Spotify track IDs out of ANY nested structure:
    - dicts with keys like spotify_id/id/track_id/...
    - lists of strings (IDs, URIs, URLs)
    - strings containing URIs (spotify:track:ID) or URLs (…/track/ID)
    """
    ids: list[str] = []
    candidate_keys = {"spotify_id", "id", "track_id", "trackId", "spotify_track_id", "spotifyId", "spotify_uri", "uri"}

    def add(raw: str | None):
        if not isinstance(raw, str): return
        # If it's a full URI/URL, extract the 22-char token; else try direct match
        m = _SPOTIFY_ID_RE.search(raw)
        if m:
            tok = m.group(0)
            ids.append(tok)

    for kind, val in _iter_scalars(match_result):
        if kind == "key" and isinstance(val, str):
            # we only use keys to bias, real extraction happens on values below
            continue
        # Values: if it’s a dict value under a “candidate” key, or any string at all
        if isinstance(val, str):
            add(val)
        elif isinstance(val, dict):
            # If a dict contains a candidate key with a string, add it
            for k2 in candidate_keys:
                v2 = val.get(k2)
                if isinstance(v2, str):
                    add(v2)

    # Dedup while preserving order
    seen, out = set(), []
    for tid in ids:
        if tid not in seen:
            seen.add(tid)
            out.append(tid)
    return out


def _spotify_me(access_token: str):
    r = requests.get("https://api.spotify.com/v1/me",
                     headers={"Authorization": f"Bearer {access_token}"}, timeout=20)
    r.raise_for_status()
    return r.json()

def _duration_close(a: int|None, b: int|None, tolerance=4) -> bool:
    if a is None or b is None: return True
    return abs(a - b) <= tolerance

def _search_best(access_token: str, item: dict) -> str|None:
    qs = []
    title = item.get("title") or ""
    artist = item.get("artist") or ""
    album = item.get("album") or ""
    dur = item.get("duration_sec")

    qs.append(f'track:"{title}" artist:"{artist}" album:"{album}"')
    qs.append(f'track:"{title}" artist:"{artist}"')
    qs.append(f'{title} {artist}')

    for q in qs:
        r = requests.get("https://api.spotify.com/v1/search",
                         headers={"Authorization": f"Bearer {access_token}"},
                         params={"q": q, "type": "track", "limit": 5}, timeout=20)
        if r.status_code == 429:
            time.sleep(int(r.headers.get("Retry-After","1")))
            continue
        r.raise_for_status()
        items = r.json().get("tracks", {}).get("items", [])
        best = None
        for t in items:
            t_dur = int(round(t.get("duration_ms", 0)/1000))
            if not _duration_close(dur, t_dur):
                continue
            best = t
            break
        if best:
            return best["id"]
    return None

def _add_tracks(access_token: str, playlist_id: str, uris: list[str]):
    for i in range(0, len(uris), 100):
        chunk = uris[i:i+100]
        r = requests.post(f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks",
                          headers={"Authorization": f"Bearer {access_token}",
                                   "Content-Type": "application/json"},
                          json={"uris": [f"spotify:track:{tid}" for tid in chunk]},
                          timeout=20)
        r.raise_for_status()

def spotify_callback(request):
    from .mongo import get_db
    db = get_db()
    if "error" in request.GET:
        return HttpResponse(f"Spotify returned error: {request.GET.get('error')}", status=400)

    code = request.GET.get("code")
    state = request.GET.get("state")
    if not code or not state or state != request.session.get("spotify_oauth_state"):
        return HttpResponse("State mismatch or missing code.", status=400)

    tok = _spotify_token_exchange(code)
    at = tok["access_token"]
    me = _spotify_me(at)
    user_id = me["id"]
    request.session["spotify_user_id"] = user_id
    _save_tokens(user_id, at, tok.get("refresh_token"), tok["expires_in"])

    items = request.session.get("parsed_items") or []
    name = request.session.get("playlist_name") or "Imported from Apple Music"
    if not items:
        return redirect("/me")

    _save_tokens(user_id, at, tok.get("refresh_token"), tok["expires_in"])

    r = requests.post(
        f"https://api.spotify.com/v1/users/{user_id}/playlists",
        headers={"Authorization": f"Bearer {at}", "Content-Type": "application/json"},
        json={"name": name, "public": False, "description": "Imported from Apple Music"},
        timeout=20,
    )
    r.raise_for_status()
    playlist = r.json()
    playlist_id = playlist["id"]
    playlist_url = playlist.get("external_urls", {}).get("spotify", "")

    matched_ids, misses = [], []
    for idx, it in enumerate(items):
        tid = _search_best(at, it)
        if tid:
            matched_ids.append(tid)
        else:
            misses.append({"idx": idx, **it})

    if matched_ids:
        _add_tracks(at, playlist_id, matched_ids)

    conv_doc = {
        "created_at": datetime.datetime.utcnow(),
        "spotify_user_id": user_id,
        "playlist_name": name,
        "spotify_playlist_id": playlist_id,
        "spotify_playlist_url": playlist_url,
        "total": len(items),
        "matched": len(matched_ids),
        "unmatched": len(misses),
    }
    cid = db.conversions.insert_one(conv_doc).inserted_id
    if misses:
        for m in misses:
            m["conversion_id"] = cid
        db.unmatched.insert_many(misses)

    request.session.pop("parsed_items", None)
    request.session.pop("playlist_name", None)
    return redirect("conversion_detail", cid=str(cid))

@require_POST
def create_spotify_playlist(request):
    spotify_user_id = request.session.get("spotify_user_id")
    if not spotify_user_id:
        return _json_error("Not logged into Spotify", status=401)

    try:
        payload = json.loads(request.body or "{}")
    except json.JSONDecodeError:
        payload = {}

    source_name = payload.get("source_name") or "Imported from Apple Music"
    make_public = bool(payload.get("public", False))

    ids = payload.get("track_ids_in_order") or request.session.get("matched_spotify_ids") or []
    if not ids:
        return _json_error("No matched Spotify track IDs found. Run a match first.", status=400)

    # Dedupe while preserving order
    seen = set()
    ordered_ids = []
    for tid in ids:
        if tid and tid not in seen:
            seen.add(tid)
            ordered_ids.append(tid)

    # Valid access token (refresh if needed)
    at = _get_valid_access_token(spotify_user_id)

    # 1) Create the playlist
    create_resp = requests.post(
        f"https://api.spotify.com/v1/users/{spotify_user_id}/playlists",
        headers={"Authorization": f"Bearer {at}", "Content-Type": "application/json"},
        json={
            "name": source_name,
            "description": "Imported via Apple→Spotify by am2spot",
            "public": make_public,
            "collaborative": False
        },
        timeout=20,
    )
    if create_resp.status_code == 401:
        # refresh and retry once
        at = _refresh_access_token(spotify_user_id)
        create_resp = requests.post(
            f"https://api.spotify.com/v1/users/{spotify_user_id}/playlists",
            headers={"Authorization": f"Bearer {at}", "Content-Type": "application/json"},
            json={
                "name": source_name,
                "description": "Imported via Apple→Spotify by am2spot",
                "public": make_public,
                "collaborative": False
            },
            timeout=20,
        )
    create_resp.raise_for_status()
    playlist = create_resp.json()
    playlist_id = playlist["id"]
    playlist_url = playlist.get("external_urls", {}).get("spotify", "")

    # 2) Add tracks in chunks of 100
    total_added = 0
    add_url = f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks"
    headers = {"Authorization": f"Bearer {at}", "Content-Type": "application/json"}

    for i in range(0, len(ordered_ids), 100):
        chunk = ordered_ids[i:i+100]
        uris = [f"spotify:track:{tid}" for tid in chunk]
        r = requests.post(add_url, headers=headers, json={"uris": uris}, timeout=25)
        if r.status_code == 401:
            at = _refresh_access_token(spotify_user_id)
            headers["Authorization"] = f"Bearer {at}"
            r = requests.post(add_url, headers=headers, json={"uris": uris}, timeout=25)
        if r.status_code == 429:
            time.sleep(int(r.headers.get("Retry-After", "1")))
            r = requests.post(add_url, headers=headers, json={"uris": uris}, timeout=25)
        r.raise_for_status()
        total_added += len(chunk)

    # 3) Verify final count
    info = requests.get(
        f"https://api.spotify.com/v1/playlists/{playlist_id}",
        headers={"Authorization": f"Bearer {at}"},
        params={"fields": "name,tracks.total,external_urls"},
        timeout=20,
    )
    info.raise_for_status()
    meta = info.json()

    # 4) Optional: persist conversion summary like your callback does
    from .mongo import get_db
    db = get_db()
    conv_doc = {
        "created_at": datetime.datetime.utcnow(),
        "spotify_user_id": spotify_user_id,
        "playlist_name": meta.get("name") or source_name,
        "spotify_playlist_id": playlist_id,
        "spotify_playlist_url": meta.get("external_urls", {}).get("spotify", playlist_url),
        "total": len(ordered_ids),
        "matched": total_added,   # we deduped, so 'matched' == attempted to add
        "unmatched": max(0, len(ordered_ids) - total_added),
        "source": "create_playlist_endpoint",
        "public": make_public,
    }
    cid = db.conversions.insert_one(conv_doc).inserted_id

    # Response consumed by the front-end
    return JsonResponse({
        "playlist_id": playlist_id,
        "playlist_url": meta.get("external_urls", {}).get("spotify", playlist_url),
        "name": meta.get("name") or source_name,
        "total_tracks_added": meta.get("tracks", {}).get("total", total_added),
        "public": make_public,
        "conversion_id": str(cid),
    })

def conversion_detail(request, cid: str):
    from .mongo import get_db
    db = get_db()
    conv = db.conversions.find_one({"_id": ObjectId(cid)})
    if not conv:
        return HttpResponse("Conversion not found.", status=404)
    misses = list(db.unmatched.find({"conversion_id": conv["_id"]}))
    html = f"""
    <h1>Conversion complete</h1>
    <p>Playlist: <b>{conv['playlist_name']}</b></p>
    <p>Spotify: <a href="{conv.get('spotify_playlist_url','')}">{conv.get('spotify_playlist_url','Open')}</a></p>
    <p>Total: {conv['total']} | Matched: {conv['matched']} | Unmatched: {conv['unmatched']}</p>
    """
    if misses:
        html += "<h3>Unmatched</h3><ol>"
        for m in misses[:50]:
            dur = m.get("duration_sec")
            html += f"<li>{m.get('artist','')} — {m.get('title','')} ({m.get('album','')})"
            if dur: html += f" · {dur}s"
            html += "</li>"
        html += "</ol>"
        if len(misses) > 50:
            html += f"<p>And {len(misses) - 50} more…</p>"
    else:
        html += "<p>All tracks matched. 🎉</p>"
    return HttpResponse(html)

def me(request):
    spotify_user_id = request.session.get("spotify_user_id")
    if not spotify_user_id:
        return HttpResponse("Not logged in. Go to /preview and click Sign in with Spotify.", status=401)
    profile = _spotify_api(spotify_user_id, "GET", "/me")
    return HttpResponse(json.dumps({
        "id": profile.get("id"),
        "display_name": profile.get("display_name"),
        "email": profile.get("email"),
    }), content_type="application/json")
