import os, io, urllib.parse, base64, datetime, math, json, re
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
from .parsers import parse_apple_xml, parse_m3u
from .mongo import get_db, ensure_indexes
import time
import uuid
import requests  # you already import below, ok if duplicated once
from pymongo import ReturnDocument


def index(request):
    return HttpResponse("It works! 🎉")

def health(request):
    return HttpResponse("ok")

# Simple in-template HTML to keep it minimal (no separate template files needed)
FORM_HTML = """
<h1>Upload Apple Playlist</h1>
<p>Export from Apple Music/iTunes: File → Library → Export Playlist… (choose XML or M3U/M3U8).</p>
<form id="upl" method="POST" enctype="multipart/form-data">
  <input type="file" name="playlist" accept=".xml,.m3u,.m3u8" required />
  <input type="text" name="name" placeholder="New Spotify playlist name" required />
  <button type="submit">Upload</button>
</form>
<script>
  function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
  }
  document.addEventListener('DOMContentLoaded', function () {
    const form = document.getElementById('upl');
    const token = getCookie('csrftoken');
    if (token) {
      const input = document.createElement('input');
      input.type = 'hidden';
      input.name = 'csrfmiddlewaretoken';
      input.value = token;
      form.appendChild(input);
    }
  });
</script>
"""

SPOTIFY_SCOPES_DEFAULT = "playlist-modify-private playlist-modify-public user-read-email"

@ensure_csrf_cookie
def upload_playlist(request):
    if request.method == "GET":
        return HttpResponse(FORM_HTML)
    f = request.FILES.get("playlist")
    name = (request.POST.get("name") or "Imported from Apple Music").strip()[:100]
    if not f:
        return HttpResponseBadRequest("No file uploaded.")
    fname = f.name.lower()
    # Parse
    if fname.endswith(".xml"):
        items = parse_apple_xml(f.file)
    elif fname.endswith(".m3u") or fname.endswith(".m3u8"):
        items = parse_m3u(f.file)
    else:
        return HttpResponseBadRequest("Unsupported file type. Use XML or M3U/M3U8.")
    if not items:
        return HttpResponseBadRequest("No tracks found in file.")
    # Save minimal session state for the upcoming Spotify step
    request.session["parsed_items"] = items
    request.session["playlist_name"] = name
    return redirect("preview")

def preview(request):
    items = request.session.get("parsed_items") or []
    name = request.session.get("playlist_name") or "Imported from Apple Music"
    if not items:
        return redirect("upload")
    first = items[:10]
    html = "<h1>Preview</h1>"
    html += f"<p>Playlist name: <b>{name}</b></p>"
    html += f"<p>Parsed {len(items)} tracks. Showing first {len(first)}:</p><ol>"
    for it in first:
        html += f"<li>{it['artist']} — {it['title']} ({it.get('album','')})</li>"
    html += "</ol>"
    html += '<p><a href="/auth/spotify/login">Continue: Sign in with Spotify</a></p>'
    return HttpResponse(html)


import requests
from bson.objectid import ObjectId
from .mongo import get_db

def spotify_login(request):
    # CSRF protection for OAuth redirect
    state = uuid.uuid4().hex
    request.session["spotify_oauth_state"] = state

    scopes = os.environ.get("SPOTIFY_SCOPES", SPOTIFY_SCOPES_DEFAULT)
    params = {
        "client_id": os.environ["SPOTIFY_CLIENT_ID"],
        "response_type": "code",
        "redirect_uri": os.environ["SPOTIFY_REDIRECT_URI"],
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
    return r.json()  # {access_token, token_type, scope, expires_in, refresh_token?}

def _tokens_col():
    return get_db().spotify_tokens

def _now_ts():
    return int(time.time())

_EXP_BUFFER = 60  # refresh 1 min before actual expiry

def _save_tokens(spotify_user_id: str, access_token: str, refresh_token: str | None, expires_in: int):
    expires_at = _now_ts() + int(expires_in) - _EXP_BUFFER
    update = {
        "$set": {
            "spotify_user_id": spotify_user_id,
            "access_token": access_token,
            "expires_at": expires_at,
            "updated_at": datetime.datetime.utcnow(),
        }
    }
    if refresh_token:
        update["$set"]["refresh_token"] = refresh_token
    _tokens_col().update_one({"spotify_user_id": spotify_user_id}, update, upsert=True)

def _get_tokens(spotify_user_id: str):
    return _tokens_col().find_one({"spotify_user_id": spotify_user_id})

def _is_expired(doc: dict | None) -> bool:
    if not doc:
        return True
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
    payload = r.json()  # contains access_token, expires_in, and sometimes refresh_token

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
    """Spotify API call with auto-refresh and single retry on 401."""
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

def _spotify_me(access_token: str):
    r = requests.get("https://api.spotify.com/v1/me",
                     headers={"Authorization": f"Bearer {access_token}"}, timeout=20)
    r.raise_for_status()
    return r.json()  # includes 'id' (user id)

def _duration_close(a: int|None, b: int|None, tolerance=4) -> bool:
    if a is None or b is None: return True
    return abs(a - b) <= tolerance

def _search_best(access_token: str, item: dict) -> str|None:
    """Return a Spotify track id or None."""
    qs = []
    title = item.get("title") or ""
    artist = item.get("artist") or ""
    album = item.get("album") or ""
    dur = item.get("duration_sec")

    # Try strict, then looser
    qs.append(f'track:"{title}" artist:"{artist}" album:"{album}"')
    qs.append(f'track:"{title}" artist:"{artist}"')
    qs.append(f'{title} {artist}')

    for q in qs:
        r = requests.get("https://api.spotify.com/v1/search",
                         headers={"Authorization": f"Bearer {access_token}"},
                         params={"q": q, "type": "track", "limit": 5}, timeout=20)
        if r.status_code == 429:
            # simple backoff
            import time; time.sleep(int(r.headers.get("Retry-After","1")))
            continue
        r.raise_for_status()
        items = r.json().get("tracks", {}).get("items", [])
        best = None
        for t in items:
            t_dur = int(round(t.get("duration_ms", 0)/1000))
            # quick filters; you can add fuzzy compares here
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
    if "error" in request.GET:
        return HttpResponse(f"Spotify returned error: {request.GET.get('error')}", status=400)

    code = request.GET.get("code")
    state = request.GET.get("state")
    if not code or not state or state != request.session.get("spotify_oauth_state"):
        return HttpResponse("State mismatch or missing code.", status=400)

    # Exchange code and save tokens, even if no upload happened
    tok = _spotify_token_exchange(code)
    at = tok["access_token"]
    me = _spotify_me(at)
    user_id = me["id"]
    request.session["spotify_user_id"] = user_id
    _save_tokens(user_id, at, tok.get("refresh_token"), tok["expires_in"])

    # If no uploaded items, go straight to /me for acceptance testing
    items = request.session.get("parsed_items") or []
    name = request.session.get("playlist_name") or "Imported from Apple Music"
    if not items:
        return redirect("/me")


    # Persist tokens for refresh
    _save_tokens(
        spotify_user_id=user_id,
        access_token=at,
        refresh_token=tok.get("refresh_token"),
        expires_in=tok["expires_in"],
    )

    # 2) Create empty playlist (use auto-refresh wrapper for all subsequent calls if you like)
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

    # 3) Match each track with raw token (ok), or use _spotify_api for retries
    matched_ids, misses = [], []
    for idx, it in enumerate(items):
        tid = _search_best(at, it)
        if tid:
            matched_ids.append(tid)
        else:
            misses.append({"idx": idx, **it})

    # 4) Add matches to playlist (raw token is fine; you can switch to refreshable flow later)
    if matched_ids:
        _add_tracks(at, playlist_id, matched_ids)

    # 5) Write conversion + unmatched to Mongo
    db = get_db()
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

    # 6) Clear the upload session and show results
    request.session.pop("parsed_items", None)
    request.session.pop("playlist_name", None)
    return redirect("conversion_detail", cid=str(cid))

def conversion_detail(request, cid: str):
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
