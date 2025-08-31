import os, io, urllib.parse, base64, datetime, math, json, re
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from .parsers import parse_apple_xml, parse_m3u
from .mongo import get_db, ensure_indexes

def index(request):
    return HttpResponse("It works! 🎉")

def health(request):
    return HttpResponse("ok")

# Simple in-template HTML to keep it minimal (no separate template files needed)
FORM_HTML = """
<h1>Upload Apple Playlist</h1>
<p>Export from Apple Music/iTunes: File → Library → Export Playlist… (choose XML or M3U/M3U8).</p>
<form method="POST" enctype="multipart/form-data">
  <input type="file" name="playlist" accept=".xml,.m3u,.m3u8" required />
  <input type="text" name="name" placeholder="New Spotify playlist name" required />
  <button type="submit">Upload</button>
</form>
"""

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
    params = {
        "client_id": os.environ["SPOTIFY_CLIENT_ID"],
        "response_type": "code",
        "redirect_uri": os.environ["SPOTIFY_REDIRECT_URI"],
        "scope": os.environ.get("SPOTIFY_SCOPES", "playlist-modify-public playlist-modify-private"),
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
    code = request.GET.get("code")
    if not code:
        err = request.GET.get("error") or "Missing code"
        return HttpResponse(f"Spotify returned error: {err}", status=400)

    # Make sure we have something to convert
    items = request.session.get("parsed_items") or []
    name = request.session.get("playlist_name") or "Imported from Apple Music"
    if not items:
        return HttpResponse("Nothing to convert. Please upload your playlist first.", status=400)

    # 1) Tokens + user
    tok = _spotify_token_exchange(code)
    at = tok["access_token"]
    me = _spotify_me(at)
    user_id = me["id"]

    # 2) Create empty playlist
    r = requests.post(f"https://api.spotify.com/v1/users/{user_id}/playlists",
                      headers={"Authorization": f"Bearer {at}", "Content-Type": "application/json"},
                      json={"name": name, "public": False, "description": "Imported from Apple Music"},
                      timeout=20)
    r.raise_for_status()
    playlist = r.json()
    playlist_id = playlist["id"]
    playlist_url = playlist.get("external_urls", {}).get("spotify", "")

    # 3) Match each track
    matched_ids, misses = [], []
    for idx, it in enumerate(items):
        tid = _search_best(at, it)
        if tid:
            matched_ids.append(tid)
        else:
            misses.append({"idx": idx, **it})

    # 4) Add matches to playlist
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

    # 6) Clear session (we're done with the upload) and show results
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
