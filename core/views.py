# core/views.py
import os, urllib.parse, datetime, json, re, time, uuid
from threading import Thread
from uuid import uuid4

from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_POST, require_GET
from django.conf import settings
import requests

from services.matching_engine import match_tracks
from .forms import LinkForm
from .parsers import parse_apple_playlist_from_url
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
# Landing
# ---------------------------------------------------------------------
def landing(request):
    return render(request, "landing.html")

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
    Unified getter used by matching:
    - Prefer a valid user token from session (if you saved one).
    - Else fall back to app token (client credentials).
    Returns token string or None.
    """
    return _get_user_token_from_session(request) or _get_app_token(request)

# ---------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------
def _db():
    from .mongo import get_db
    return get_db()

def _jobs_col():
    return _db().jobs

def _conversions_col():
    return _db().conversions

def _unmatched_col():
    return _db().unmatched

def _tokens_col():
    return _db().spotify_tokens

# ---------------------------------------------------------------------
# Upload page
# ---------------------------------------------------------------------
@ensure_csrf_cookie
def upload_link(request):
    if request.method == 'POST':
        form = LinkForm(request.POST)
        if not form.is_valid():
            return HttpResponseBadRequest("Invalid URL.")

        url = form.cleaned_data['url']
        try:
            rows = parse_apple_playlist_from_url(url)
        except Exception as e:
            return HttpResponseBadRequest(f"Error: {e}")

        # Save only what we need
        request.session["apple_tracks_all"] = rows
        request.session["playlist_name"] = url or "Imported from Apple Music"

        # One-shot flag so GET will show preview exactly once
        request.session["just_uploaded"] = True

        # Clear any old match/session artifacts from previous runs
        for k in ("matched_spotify_ids", "matched_scope", "matched_summary"):
            request.session.pop(k, None)

        request.session.modified = True
        return redirect("upload")

    # GET — default: no preview, no old counts
    just_uploaded = request.session.pop("just_uploaded", False)

    preview = []
    count_total = 0
    filename = ""
    show_match_button = False

    if just_uploaded:
        rows = request.session.get("apple_tracks_all") or []
        preview = rows[:10]
        count_total = len(rows)
        filename = request.session.get("playlist_name", "")
        show_match_button = True  # show the “Run match” button only after fresh upload

    return render(request, 'upload.html', {
        'form': LinkForm(),
        'preview': preview,          # will be [] unless just uploaded
        'count_total': count_total,  # 0 unless just uploaded
        'filename': filename,
        'uploaded_ok': show_match_button,
        'track_count': count_total,
    })

def _jobs_col():
    from .mongo import get_db
    return get_db().jobs

@require_POST
def match_run(request, job_id: str):
    """
    Process the next N tracks of a job and update progress.
    The client calls this repeatedly until status == 'done'.
    """
    job = _jobs_col().find_one({"_id": job_id})
    if not job:
        return JsonResponse({"error": "Job not found"}, status=404)
    access_token = _get_any_spotify_token(request)
    if not access_token:
        return JsonResponse({"error": "Spotify credentials missing"}, status=400)

    apple_tracks = job.get("apple_tracks") or []
    total = job.get("total") or len(apple_tracks)
    done = int(job.get("done") or 0)
    if done >= total:
        return JsonResponse({"done": done, "total": total, "status": "done"})

    batch = max(1, min( int(request.GET.get("batch") or 10), 100 ))
    slice_tracks = apple_tracks[done:done+batch]
    if not slice_tracks:
        _jobs_col().update_one({"_id": job_id}, {"$set": {"status": "done", "finished_at": datetime.datetime.utcnow()}})
        return JsonResponse({"done": done, "total": total, "status": "done"})

    # Run matcher on this slice
    data = match_tracks(access_token, slice_tracks, fuzzy_threshold=85)
    results = data["results"] if isinstance(data, dict) and isinstance(data.get("results"), list) else (data or [])

    # Count statuses
    matched_ct = sum(1 for r in results if r.get("status") == "matched")
    fuzzy_ct   = sum(1 for r in results if r.get("status") == "fuzzy_matched")
    not_ct     = sum(1 for r in results if r.get("status") == "not_found")

    # Extract IDs to add later
    ids_this = []
    for r in results:
        tid = r.get("spotify_id")
        if isinstance(tid, str) and len(tid) == 22:
            ids_this.append(tid)

    # Update job doc
    _jobs_col().update_one(
        {"_id": job_id},
        {
            "$inc": {
                "done": len(slice_tracks),
                "summary.matched": matched_ct,
                "summary.fuzzy_matched": fuzzy_ct,
                "summary.not_found": not_ct,
            },
            "$push": {"results": {"$each": results}},
            "$addToSet": {"matched_ids": {"$each": ids_this}},
            "$set": {"status": "running", "updated_at": datetime.datetime.utcnow()},
        }
    )

    done += len(slice_tracks)
    if done >= total:
        _jobs_col().update_one({"_id": job_id}, {"$set": {"status": "done", "finished_at": datetime.datetime.utcnow()}})

    return JsonResponse({"done": done, "total": total, "status": "done" if done >= total else "running"})

# ---------------------------------------------------------------------
# Matching job flow
# ---------------------------------------------------------------------
def _collect_ids_from_results(payload) -> list[str]:
    """
    Extract Spotify track IDs from matcher output:
      {"summary": {...}, "results": [ { "status": "...", "spotify_id": "..." }, ... ]}
    Keep only matched/fuzzy_matched; dedupe, preserve order.
    """
    ids = []
    if isinstance(payload, dict) and isinstance(payload.get("results"), list):
        seen = set()
        for row in payload["results"]:
            if not isinstance(row, dict):
                continue
            if row.get("status") in ("matched", "fuzzy_matched"):
                tid = row.get("spotify_id")
                if isinstance(tid, str) and len(tid) == 22 and tid not in seen:
                    seen.add(tid)
                    ids.append(tid)
    return ids

@require_POST
def match_start(request):
    """Start a background matching job, return job_id."""
    apple_tracks = request.session.get("apple_tracks_all") or []
    if not apple_tracks:
        return JsonResponse({"error": "No tracks found in session. Go back to Upload."}, status=400)

    source_name = request.session.get("playlist_name") or "Imported from Apple Music"

    token = _get_any_spotify_token(request)
    if not token:
        return JsonResponse({"error": "Spotify app credential missing (client id/secret)."}, status=500)

    job_id = uuid4().hex
    now = datetime.datetime.utcnow()
    _jobs_col().insert_one({
        "_id": job_id,
        "status": "queued",
        "progress": 0,
        "created_at": now,
        "updated_at": now,
        "source_name": source_name,
        "apple_count": len(apple_tracks),
        "summary": None,
        "results": None,
        "matched_ids": [],
        "error": None,
    })

    Thread(target=_run_match_job, args=(job_id, token, apple_tracks), daemon=True).start()
    return JsonResponse({"job_id": job_id})

def _run_match_job(job_id: str, access_token: str, apple_tracks: list[dict]):
    col = _jobs_col()
    def set_state(**kv):
        kv["updated_at"] = datetime.datetime.utcnow()
        col.update_one({"_id": job_id}, {"$set": kv})

    try:
        set_state(status="running", progress=10)
        data = match_tracks(access_token, apple_tracks, fuzzy_threshold=85)
        ids = _collect_ids_from_results(data)
        summary = data.get("summary") if isinstance(data, dict) else None
        results = data.get("results") if isinstance(data, dict) else data
        set_state(progress=90)
        set_state(status="done", progress=100, results=results, summary=summary, matched_ids=ids)
    except Exception as e:
        set_state(status="error", error=str(e), progress=100)

@require_GET
def match_progress_page(request, job_id: str):
    job = _jobs_col().find_one({"_id": job_id})
    total = int(job.get("total", 0)) if job else 0
    resp = render(request, "match_progress.html", {"job_id": job_id, "total": total})
    resp["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp["Pragma"] = "no-cache"
    return resp

@require_GET
def match_status(request, job_id: str):
    job = _jobs_col().find_one({"_id": job_id}, {"_id": 0})
    if not job:
        return JsonResponse({"status": "missing"}, status=404)
    return JsonResponse({
        "status": job.get("status"),
        "progress": int(job.get("progress") or 0),
        "error": job.get("error"),
    })

from django.shortcuts import render, redirect
from django.views.decorators.http import require_GET

@require_GET
def match_results_page(request, job_id: str):
    job = _jobs_col().find_one({"_id": job_id})
    if not job:
        return HttpResponse("Job not found.", status=404)

    total = int(job.get("total") or 0)
    done = int(job.get("done") or 0)
    status = job.get("status") or ("done" if done >= total and total > 0 else "running")

    # 🚦 If the job isn't finished yet, always send user to the progress page
    if status != "done" or done < total:
        return redirect("match_progress", job_id=job_id)

    results = job.get("results") or []
    summary = job.get("summary") or {"matched": 0, "fuzzy_matched": 0, "not_found": 0}
    created_flag = request.GET.get("created")
    playlist_url = request.GET.get("playlist_url", "")

    resp = render(request, "match_results.html", {
        "job_id": job_id,
        "results": results,
        "summary": summary,
        "source_name": job.get("source_name") or "Imported from Apple Music",
        "created": created_flag == "1",
        "playlist_url": playlist_url,
    })
    # prevent stale renders
    resp["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp["Pragma"] = "no-cache"
    return resp

@require_GET
def match_report_csv(request, job_id: str):
    job = _jobs_col().find_one({"_id": job_id})
    if not job:
        return HttpResponse("Job not found.", status=404)
    import csv
    from django.utils.encoding import smart_str
    resp = HttpResponse(content_type="text/csv")
    resp["Content-Disposition"] = f'attachment; filename="match_report_{job_id}.csv"'

    # ⬇️ important: stop repeat downloads and prefetch weirdness
    resp["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp["Pragma"] = "no-cache"
    resp["Expires"] = "0"

    w = csv.writer(resp)
    w.writerow(["status","score","raw_title","raw_artist","raw_album","spotify_id","method"])
    for r in (job.get("results") or []):
        w.writerow([
            r.get("status"), r.get("score"),
            smart_str(r.get("raw_title","")), smart_str(r.get("raw_artist","")), smart_str(r.get("raw_album","")),
            r.get("spotify_id"), r.get("method"),
        ])
    return resp

# ---------------------------------------------------------------------
# OAuth + playlist creation (via callback)
# ---------------------------------------------------------------------
def _json_error(message: str, status=400):
    return JsonResponse({"error": message}, status=status)

def spotify_login(request):
    state = uuid.uuid4().hex
    request.session["spotify_oauth_state"] = state

    job_id = request.GET.get("job_id")
    next_url = request.GET.get("next") or "/"
    playlist_name = request.GET.get("playlist_name")  # ⬅️ new
    request.session["oauth_ctx"] = {"job_id": job_id, "next": next_url, "playlist_name": playlist_name}
    request.session.modified = True

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

def _now_ts(): return int(time.time())
_EXP_BUFFER = 60  # refresh 1 min early

def _save_tokens(spotify_user_id: str, access_token: str, refresh_token: str | None, expires_in: int):
    expires_at = _now_ts() + int(expires_in) - _EXP_BUFFER
    update = {"$set": {
        "spotify_user_id": spotify_user_id,
        "access_token": access_token,
        "expires_at": expires_at,
        "updated_at": datetime.datetime.utcnow(),
    }}
    if refresh_token:
        update["$set"]["refresh_token"] = refresh_token
    _tokens_col().update_one({"spotify_user_id": spotify_user_id}, update, upsert=True)

def _get_tokens(spotify_user_id: str):
    return _tokens_col().find_one({"spotify_user_id": spotify_user_id})

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

def _spotify_me(access_token: str):
    r = requests.get("https://api.spotify.com/v1/me",
                     headers={"Authorization": f"Bearer {access_token}"}, timeout=20)
    r.raise_for_status()
    return r.json()

def spotify_callback(request):
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

    # Use job context to build playlist and return to results page
    ctx = request.session.pop("oauth_ctx", {}) or {}
    job_id = ctx.get("job_id")
    next_url = ctx.get("next") or "/"
    chosen_name = ctx.get("playlist_name")  # ⬅️ may be None

    if job_id:
        job = _jobs_col().find_one({"_id": job_id})
        if not job:
            return redirect(next_url)

        matched_ids = job.get("matched_ids") or _collect_ids_from_results({"results": job.get("results") or []})
        # prefer chosen name, else job source name, else fallback
        name = (chosen_name or job.get("source_name") or "Imported from Apple Music")[:100]

        # Create playlist with 'name'
        r = requests.post(
            f"https://api.spotify.com/v1/users/{user_id}/playlists",
            headers={"Authorization": f"Bearer {at}", "Content-Type": "application/json"},
            json={"name": name, "public": False, "description": "Imported via Apple→Spotify"},
            timeout=20,
        )
        r.raise_for_status()
        playlist = r.json()
        playlist_id = playlist["id"]
        playlist_url = playlist.get("external_urls", {}).get("spotify", "")

        # 2) Add tracks in chunks of 100
        if matched_ids:
            add_url = f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks"
            headers = {"Authorization": f"Bearer {at}", "Content-Type": "application/json"}
            for i in range(0, len(matched_ids), 100):
                chunk = matched_ids[i:i+100]
                rr = requests.post(add_url, headers=headers, json={"uris": [f"spotify:track:{tid}" for tid in chunk]}, timeout=25)
                if rr.status_code == 429:
                    time.sleep(int(rr.headers.get("Retry-After", "1")))
                    rr = requests.post(add_url, headers=headers, json={"uris": [f"spotify:track:{tid}" for tid in chunk]}, timeout=25)
                rr.raise_for_status()

        # 3) Persist conversion record
        _conversions_col().insert_one({
            "created_at": datetime.datetime.utcnow(),
            "spotify_user_id": user_id,
            "playlist_name": name,
            "spotify_playlist_id": playlist_id,
            "spotify_playlist_url": playlist_url,
            "total": len(matched_ids),
            "matched": len(matched_ids),
            "unmatched": 0,
            "source": f"job:{job_id}",
        })

        sep = "&" if "?" in next_url else "?"
        return redirect(f"{next_url}{sep}created=1&playlist_url={urllib.parse.quote(playlist_url)}")

    # No job context → fallback
    return redirect("/me")

# ---------------------------------------------------------------------
# Legacy utilities
# ---------------------------------------------------------------------
def conversion_detail(request, cid: str):
    conv = _conversions_col().find_one({"_id": ObjectId(cid)})
    if not conv:
        return HttpResponse("Conversion not found.", status=404)
    misses = list(_unmatched_col().find({"conversion_id": conv["_id"]}))
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
        return HttpResponse("Not logged in.", status=401)
    profile = _spotify_api(spotify_user_id, "GET", "/me")
    return HttpResponse(json.dumps({
        "id": profile.get("id"),
        "display_name": profile.get("display_name"),
        "email": profile.get("email"),
    }), content_type="application/json")
