# core/views.py
import os, sys, subprocess, urllib.parse, datetime, json, time, uuid
from uuid import uuid4

from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_exempt
from django.views.decorators.http import require_POST, require_GET
from django.conf import settings
from django.urls import reverse
from django.views.decorators.cache import never_cache
import requests
from bson.objectid import ObjectId

from services.matching_engine import match_tracks
from .forms import LinkForm
from .parsers import parse_apple_playlist_from_url
from .decorators import approved_required

# ---------------------------------------------------------------------
# Debug: environment / session status (kept)
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
        "last_uploaded_url": request.session.get("last_uploaded_url"),
        "last_parsed_count": request.session.get("last_parsed_count"),
    })

# ---------------------------------------------------------------------
# Landing (kept)
# ---------------------------------------------------------------------
def landing(request):
    return render(request, "landing.html")

# ---------------------------------------------------------------------
# Spotify token helpers (client-credentials for matching; service account for playlist ops)
# ---------------------------------------------------------------------
SPOTIFY_TOKEN_URL = "https://accounts.spotify.com/api/token"
SERVICE_USER_ID = os.environ.get("SPOTIFY_SERVICE_USER_ID")  # your service Spotify account user id (required)
SERVICE_REFRESH_TOKEN = os.environ.get("SPOTIFY_REFRESH_TOKEN")

def _get_user_token_from_session(request):
    token = request.session.get("spotify_access_token")
    expires_at = request.session.get("spotify_expires_at")
    if token and (not expires_at or time.time() < (expires_at - 60)):
        return token
    return None

def _get_app_token(request):
    """Client Credentials flow token – used for read-only catalog/matching calls."""
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
    # For matching we can use client credentials; user token not required anymore.
    return _get_user_token_from_session(request) or _get_app_token(request)

# ---------------------------------------------------------------------
# DB helpers (kept)
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

def _uploads_col():
    # holds bulky parsed tracks keyed by a small token
    return _db().uploads

# views.py
from django.shortcuts import render, redirect
from django.core.mail import send_mail
from .models import SpotifyAccessRequest

def request_access(request):
    if request.method == "POST":
        ar = SpotifyAccessRequest.objects.create(
            email=request.POST["email"].strip(),
            username=request.POST.get("username","").strip(),
            org=request.POST.get("org","").strip(),
            notes=request.POST.get("notes","").strip(),
        )
        # TODO: send yourself a notification with a link to /admin/access-requests/
        return render(request, "thanks_pending.html")
    return render(request, "request_access.html")

def can_connect(email: str) -> bool:
    # after you approve in dashboard, flip approved=True in your admin
    return SpotifyAccessRequest.objects.filter(email=email, approved=True).exists()

def connect_spotify_entry(request):
    user_email = request.user.email if request.user.is_authenticated else None
    if not user_email or not can_connect(user_email):
        return redirect("request_access")

# ---------------------------------------------------------------------
# Upload page (NO login/approval required)
# ---------------------------------------------------------------------
def _normalize_apple_url(raw: str) -> str:
    raw = (raw or "").strip()
    if raw and not raw.lower().startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw

@ensure_csrf_cookie
@never_cache
def upload_link(request):  # 👈 removed @approved_required
    if request.method == 'POST':
        form = LinkForm(request.POST)
        if not form.is_valid():
            request.session["flash_error"] = "Invalid URL. Please paste a full Apple Music playlist link."
            resp = redirect(reverse("upload"))
            resp["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            resp["Pragma"] = "no-cache"
            resp["Expires"] = "0"
            return resp

        for k in ("upload_guard", "playlist_name"):
            request.session.pop(k, None)

        url = _normalize_apple_url(form.cleaned_data['url'])

        try:
            rows = parse_apple_playlist_from_url(url)  # list[dict]
        except Exception as e:
            request.session["flash_error"] = f"Error fetching playlist: {e}"
            resp = redirect(reverse("upload"))
            resp["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            resp["Pragma"] = "no-cache"
            resp["Expires"] = "0"
            return resp

        if not rows:
            request.session["flash_error"] = "No tracks were found at that URL."
            resp = redirect(reverse("upload"))
            resp["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            resp["Pragma"] = "no-cache"
            resp["Expires"] = "0"
            return resp

        token = uuid.uuid4().hex
        playlist_name = url or "Imported from Apple Music"

        _uploads_col().update_one(
            {"_id": token},
            {"$set": {
                "created_at": datetime.datetime.utcnow(),
                "playlist_name": playlist_name,
                "rows": rows,
            }},
            upsert=True
        )

        for k in ("matched_spotify_ids", "matched_scope", "matched_summary"):
            request.session.pop(k, None)

        request.session["upload_guard"] = token
        request.session["last_uploaded_url"] = url
        request.session["last_parsed_count"] = len(rows)
        request.session["playlist_name"] = playlist_name
        request.session.modified = True

        resp = redirect(f"{reverse('upload')}?uploaded={token}")
        resp["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp["Pragma"] = "no-cache"
        resp["Expires"] = "0"
        return resp

    # ---------- GET ----------
    error_msg = request.session.pop("flash_error", None)

    token_param = request.GET.get("uploaded")
    guard_ok = token_param and (token_param == request.session.get("upload_guard"))

    preview, count_total, filename = [], 0, ""
    uploaded_ok = False
    if guard_ok:
        doc = _uploads_col().find_one({"_id": token_param})
        if doc and isinstance(doc.get("rows"), list):
            rows = doc["rows"]
            preview = rows[:10]
            count_total = len(rows)
            filename = doc.get("playlist_name", "")
            uploaded_ok = True

    resp = render(request, 'upload.html', {
        'form': LinkForm(),
        'preview': preview,
        'count_total': count_total,
        'filename': filename,
        'uploaded_ok': uploaded_ok,
        'track_count': count_total,
        'error': error_msg,
        'last_url': request.session.get("last_uploaded_url"),
        'last_count': request.session.get("last_parsed_count"),
    })
    resp["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private"
    resp["Pragma"] = "no-cache"
    resp["Expires"] = "0"
    resp["Vary"] = "Cookie"
    return resp

# ---------------------------------------------------------------------
# Matching job flow (kept)
# ---------------------------------------------------------------------
def _collect_ids_from_results(payload) -> list[str]:
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

def _pick(d: dict, *candidates, sep: str | None = None) -> str:
    for k in candidates:
        if k in d and d[k] is not None:
            v = d[k]
            if isinstance(v, list):
                if sep:
                    v = sep.join(str(x).strip() for x in v if str(x).strip())
                else:
                    v = v[0] if v else ""
            v = str(v).strip()
            if v:
                return v
    return ""

def _shrink_track(t: dict) -> dict:
    title   = _pick(t, "raw_title", "title", "name", "trackName", "song", "track_title")
    artist  = _pick(t, "raw_artist", "artist", "artists", "artistName", "primaryArtist", "by", sep=", ")
    album   = _pick(t, "raw_album", "album", "collectionName", "albumName", "release")
    isrc    = _pick(t, "raw_isrc", "isrc", "ISRC")

    dur_sec = t.get("duration_sec")
    dur_ms  = t.get("duration_ms")
    if dur_sec is None:
        if isinstance(dur_ms, (int, float)):
            dur_sec = int(round(dur_ms / 1000.0))
        else:
            try:
                dur_sec = int(str(t.get("duration", "")).strip())
            except Exception:
                dur_sec = None

    norm_title  = _pick(t, "norm_title")
    norm_artist = _pick(t, "norm_artist")

    out = {
        "raw_title": title,
        "raw_artist": artist,
        "raw_album": album,
        "raw_isrc": isrc or None,
        "duration_sec": dur_sec,
        "title": title,
        "artist": artist,
        "album": album,
        "isrc": isrc or None,
        "duration_ms": dur_ms,
    }
    if norm_title:
        out["norm_title"] = norm_title
    if norm_artist:
        out["norm_artist"] = norm_artist
    return out

@require_POST
@never_cache
def match_start(request):
    token = request.session.get("upload_guard")
    doc = _uploads_col().find_one({"_id": token}) if token else None
    rows = (doc or {}).get("rows") or []
    if not isinstance(rows, list) or not rows:
        return JsonResponse({"error": "No uploaded tracks. Please upload first."}, status=400)

    job_id = uuid4().hex
    now = datetime.datetime.utcnow()

    apple_tracks = [_shrink_track(t) for t in rows]
    total = len(apple_tracks)

    missing_core = sum(1 for r in apple_tracks if not r["raw_title"] or not r["raw_artist"])
    if missing_core > max(2, int(0.5 * total)):
        return JsonResponse({
            "error": "Parsed playlist is missing titles or artists (field mismatch). "
                     "Adjust parser output keys or the _shrink_track() mapping."
        }, status=400)

    _jobs_col().insert_one({
        "_id": job_id,
        "status": "running",
        "created_at": now,
        "updated_at": now,
        "finished_at": None,
        "apple_tracks": apple_tracks,
        "total": total,
        "done": 0,
        "results": [],
        "summary": {"matched": 0, "fuzzy_matched": 0, "not_found": 0},
        "matched_ids": [],
        "source_name": request.session.get("playlist_name") or "Imported from Apple Music",
    })

    resp = JsonResponse({"job_id": job_id})
    resp["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private"
    resp["Pragma"] = "no-cache"
    resp["Expires"] = "0"
    resp["Vary"] = "Cookie"
    return resp

@require_POST
def match_run(request, job_id: str):
    col = _jobs_col()
    job = col.find_one({"_id": job_id})
    if not job:
        return JsonResponse({"error": "Job not found"}, status=404)

    apple_tracks = job.get("apple_tracks") or []
    total = int(job.get("total") or (len(apple_tracks) if isinstance(apple_tracks, list) else 0))
    done = int(job.get("done") or 0)
    done = max(0, min(done, total))

    if not isinstance(apple_tracks, list) or total <= 0:
        return JsonResponse({"error": "Job has no tracks. Please re-upload."}, status=400)

    if done >= total:
        if job.get("status") != "done":
            col.update_one({"_id": job_id}, {"$set": {
                "status": "done",
                "finished_at": datetime.datetime.utcnow(),
                "updated_at": datetime.datetime.utcnow()
            }})
        return JsonResponse({"done": total, "total": total, "status": "done", "processed": 0})

    try:
        batch = int(request.GET.get("batch", "10"))
    except Exception:
        batch = 10
    batch = max(1, min(batch, 100))

    remaining = total - done
    take = min(batch, remaining)
    start = done
    stop = start + take
    slice_tracks = apple_tracks[start:stop]

    if not slice_tracks:
        col.update_one({"_id": job_id}, {"$set": {
            "status": "done",
            "done": total,
            "finished_at": datetime.datetime.utcnow(),
            "updated_at": datetime.datetime.utcnow()
        }})
        return JsonResponse({"done": total, "total": total, "status": "done", "processed": 0})

    access_token = _get_any_spotify_token(request)
    if not access_token:
        return JsonResponse({"error": "Spotify credentials missing"}, status=400)

    data = match_tracks(access_token, slice_tracks, fuzzy_threshold=85)
    results = data["results"] if isinstance(data, dict) and isinstance(data.get("results"), list) else (data or [])

    matched_ct = sum(1 for r in results if r.get("status") == "matched")
    fuzzy_ct   = sum(1 for r in results if r.get("status") == "fuzzy_matched")
    not_ct     = sum(1 for r in results if r.get("status") == "not_found")

    ids_this = []
    for r in results:
        tid = r.get("spotify_id")
        if isinstance(tid, str) and len(tid) == 22:
            ids_this.append(tid)

    processed = len(slice_tracks)
    new_done = min(total, done + processed)

    col.update_one({"_id": job_id}, {
        "$inc": {
            "done": processed,
            "summary.matched": matched_ct,
            "summary.fuzzy_matched": fuzzy_ct,
            "summary.not_found": not_ct,
        },
        "$push": {"results": {"$each": results}},
        "$addToSet": {"matched_ids": {"$each": ids_this}},
        "$set": {"status": ("done" if new_done >= total else "running"),
                 "updated_at": datetime.datetime.utcnow()},
    })

    if new_done >= total:
        col.update_one({"_id": job_id}, {"$set": {
            "status": "done",
            "finished_at": datetime.datetime.utcnow(),
            "updated_at": datetime.datetime.utcnow()
        }})

    return JsonResponse({
        "done": new_done,
        "total": total,
        "status": "done" if new_done >= total else "running",
        "processed": processed,
    })

# ---------------------------------------------------------------------
# Pages (kept)
# ---------------------------------------------------------------------
@require_GET
@never_cache
def match_progress_page(request, job_id: str):
    job = _jobs_col().find_one({"_id": job_id})
    total = int(job.get("total", 0)) if job else 0
    resp = render(request, "match_progress.html", {"job_id": job_id, "total": total})
    resp["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp["Pragma"] = "no-cache"
    return resp

@require_GET
@never_cache
def match_results_page(request, job_id: str):
    job = _jobs_col().find_one({"_id": job_id})
    if not job:
        return HttpResponse("Job not found.", status=404)

    total = int(job.get("total") or 0)
    done = int(job.get("done") or 0)
    status = job.get("status") or ("done" if done >= total and total > 0 else "running")

    if status != "done" or done < total:
        return redirect("match_progress_page", job_id=job_id)

    results = job.get("results") or []
    summary = job.get("summary") or {"matched": 0, "fuzzy_matched": 0, "not_found": 0}

    # Prefer playlist_url stored on the job; fall back to querystring for backward compat
    playlist_url = (
        job.get("playlist_url")
        or job.get("open_url")
        or request.GET.get("playlist_url", "")
    )

    resp = render(request, "match_results.html", {
        "job_id": job_id,
        "results": results,
        "summary": summary,
        "source_name": job.get("source_name") or "Imported from Apple Music",
        "created": bool(playlist_url),
        "playlist_url": playlist_url,
    })
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
# Service account token + API helpers (NEW)
# ---------------------------------------------------------------------
def _now_ts(): return int(time.time())
_EXP_BUFFER = 60

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

    # Try DB refresh token first if it exists
    refresh_token = doc.get("refresh_token") if doc else None

    # If none in DB and this is the service user, fall back to env
    if not refresh_token and spotify_user_id == SERVICE_USER_ID:
        refresh_token = os.environ.get("SPOTIFY_REFRESH_TOKEN")

    if not refresh_token:
        raise RuntimeError("No refresh token available")

    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": os.environ["SPOTIFY_CLIENT_ID"],
        "client_secret": os.environ["SPOTIFY_CLIENT_SECRET"],
    }
    r = requests.post(SPOTIFY_TOKEN_URL, data=data, timeout=20)
    r.raise_for_status()
    payload = r.json()

    new_access = payload["access_token"]
    # Spotify might or might not return a new refresh token
    new_refresh = payload.get("refresh_token") or refresh_token

    _save_tokens(spotify_user_id, new_access, new_refresh, payload["expires_in"])
    return new_access


def _get_valid_access_token(spotify_user_id: str) -> str:
    doc = _get_tokens(spotify_user_id)
    if _is_expired(doc):
        return _refresh_access_token(spotify_user_id)
    return doc["access_token"]

def spotify_service_api(method: str, path: str, **kwargs):
    """Spotify Web API call using the SERVICE_USER_ID's access token."""
    if not SERVICE_USER_ID:
        raise RuntimeError("Missing SPOTIFY_SERVICE_USER_ID")
    base = "https://api.spotify.com/v1"
    token = _get_valid_access_token(SERVICE_USER_ID)
    headers = kwargs.pop("headers", {})
    headers["Authorization"] = f"Bearer {token}"
    r = requests.request(method, base + path, headers=headers, timeout=20, **kwargs)
    if r.status_code == 401:
        token = _refresh_access_token(SERVICE_USER_ID)
        headers["Authorization"] = f"Bearer {token}"
        r = requests.request(method, base + path, headers=headers, timeout=20, **kwargs)
    r.raise_for_status()
    return r.json() if r.content else {}

# ---------------------------------------------------------------------
# Invite-bot bridge (NEW) — calls tools/spotify_invite_bot.py
# ---------------------------------------------------------------------
def _mint_collaborator_invite_link(playlist_id: str) -> str:
    """
    Runs a Playwright-based helper that:
      - opens https://open.spotify.com/playlist/{id} as the service account
      - clicks "More" → "Invite collaborators" → "Copy link"
      - prints link to stdout
    """
    cmd = [sys.executable, 'tools/spotify_invite_bot.py', playlist_id]
    run = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    if run.returncode != 0:
        raise RuntimeError(f"invite bot failed: {run.stderr.decode('utf-8', 'ignore')}")
    link = run.stdout.decode('utf-8').strip()
    if not (link.startswith("http://") or link.startswith("https://")):
        raise RuntimeError("No invite link returned")
    return link

# ---------------------------------------------------------------------
# Convert API: create playlist under service account, make collaborative, add tracks, mint invite (NEW)
# ---------------------------------------------------------------------
@require_GET
@never_cache
def match_results_page(request, job_id: str):
    job = _jobs_col().find_one({"_id": job_id})
    if not job:
        return HttpResponse("Job not found.", status=404)

    total = int(job.get("total") or 0)
    done = int(job.get("done") or 0)
    status = job.get("status") or ("done" if done >= total and total > 0 else "running")

    if status != "done" or done < total:
        return redirect("match_progress_page", job_id=job_id)

    # NEW: if playlist not created yet, call api_convert right now
    playlist_url = job.get("playlist_url") or job.get("invite_link") or job.get("open_url")
    if not playlist_url:
        # AUTO-CREATE playlist
        try:
            import requests
            convert_resp = requests.post(
                request.build_absolute_uri("/api/convert"),
                json={"job_id": job_id, "playlist_name": job.get("source_name", "Imported")}
            )
            if convert_resp.ok:
                data = convert_resp.json()
                playlist_url = data.get("invite_link") or data.get("open_url")
                # Persist again (in case convert didn't)
                _jobs_col().update_one(
                    {"_id": job_id},
                    {"$set": {"playlist_url": playlist_url}}
                )
        except Exception as e:
            print("AUTO-CONVERT ERROR:", e)

    # fallback
    playlist_url = playlist_url or request.GET.get("playlist_url", "")

    results = job.get("results") or []
    summary = job.get("summary") or {"matched": 0, "fuzzy_matched": 0, "not_found": 0}

    return render(request, "match_results.html", {
        "job_id": job_id,
        "results": results,
        "summary": summary,
        "source_name": job.get("source_name") or "Imported from Apple Music",
        "created": bool(playlist_url),
        "playlist_url": playlist_url,
    })

# ---------------------------------------------------------------------
# Regenerate invite (NEW)
# ---------------------------------------------------------------------
@csrf_exempt
@require_POST
def api_regen_invite(request, playlist_id: str):
    try:
        link = _mint_collaborator_invite_link(playlist_id)
        _conversions_col().update_one(
            {"spotify_playlist_id": playlist_id},
            {"$set": {"invite_link": link, "invite_generated_at": datetime.datetime.utcnow()}}
        )
        return JsonResponse({"invite_link": link})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
    
def spotify_callback(request):
    return HttpResponse(f"code={request.GET.get('code')}, state={request.GET.get('state')}")

# ---------------------------------------------------------------------
# Legacy utilities (kept unless you confirm removal)
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
    """
    Legacy: requires a per-user token in session. Kept for now; safe to remove later
    once you confirm nothing calls this.
    """
    spotify_user_id = request.session.get("spotify_user_id")
    if not spotify_user_id:
        return HttpResponse("Not logged in.", status=401)
    profile = spotify_service_api("GET", "/me")  # uses service token; changed from per-user
    return HttpResponse(json.dumps({
        "id": profile.get("id"),
        "display_name": profile.get("display_name"),
        "email": profile.get("email"),
    }), content_type="application/json")
