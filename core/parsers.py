import io, re, plistlib

def normalize_text(s: str) -> str:
    s = s or ""
    s = s.strip()
    s = re.sub(r"\s+", " ", s)
    # remove common noise while keeping a copy elsewhere if you want retries later
    s = re.sub(r"\((feat\.|featuring)[^)]+\)", "", s, flags=re.I)
    s = re.sub(r"\s*-\s*(remaster(ed)?(\s*\d{4})?|live|mono|stereo)\b.*", "", s, flags=re.I)
    return s.strip()

def parse_apple_xml(fileobj) -> list[dict]:
    """Return list of dicts: {title, artist, album, duration_sec}."""
    pl = plistlib.load(fileobj)
    tracks_map = pl.get("Tracks", {})
    playlists = pl.get("Playlists", [])
    items = []
    # Exported single playlist usually appears at index 0
    plist = playlists[0] if playlists else {}
    for it in plist.get("Playlist Items", []):
        tid = str(it.get("Track ID"))
        t = tracks_map.get(tid, {})
        title = normalize_text(t.get("Name", ""))
        artist = normalize_text(t.get("Artist", ""))
        album = normalize_text(t.get("Album", ""))
        dur_ms = t.get("Total Time")
        dur = int(round(dur_ms/1000)) if isinstance(dur_ms, int) else None
        if title and artist:
            items.append({"title": title, "artist": artist, "album": album, "duration_sec": dur})
    return items

def parse_m3u(fileobj) -> list[dict]:
    """Parse M3U/M3U8 with #EXTINF: <secs>,Artist - Title."""
    raw = fileobj.read()
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1", errors="replace")
    else:
        text = raw
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    items, pending = [], None
    for ln in lines:
        if ln.startswith("#EXTINF:"):
            m = re.match(r"#EXTINF:(-?\d+),(.*)", ln)
            dur = int(m.group(1)) if m else None
            meta = (m.group(2) if m else "")
            # Split "Artist - Title"
            if " - " in meta:
                artist, title = meta.split(" - ", 1)
            else:
                artist, title = "", meta
            pending = {"title": normalize_text(title), "artist": normalize_text(artist), "album": "", "duration_sec": dur}
        elif ln.startswith("#"):
            continue
        else:
            # ln is the media path/URL; we don't actually need it
            if pending and pending["title"]:
                items.append(pending)
            pending = None
    return items
