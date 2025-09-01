import re
import html
import urllib.parse
import requests
from bs4 import BeautifulSoup

APPLE_PLAYLIST_RE = re.compile(r'^https?://(music|geo)\.apple\.com/[^/]+/playlist/')

def is_apple_playlist_url(url: str) -> bool:
    return bool(APPLE_PLAYLIST_RE.match(url.strip().lower()))

def _http_get(url: str, timeout=12) -> str:
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }
    r = requests.get(url, headers=headers, timeout=timeout)
    r.raise_for_status()
    return r.text

def _extract_song_urls_from_playlist_html(html_text: str):
    soup = BeautifulSoup(html_text, 'html.parser')
    urls = [m.get("content") for m in soup.find_all('meta', {"property": "music:song"}) if m.get("content")]
    return urls

def _extract_track_id_from_song_url(url: str):
    q = urllib.parse.urlparse(url).query
    params = urllib.parse.parse_qs(q)
    if 'i' in params and params['i']:
        return params['i'][0]
    # fallback: last numeric path segment
    parts = [p for p in urllib.parse.urlparse(url).path.split('/') if p]
    if parts and parts[-1].isdigit():
        return parts[-1]
    return None

def _lookup_tracks_itunes(ids):
    if not ids:
        return {}
    ids_csv = ",".join(ids)
    url = f"https://itunes.apple.com/lookup?id={ids_csv}"
    data = requests.get(url, timeout=10).json()
    return {str(item['trackId']): item for item in data.get('results', []) if 'trackId' in item}

def normalize_title(title: str) -> str:
    import re, unicodedata
    if not title: return ''
    s = unicodedata.normalize('NFKD', title)
    s = ''.join(c for c in s if not unicodedata.combining(c))
    s = re.sub(r'\(.*?\)|\[.*?\]', '', s)
    s = s.lower()
    s = re.sub(r'[^a-z0-9\s]', ' ', s)
    return re.sub(r'\s+', ' ', s).strip()

def normalize_artist(artist: str) -> str:
    if not artist: return ''
    s = artist.lower()
    s = re.sub(r'[^a-z0-9\s&]', ' ', s)
    return re.sub(r'\s+', ' ', s).strip()

def parse_apple_playlist_from_url(url: str):
    if not is_apple_playlist_url(url):
        raise ValueError("That doesn't look like an Apple Music playlist link.")

    html_text = _http_get(url)
    song_urls = _extract_song_urls_from_playlist_html(html_text)
    ids = [tid for su in song_urls if (tid := _extract_track_id_from_song_url(su))]
    itunes_map = _lookup_tracks_itunes(ids)

    rows = []
    for tid in ids:
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
