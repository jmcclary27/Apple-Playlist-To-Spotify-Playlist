#!/usr/bin/env python
import os
import sys
import json
import time
from pathlib import Path

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

# ---------------------------------------------------------------------
# Config / env
# ---------------------------------------------------------------------
SPOTIFY_EMAIL = os.environ.get("SPOTIFY_SERVICE_EMAIL")
SPOTIFY_PASSWORD = os.environ.get("SPOTIFY_SERVICE_PASSWORD")

# Where we cache login cookies so we don't have to log in every time
AUTH_STATE_PATH = Path(__file__).parent / "spotify_auth_state.json"

HEADLESS = os.environ.get("SPOTIFY_INVITE_HEADLESS", "true").lower() != "false"

PLAYLIST_BASE_URL = "https://open.spotify.com/playlist/"

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def require_env(var_name: str) -> str:
    value = os.environ.get(var_name)
    if not value:
        eprint(f"Missing required env var: {var_name}")
        sys.exit(1)
    return value


def login_if_needed(page, context):
    """
    If we're on a login page, fill in username/password and save auth state.
    """
    # Spotify might redirect a few times
    time.sleep(1)

    url = page.url
    if "accounts.spotify.com" not in url and "login" not in url:
        # Already logged in
        return

    eprint(f"[spotify_invite_bot] On login page: {url}")

    email = require_env("SPOTIFY_SERVICE_EMAIL")
    password = require_env("SPOTIFY_SERVICE_PASSWORD")

    # Sometimes Spotify shows a "Log in" landing page with a button.
    try:
        # If there's a "Log in" button that navigates to the real form, click it.
        page.get_by_role("button", name="Log in").click(timeout=5000)
        page.wait_for_timeout(1000)
    except Exception:
        pass  # best effort

    # Fill the form – these selectors are based on Spotify's current login page.
    # You might need to tweak if they change the DOM.
    page.fill('input#login-username', email)
    page.fill('input#login-password', password)

    # The main login button
    page.click('button#login-button')

    # Wait for redirect back to open.spotify.com
    try:
        page.wait_for_url("**open.spotify.com**", timeout=30000)
    except PlaywrightTimeoutError:
        eprint("[spotify_invite_bot] Login did not redirect to open.spotify.com in time")
        # Still try to save state so next run might skip some steps
        context.storage_state(path=AUTH_STATE_PATH)
        return

    # Save auth state so future runs don't have to log in
    context.storage_state(path=AUTH_STATE_PATH)
    eprint("[spotify_invite_bot] Login successful and auth state saved")


def open_playlist_and_get_invite_link(page, playlist_id: str) -> str:
    """
    Opens the collaborative playlist page and clicks:
      • More options (three dots)
      • Invite collaborators
      • Copy link
    Then reads the clipboard via JS and returns the link.
    """
    target_url = PLAYLIST_BASE_URL + playlist_id
    eprint(f"[spotify_invite_bot] Opening {target_url}")
    page.goto(target_url, wait_until="networkidle", timeout=60000)

    # If we got bounced to login, handle that.
    if "login" in page.url or "accounts.spotify.com" in page.url:
        login_if_needed(page, page.context)
        # Go back to the playlist page after login
        eprint("[spotify_invite_bot] Reloading playlist after login")
        page.goto(target_url, wait_until="networkidle", timeout=60000)

    # Give it a moment for all React bits to settle
    page.wait_for_timeout(2000)

    # Try to locate the "More options" (three dots) button.
    # We'll try a few strategies in order.
    more_button = None
    try:
        more_button = page.get_by_label("More options")
    except Exception:
        pass

    if not more_button:
        try:
            more_button = page.get_by_role("button", name="More options")
        except Exception:
            pass

    if not more_button:
        try:
            # Fallback: any button that has an aria-label with "More"
            more_button = page.locator('button[aria-label*="More"]')
        except Exception:
            pass

    if not more_button:
        eprint("[spotify_invite_bot] Could not find 'More options' button")
        sys.exit(1)

    more_button.click()
    page.wait_for_timeout(500)

    # Click "Invite collaborators"
    # Text might change slightly, so we use partial match and case-insensitive.
    invite_item = None
    try:
        invite_item = page.get_by_text("Invite collaborators", exact=False)
    except Exception:
        pass

    if not invite_item:
        eprint("[spotify_invite_bot] Could not find 'Invite collaborators' menu item")
        sys.exit(1)

    invite_item.click()
    page.wait_for_timeout(500)

    # Click "Copy link"
    copy_item = None
    try:
        copy_item = page.get_by_text("Copy link", exact=False)
    except Exception:
        pass

    if not copy_item:
        eprint("[spotify_invite_bot] Could not find 'Copy link' button")
        sys.exit(1)

    copy_item.click()
    page.wait_for_timeout(500)

    # Ensure we have clipboard perms and read from clipboard via JS
    page.context.grant_permissions(
        ["clipboard-read", "clipboard-write"],
        origin="https://open.spotify.com",
    )

    try:
        link = page.evaluate("navigator.clipboard.readText()")
    except Exception as e:
        eprint(f"[spotify_invite_bot] Failed to read clipboard: {e}")
        sys.exit(1)

    if not link or not isinstance(link, str):
        eprint("[spotify_invite_bot] Clipboard did not contain a link")
        sys.exit(1)

    link = link.strip()
    eprint(f"[spotify_invite_bot] Got invite link: {link}")

    return link


def main():
    if len(sys.argv) != 2:
        eprint("Usage: spotify_invite_bot.py <playlist_id>")
        sys.exit(1)

    playlist_id = sys.argv[1].strip()
    if not playlist_id:
        eprint("Empty playlist_id")
        sys.exit(1)

    # Basic sanity check: Spotify playlist IDs are 22 characters usually,
    # but we won't be too strict here.
    if "/" in playlist_id or "http" in playlist_id:
        eprint("Please pass only the raw playlist ID, not a full URL")
        sys.exit(1)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=HEADLESS)
        context_kwargs = {}

        # Reuse saved auth state if it exists
        if AUTH_STATE_PATH.exists():
            eprint(f"[spotify_invite_bot] Using existing auth state: {AUTH_STATE_PATH}")
            context_kwargs["storage_state"] = str(AUTH_STATE_PATH)

        context = browser.new_context(**context_kwargs)
        page = context.new_page()

        try:
            invite_link = open_playlist_and_get_invite_link(page, playlist_id)
        finally:
            context.close()
            browser.close()

    # IMPORTANT: print ONLY the link to stdout so Django can read it cleanly
    print(invite_link)


if __name__ == "__main__":
    main()
