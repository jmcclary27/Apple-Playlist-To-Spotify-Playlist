#!/usr/bin/env python
import os
import sys
import json
import time
from pathlib import Path
import re

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


def login_with_service_account(page, context):
    """
    Always log in as the service account on the accounts.spotify.com login page.
    Uses flexible selectors to handle minor UI changes.
    """
    email = require_env("SPOTIFY_SERVICE_EMAIL")
    password = require_env("SPOTIFY_SERVICE_PASSWORD")

    eprint("[spotify_invite_bot] Navigating to Spotify login page")
    page.goto("https://accounts.spotify.com/en/login", wait_until="domcontentloaded", timeout=60000)

    # Best-effort: dismiss cookie / consent banner if it exists
    try:
        cookie_button = page.get_by_role("button", name=re.compile("Accept|Agree", re.I))
        cookie_button.click(timeout=3000)
        page.wait_for_timeout(500)
        eprint("[spotify_invite_bot] Clicked cookie consent button")
    except Exception:
        pass

    # Sometimes there's a "Log in" button before the actual form
    try:
        login_btn = page.get_by_role("button", name=re.compile("Log in", re.I))
        login_btn.click(timeout=3000)
        page.wait_for_timeout(1000)
        eprint("[spotify_invite_bot] Clicked preliminary 'Log in' button")
    except Exception:
        pass

    # Find the username/email input using multiple possible attributes
    username_locator = page.locator(
        'input#login-username, input[name="username"], input[autocomplete="username"], input[type="text"]'
    ).first

    try:
        username_locator.wait_for(state="visible", timeout=30000)
    except PlaywrightTimeoutError:
        eprint("[spotify_invite_bot] Could not find username field on login page")
        eprint("[spotify_invite_bot] Current URL:", page.url)
        sys.exit(1)

    username_locator.fill(email)

    # Find the password input similarly
    password_locator = page.locator(
        'input#login-password, input[name="password"], input[autocomplete="current-password"], input[type="password"]'
    ).first

    try:
        password_locator.wait_for(state="visible", timeout=30000)
    except PlaywrightTimeoutError:
        eprint("[spotify_invite_bot] Could not find password field on login page")
        eprint("[spotify_invite_bot] Current URL:", page.url)
        sys.exit(1)

    password_locator.fill(password)

    # Click the main "Log in" button (by role + name or fallback to submit button)
    try:
        login_button = page.get_by_role("button", name=re.compile("Log in", re.I))
    except Exception:
        login_button = page.locator('button[type="submit"]').first

    login_button.click()
    eprint("[spotify_invite_bot] Submitted login form, waiting for redirect...")

    try:
        page.wait_for_url("**open.spotify.com**", timeout=60000)
    except PlaywrightTimeoutError:
        eprint("[spotify_invite_bot] Login did not redirect to open.spotify.com in time")
        # Still continue; some flows might keep us on accounts domain briefly

    eprint("[spotify_invite_bot] Login complete as service account (URL: %s)" % page.url)


def open_playlist_and_get_invite_link(page, playlist_id: str) -> str:
    target_url = PLAYLIST_BASE_URL + playlist_id
    eprint(f"[spotify_invite_bot] Opening {target_url}")
    page.goto(target_url, wait_until="networkidle", timeout=60000)

    # Small wait for React to fully settle
    page.wait_for_timeout(2000)

    # Click playlist-level "More options"
    try:
        action_bar = page.get_by_test_id("action-bar-row")
        more_button = action_bar.get_by_test_id("more-button").first
    except Exception as e:
        eprint(f"[spotify_invite_bot] Could not find playlist action-bar more button: {e}")
        sys.exit(1)

    more_button.click()
    page.wait_for_timeout(800)

    # Read menu items and pick the one with "invite"
    menu_items_locator = page.locator('[role="menuitem"]')
    menu_texts = menu_items_locator.all_text_contents()
    eprint("[spotify_invite_bot] Menu items:", menu_texts)

    invite_index = None
    for idx, text in enumerate(menu_texts):
        if "invite" in text.lower():
            invite_index = idx
            break

    if invite_index is None:
        eprint("[spotify_invite_bot] Could not find any menu item with 'invite' in the text")
        sys.exit(1)

    invite_item = menu_items_locator.nth(invite_index)
    eprint(f"[spotify_invite_bot] Clicking invite menu item: {menu_texts[invite_index]!r}")
    invite_item.click()
    page.wait_for_timeout(800)

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

    if "/" in playlist_id or "http" in playlist_id:
        eprint("Please pass only the raw playlist ID, not a full URL")
        sys.exit(1)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=HEADLESS)
        context = browser.new_context()
        page = context.new_page()

        try:
            # 1) Log in as the service account
            login_with_service_account(page, context)

            # 2) Now open the playlist *as that account*
            invite_link = open_playlist_and_get_invite_link(page, playlist_id)
        finally:
            context.close()
            browser.close()

    print(invite_link)


if __name__ == "__main__":
    main()
