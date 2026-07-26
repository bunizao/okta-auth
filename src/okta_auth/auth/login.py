"""Generalized Okta SSO login engine.

Performs browser-based authentication with support for:
- Single-page and two-step Okta login flows
- TOTP-based MFA (Google Authenticator, Okta Verify, etc.)
- Session persistence via Playwright storage_state
"""

from __future__ import annotations

import asyncio
import tempfile
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from playwright.async_api import Page
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from okta_auth.auth import session_store
from okta_auth.auth.totp import gen_totp
from okta_auth.browser.controller import BrowserConfig, BrowserController
from okta_auth.browser.detection import is_browser_channel_available
from okta_auth.browser.helpers import (
    click_first_match,
    fill_first_match,
    maybe_switch_to_code_factor,
)
from okta_auth.log import debug_detail, logger


@dataclass
class LoginCredentials:
    username: Optional[str] = None
    password: Optional[str] = None
    totp_secret: Optional[str] = None


# ---------- Selector banks ----------

USERNAME_SELECTORS = [
    "#okta-signin-username",
    'input[name="identifier"]',
    'input[name="username"]',
    'input[autocomplete="username"]',
    'input[type="email"]',
    'input[data-se="o-form-input-username"]',
    'input[data-se*="username"]',
    'input[id="idp-discovery-username"]',
    'input[placeholder*="user" i]',
    'input[placeholder*="email" i]',
    'input[id*="username" i]',
    'input[id*="user" i]',
    'input[name*="user"]',
    'input[name*="login"]',
    'input[name*="email"]',
    'input[type="text"]:visible',
    "input:not([type]):visible",
]

PASSWORD_SELECTORS = [
    "#okta-signin-password",
    'input[name="password"]',
    'input[autocomplete="current-password"]',
    'input[type="password"]',
    'input[data-se="o-form-input-password"]',
    'input[data-se*="password"]',
    'input[placeholder*="pass" i]',
    'input[id*="password" i]',
    'input[name*="pass"]',
    'input[name*="pwd"]',
]

SUBMIT_SELECTORS = [
    'button[type="submit"]',
    'input[type="submit"]',
    'button:has-text("Sign in")',
    'button:has-text("Log in")',
    "#okta-signin-submit",
]

NEXT_SELECTORS = [
    'button[type="submit"]',
    'input[type="submit"]',
    'button:has-text("Next")',
    'button:has-text("Continue")',
]

OTP_SELECTORS = [
    'input[name="credentials.passcode"]',
    'input[name="credentials.otp"]',
    'input[name="otp"]',
    'input[name="code"]',
    'input[name="passcode"]',
    'input[autocomplete="one-time-code"]',
    'input[inputmode="numeric"]',
    'input[type="tel"]',
    'input[type="text"][autocomplete="off"]',
    'input[id*="code" i]',
    'input[placeholder*="code" i]',
    'input[placeholder*="OTP" i]',
    'input[type="text"]:visible',
]

MFA_SUBMIT_SELECTORS = [
    'button[type="submit"]',
    'input[type="submit"]',
    'button:has-text("Verify")',
    'button:has-text("Submit")',
]


async def _is_on_portal(page: Page) -> bool:
    """Check if we've left Okta and are on the target portal."""
    host = urlparse(page.url).netloc.lower()
    if "okta" in host:
        return False
    try:
        login_fields = page.locator(
            '#okta-signin-username, input[name="username"], '
            'input[type="password"], #okta-signin-password'
        )
        visible = await login_fields.first.is_visible(timeout=1500)
        return not visible
    except Exception:
        return True


async def auto_login(page: Page, creds: LoginCredentials) -> bool:
    """Attempt automated Okta login with credentials and optional TOTP MFA."""
    if not (creds.username and creds.password):
        logger.warning("No username or password provided, skipping auto-login")
        return False

    logger.info("Attempting automatic login...")

    # Wait for page load
    try:
        await page.wait_for_load_state("networkidle", timeout=10000)
    except Exception:
        pass

    # Check if already logged in
    if await _is_on_portal(page):
        logger.info("Already logged in")
        return True

    # Fill username
    logger.info("Filling username...")
    user_ok = await fill_first_match(page, USERNAME_SELECTORS, creds.username)
    if not user_ok:
        logger.warning("Failed to fill username field")

    # Fill password
    logger.info("Filling password...")
    pass_ok = await fill_first_match(page, PASSWORD_SELECTORS, creds.password)

    # Two-step login: username first, then password on next page
    if user_ok and not pass_ok:
        logger.info("Two-step login detected, clicking Next...")
        await click_first_match(page, NEXT_SELECTORS)
        await asyncio.sleep(3)

        try:
            await page.wait_for_selector(
                'input[type="password"], input[name="password"]', timeout=10000
            )
        except Exception:
            logger.warning("Password field not found after Next step")

        pass_ok = await fill_first_match(page, PASSWORD_SELECTORS, creds.password)
        if pass_ok:
            await click_first_match(page, SUBMIT_SELECTORS)
        else:
            logger.warning("Failed to fill password on second page")
            return False
    elif user_ok and pass_ok:
        await click_first_match(page, SUBMIT_SELECTORS)
    else:
        logger.warning("Could not fill username or password fields")
        return False

    await asyncio.sleep(3)

    # Handle MFA
    if creds.totp_secret:
        logger.info("Handling MFA with TOTP...")
        await maybe_switch_to_code_factor(page)

        otp = gen_totp(creds.totp_secret)
        debug_detail(f"Generated TOTP code: {otp}")

        otp_ok = await fill_first_match(page, OTP_SELECTORS, otp)

        # Try individual digit boxes
        if not otp_ok:
            boxes = page.locator('input[aria-label*="digit" i], input[maxlength="1"]')
            try:
                count = await boxes.count()
                if count >= 6:
                    for i, ch in enumerate(otp[:count]):
                        await boxes.nth(i).fill(ch)
                    otp_ok = True
            except Exception:
                pass

        if otp_ok:
            await click_first_match(page, MFA_SUBMIT_SELECTORS)
            await asyncio.sleep(5)
        else:
            logger.warning("Could not enter MFA code")
            return False

    # Wait for authentication to complete
    logger.info("Waiting for authentication to complete...")
    for _ in range(10):
        await asyncio.sleep(1)
        if await _is_on_portal(page):
            logger.info("Successfully authenticated — now on %s", urlparse(page.url).netloc)
            return True

    if "okta" in urlparse(page.url).netloc.lower():
        logger.warning("Still on Okta domain after login attempt")
        return False

    logger.info("Auto-login completed")
    return True


async def perform_login(
    url: str,
    username: str,
    password: str,
    totp_secret: Optional[str] = None,
    browser_name: str = "chromium",
    channel: Optional[str] = None,
    headed: bool = False,
    timeout_ms: int = 60000,
    settle_ms: int = 0,
) -> dict:
    """High-level login function: authenticate and store session.

    Returns a dict with keys: success, domain_key, message, url.
    """
    # Auto-detect best browser channel
    if not channel and browser_name == "chromium":
        if is_browser_channel_available("chrome"):
            channel = "chrome"

    creds = LoginCredentials(
        username=username,
        password=password,
        totp_secret=totp_secret,
    )

    config = BrowserConfig(
        name=browser_name,
        channel=channel,
        headed=headed,
        timeout_ms=timeout_ms,
    )

    # Use a temp file for initial storage state, then persist to session store
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp:
        tmp_path = tmp.name

    try:
        async with BrowserController(config) as controller:
            page = await controller.context.new_page()
            await page.goto(url, timeout=timeout_ms)

            success = await auto_login(page, creds)

            if success:
                if settle_ms > 0:
                    try:
                        await page.wait_for_load_state("networkidle", timeout=settle_ms)
                    except PlaywrightTimeoutError:
                        pass
                await controller.context.storage_state(path=tmp_path)
                domain_key = session_store.save_session(url, tmp_path)
                return {
                    "success": True,
                    "domain_key": domain_key,
                    "message": f"Session saved for {domain_key}",
                    "url": url,
                }
            else:
                return {
                    "success": False,
                    "domain_key": None,
                    "message": "Auto-login failed — could not authenticate",
                    "url": url,
                }
    except Exception as exc:
        return {
            "success": False,
            "domain_key": None,
            "message": f"Login error: {type(exc).__name__}: {exc}",
            "url": url,
        }
    finally:
        import os

        try:
            os.unlink(tmp_path)
        except OSError:
            pass


async def verify_session(
    url: str,
    browser_name: str = "chromium",
    channel: Optional[str] = None,
    timeout_ms: int = 30000,
) -> dict:
    """Check if a stored session for the given URL is still valid.

    Returns a dict with keys: valid, domain_key, message, url.
    """
    session_path = session_store.get_session_path(url)
    if not session_path:
        return {
            "valid": False,
            "domain_key": None,
            "message": "No stored session found for this URL",
            "url": url,
        }

    if not channel and browser_name == "chromium":
        if is_browser_channel_available("chrome"):
            channel = "chrome"

    config = BrowserConfig(
        name=browser_name,
        channel=channel,
        headed=False,
        storage_state=session_path,
        timeout_ms=timeout_ms,
    )

    try:
        async with BrowserController(config) as controller:
            page = await controller.context.new_page()
            await page.goto(url, timeout=timeout_ms)
            active = await _is_on_portal(page)
            return {
                "valid": active,
                "domain_key": session_store._domain_key(url),
                "message": "Session is active" if active else "Session expired or invalid",
                "url": url,
            }
    except Exception as exc:
        return {
            "valid": False,
            "domain_key": session_store._domain_key(url),
            "message": f"Session check error: {type(exc).__name__}: {exc}",
            "url": url,
        }
