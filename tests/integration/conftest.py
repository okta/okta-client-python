# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

"""Shared fixtures for integration tests."""

from __future__ import annotations

import asyncio
import json
import os
import threading
import webbrowser
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import urlparse

import pytest

from okta_client.authfoundation import OAuth2Client, OAuth2ClientConfiguration, Token
from okta_client.oauth2auth import AuthorizationCodeFlow

from .utils import repo_root

# ---------------------------------------------------------------------------
# Redirect callback capture
# ---------------------------------------------------------------------------


class _RedirectCapture:
    """Thread-safe container for the captured redirect URL."""

    def __init__(self) -> None:
        self.url: str | None = None
        self._event = threading.Event()

    def set(self, url: str) -> None:
        self.url = url
        self._event.set()

    def wait(self, timeout: float = 120) -> str | None:
        self._event.wait(timeout)
        return self.url


def _make_callback_handler(capture: _RedirectCapture, callback_path: str):
    """Return a request handler class that captures the first matching redirect."""

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path.startswith(callback_path):
                port = self.server.server_address[1]  # type: ignore[index]
                capture.set(f"http://localhost:{port}{self.path}")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<html><body>"
                    b"<h1>Sign-in complete!</h1>"
                    b"<p>You may close this tab.</p>"
                    b"</body></html>"
                )
            else:
                self.send_response(204)
                self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            pass

    return _Handler


def _start_callback_server(
    redirect_uri: str,
    capture: _RedirectCapture,
) -> HTTPServer:
    """Start a local HTTP server that listens for the authorization callback."""
    parsed = urlparse(redirect_uri)
    port = parsed.port if parsed.port is not None else 8080
    path = parsed.path or "/"
    handler_cls = _make_callback_handler(capture, path)
    server = HTTPServer(("localhost", port), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _run_automated_signin(url: str, credentials: dict[str, str]) -> None:
    """Use Selenium to automate the Okta Identity Engine sign-in page."""
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.support.ui import WebDriverWait

    options = webdriver.ChromeOptions()
    if os.environ.get("CI"):
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")

    driver = webdriver.Chrome(options=options)
    try:
        driver.get(url)
        wait = WebDriverWait(driver, 60)

        username_input = wait.until(
            EC.presence_of_element_located((By.NAME, "identifier"))
        )
        username_input.send_keys(credentials["username"])

        next_button = wait.until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, "[type='submit']"))
        )
        next_button.click()

        select_password = WebDriverWait(driver, 5).until(
            EC.element_to_be_clickable((
                By.CSS_SELECTOR,
                "a[aria-label='Select Password.']",
            ))
        )
        select_password.click()

        password_input = wait.until(
            EC.presence_of_element_located((
                By.CSS_SELECTOR,
                "input[name='credentials.passcode'], "
                "input[name='passcode'], "
                "input[type='password']",
            ))
        )
        password_input.send_keys(credentials["password"])

        verify_button = wait.until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, "[type='submit']"))
        )
        verify_button.click()

        wait.until(
            lambda d: "localhost" in (urlparse(d.current_url).hostname or "")
        )
    finally:
        driver.quit()


_BROWSER_TIMEOUT = 120


def _perform_web_signin(
    overrides: dict[str, Any] | None = None,
) -> Token:
    """Execute the full Authorization Code (PKCE) flow with browser sign-in.

    Args:
        overrides: Optional mapping of attribute names to values that will
            be applied to the :class:`OAuth2ClientConfiguration` loaded
            from ``okta-web.json`` via :func:`dataclasses.replace`.

    Returns the :class:`Token` from the token exchange.  Skips the test
    if ``okta-web.json`` is not present.
    """
    root = repo_root()
    okta_web = root / "okta-web.json"
    test_config_1fa = root / "test-configuration-1fa.json"

    if not okta_web.exists():
        pytest.skip("okta-web.json not found")

    config = OAuth2ClientConfiguration.from_file(str(okta_web))
    if overrides:
        config = replace(config, **overrides)
    assert config.redirect_uri, "okta-web.json must include redirect_uri"

    client = OAuth2Client(
        configuration=replace(
            config,
            base_url=config.issuer,
            user_agent="okta-client-python-integration-test",
        )
    )

    flow = AuthorizationCodeFlow(client=client)
    authorize_url = asyncio.run(flow.start())

    verbose = os.environ.get("INTEGRATION_VERBOSE")
    if verbose:
        print(f"\nAuthorize URL:\n  {authorize_url}\n")

    capture = _RedirectCapture()
    server = _start_callback_server(config.redirect_uri, capture)

    try:
        if test_config_1fa.exists():
            creds = json.loads(test_config_1fa.read_text(encoding="utf-8"))
            signin_thread = threading.Thread(
                target=_run_automated_signin,
                args=(authorize_url, creds),
                daemon=True,
            )
            signin_thread.start()
        else:
            print(f"\nOpen the following URL to sign in:\n  {authorize_url}\n")
            webbrowser.open(authorize_url)

        redirect_url = capture.wait(timeout=_BROWSER_TIMEOUT)
    finally:
        server.shutdown()

    assert redirect_url is not None, (
        "Timed out waiting for the authorization callback.  "
        f"Ensure sign-in completed within {_BROWSER_TIMEOUT}s."
    )

    token = asyncio.run(flow.resume(redirect_url))

    if verbose:
        print("\nToken Details:")
        print(f"  Access Token: {token.access_token[:20]}...")
        print(f"  Token Type:   {token.token_type}")
        print(f"  Expires In:   {token.expires_in}")
        print(f"  Scope:        {token.scope}")
        print(f"  ID Token:     {'present' if token.id_token else 'None'}")
        print(f"  Refresh Token: {'present' if token.refresh_token else 'None'}")
        print()

    return token


@pytest.fixture(scope="module")
def web_signin_overrides() -> dict[str, Any] | None:
    """Return configuration overrides for the web sign-in flow.

    Override this fixture in a downstream conftest or test module to
    customise the :class:`OAuth2ClientConfiguration` used by
    :func:`web_signin_token`.
    """
    return None


@pytest.fixture(scope="module")
def web_signin_token(web_signin_overrides: dict[str, Any] | None) -> Token:
    """Module-scoped fixture: perform web redirect sign-in once per module and share the token."""
    return _perform_web_signin(overrides=web_signin_overrides)
