# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

"""Web redirect sign-in integration test.

Exercises the full Authorization Code Flow (PKCE) end-to-end via the
shared ``web_signin_token`` session fixture (see ``conftest.py``).

The fixture performs:

1. ``AuthorizationCodeFlow.start()`` to build the authorize URL.
2. A local HTTP server to capture the redirect callback.
3. Browser-based sign-in (Selenium in CI, system browser locally).
4. ``AuthorizationCodeFlow.resume()`` to exchange the code for tokens.

This test validates the returned token fields.

Prerequisites
~~~~~~~~~~~~~

- ``okta-web.json`` — OAuth2 client configuration with ``client_secret``,
  ``redirect_uri`` pointing to ``http://localhost:<port>/...``, and scopes
  including ``openid``.
- ``test-configuration-1fa.json`` *(optional)* — JSON with ``username`` and
  ``password`` keys for headless browser automation.  When absent the test
  opens the system browser for manual sign-in.
- For CI: Google Chrome / Chromium and the ``selenium`` pip package.
"""

from __future__ import annotations

import pytest

from okta_client.authfoundation import Token

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_web_redirect_signin(web_signin_token: Token) -> None:
    """Full end-to-end Authorization Code (PKCE) flow with browser sign-in."""
    token = web_signin_token

    assert token.access_token, "Expected an access token"
    assert token.token_type.lower() == "bearer"
    assert token.id_token is not None, "Expected an ID token for openid scope"

    granted_scopes = set(token.scope or [])
    if "offline_access" in granted_scopes:
        assert token.refresh_token, "Expected a refresh token for offline_access scope"
