# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from okta_client.authfoundation.oauth2 import OAuth2Error

__all__ = [
    "parse_redirect_uri",
]

def parse_redirect_uri(
    url: str,
    *,
    expected_state: str,
    expected_redirect_uri: str,
) -> str:
    """Parse an authorization redirect URI and extract the authorization code.

    Validates:
    - The redirect URI scheme+host+path matches ``expected_redirect_uri``.
    - No ``error`` parameter is present in the query string.
    - The ``state`` parameter matches ``expected_state``.
    - A ``code`` parameter is present and non-empty.

    Returns the authorization ``code`` value.

    Raises:
        OAuth2Error: On error responses, state mismatch, or missing code.
    """
    parsed = urlparse(url)
    expected = urlparse(expected_redirect_uri)

    def _effective_port(parts: object, scheme: str) -> int | None:
        """Return the explicit port, or the default for the scheme."""
        port = getattr(parts, "port", None)
        if port is not None:
            return port
        return 443 if scheme == "https" else 80 if scheme == "http" else None

    if (
        parsed.scheme != expected.scheme
        or parsed.hostname != expected.hostname
        or _effective_port(parsed, parsed.scheme) != _effective_port(expected, expected.scheme)
        or parsed.path != expected.path
    ):
        raise OAuth2Error(
            error="redirect_uri_mismatch",
            error_description=(
                f"Redirect URI does not match the expected URI: "
                f"expected {expected_redirect_uri}, got {parsed.scheme}://{parsed.netloc}{parsed.path}"
            ),
        )

    query_params = parse_qs(parsed.query, keep_blank_values=True)

    error = query_params.get("error")
    if error:
        raise OAuth2Error(
            error=error[0],
            error_description=query_params.get("error_description", [None])[0],
        )

    state_values = query_params.get("state")
    if not state_values or state_values[0] != expected_state:
        raise OAuth2Error(
            error="state_mismatch",
            error_description="The state parameter in the redirect URI does not match the expected state.",
        )

    code_values = query_params.get("code")
    if not code_values or not code_values[0]:
        raise OAuth2Error(
            error="missing_code",
            error_description="The redirect URI does not contain an authorization code.",
        )

    return code_values[0]
