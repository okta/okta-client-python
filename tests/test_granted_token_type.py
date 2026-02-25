# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

"""Tests for GrantedTokenType enum behavior, str compatibility, and Token integration."""

from __future__ import annotations

from okta_client.authfoundation import GrantedTokenType, Token, TokenContext
from okta_client.authfoundation.networking import APIRequestMethod, HTTPRequest

_DEFAULT_CONTEXT = TokenContext(issuer="https://example.com", client_id="client")


# ===========================================================================
# GrantedTokenType enum
# ===========================================================================


class TestGrantedTokenType:
    def test_bearer_equals_string(self) -> None:
        assert GrantedTokenType.BEARER == "Bearer"

    def test_dpop_equals_string(self) -> None:
        assert GrantedTokenType.DPOP == "DPoP"

    def test_na_equals_string(self) -> None:
        assert GrantedTokenType.NA == "N_A"

    def test_bearer_is_instance_of_str(self) -> None:
        assert isinstance(GrantedTokenType.BEARER, str)

    def test_fstring_interpolation(self) -> None:
        """Ensure enum works in f-strings (used by authorize)."""
        assert f"{GrantedTokenType.BEARER} token123" == "Bearer token123"


# ===========================================================================
# Token.authorize with GrantedTokenType
# ===========================================================================


def _make_request() -> HTTPRequest:
    return HTTPRequest(method=APIRequestMethod.GET, url="https://example.com", headers={}, body=None, timeout=None)


class TestTokenAuthorizeWithEnum:
    def test_bearer_authorize(self) -> None:
        token = Token(
            access_token="tok",
            token_type=GrantedTokenType.BEARER,
            _expires_in=3600,
            context=_DEFAULT_CONTEXT,
        )
        req = token.authorize(_make_request())
        assert req.headers["Authorization"] == "Bearer tok"

    def test_na_authorize(self) -> None:
        """N_A tokens still produce an authorization header (the caller decides usage)."""
        token = Token(
            access_token="jag",
            token_type=GrantedTokenType.NA,
            _expires_in=300,
            context=_DEFAULT_CONTEXT,
        )
        req = token.authorize(_make_request())
        assert req.headers["Authorization"] == "N_A jag"


# ===========================================================================
# Token constructed with string still works (backward compat)
# ===========================================================================


class TestTokenBackwardCompat:
    def test_construct_with_string_bearer(self) -> None:
        token = Token(
            access_token="t",
            token_type="Bearer",
            _expires_in=3600,
            context=_DEFAULT_CONTEXT,
        )
        assert token.token_type == "Bearer"
        req = token.authorize(_make_request())
        assert req.headers["Authorization"] == "Bearer t"
