# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

from okta_client.authfoundation import GrantedTokenType, Token, TokenContext
from okta_client.authfoundation.networking import APIRequestMethod, HTTPRequest


def _make_request() -> HTTPRequest:
    return HTTPRequest(method=APIRequestMethod.GET, url="https://example.com", headers={}, body=None, timeout=None)


def test_token_authorize() -> None:
    context = TokenContext(issuer="https://example.com", client_id="client")
    token = Token(
        access_token="token",
        token_type="Bearer",
        _expires_in=3600,
        _issued_at=1000.0,
        context=context,
    )

    req = token.authorize(_make_request())
    assert req.headers["Authorization"] == "Bearer token"


def test_token_from_response_parses_scope() -> None:
    context = TokenContext(issuer="https://example.com", client_id="client")
    token = Token.from_response(
        {
            "access_token": "token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "openid profile",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        },
        context=context,
        issued_at=123.0,
    )

    assert token.scope == ["openid", "profile"]
    assert token.issued_token_type == "urn:ietf:params:oauth:token-type:access_token"


def test_token_requires_access_token() -> None:
    context = TokenContext(issuer="https://example.com", client_id="client")
    try:
        Token(
            access_token="",
            token_type="Bearer",
            _expires_in=3600,
            _issued_at=1000.0,
            context=context,
        )
    except ValueError:
        return
    raise AssertionError("Expected ValueError for missing access_token")


def test_token_requires_token_type() -> None:
    context = TokenContext(issuer="https://example.com", client_id="client")
    try:
        Token(
            access_token="token",
            token_type="",
            _expires_in=3600,
            _issued_at=1000.0,
            context=context,
        )
    except ValueError:
        return
    raise AssertionError("Expected ValueError for missing token_type")


def test_token_requires_expires_in() -> None:
    context = TokenContext(issuer="https://example.com", client_id="client")
    try:
        Token(
            access_token="token",
            token_type="Bearer",
            _expires_in=None,  # type: ignore[arg-type]
            _issued_at=1000.0,
            context=context,
        )
    except ValueError:
        return
    raise AssertionError("Expected ValueError for missing expires_in")


def test_token_rejects_negative_expires_in() -> None:
    context = TokenContext(issuer="https://example.com", client_id="client")
    try:
        Token(
            access_token="token",
            token_type="Bearer",
            _expires_in=-1,
            _issued_at=1000.0,
            context=context,
        )
    except ValueError:
        return
    raise AssertionError("Expected ValueError for negative expires_in")


def test_token_from_response_requires_expires_in() -> None:
    context = TokenContext(issuer="https://example.com", client_id="client")
    try:
        Token.from_response(
            {
                "access_token": "token",
                "token_type": "Bearer",
            },
            context=context,
            issued_at=123.0,
        )
    except ValueError:
        return
    raise AssertionError("Expected ValueError for missing expires_in")


def test_token_merge_prefers_new_values() -> None:
    context = TokenContext(issuer="https://example.com", client_id="client")
    previous = Token(
        access_token="old",
        token_type="Bearer",
        _expires_in=3600,
        _issued_at=1000.0,
        context=context,
        refresh_token="refresh-old",
        scope=["openid"],
        raw_fields={"access_token": "old", "custom": "keep"},
    )
    refreshed = Token(
        access_token="new",
        token_type="Bearer",
        _expires_in=1800,
        _issued_at=2000.0,
        context=context,
        refresh_token=None,
        scope=None,
        raw_fields={"access_token": "new", "custom": "override"},
    )

    merged = refreshed.merge(previous)

    assert merged.access_token == "new"
    assert merged.expires_in == 1800
    assert merged.refresh_token == "refresh-old"
    assert merged.scope == ["openid"]
    assert merged.raw_fields == {"access_token": "new", "custom": "override"}


# ===========================================================================
# Token.from_response — GrantedTokenType enum resolution
# ===========================================================================


class TestTokenFromResponseEnum:
    def test_resolves_bearer(self) -> None:
        context = TokenContext(issuer="https://example.com", client_id="client")
        token = Token.from_response(
            {"access_token": "t", "token_type": "Bearer", "expires_in": 3600},
            context=context,
        )
        assert token.token_type is GrantedTokenType.BEARER
        assert token.token_type == "Bearer"

    def test_resolves_na(self) -> None:
        context = TokenContext(issuer="https://example.com", client_id="client")
        token = Token.from_response(
            {"access_token": "t", "token_type": "N_A", "expires_in": 300},
            context=context,
        )
        assert token.token_type is GrantedTokenType.NA
        assert token.token_type == "N_A"

    def test_resolves_dpop(self) -> None:
        context = TokenContext(issuer="https://example.com", client_id="client")
        token = Token.from_response(
            {"access_token": "t", "token_type": "DPoP", "expires_in": 3600},
            context=context,
        )
        assert token.token_type is GrantedTokenType.DPOP

    def test_unknown_type_falls_through_as_string(self) -> None:
        context = TokenContext(issuer="https://example.com", client_id="client")
        token = Token.from_response(
            {"access_token": "t", "token_type": "mac", "expires_in": 3600},
            context=context,
        )
        assert token.token_type == "mac"
        assert not isinstance(token.token_type, GrantedTokenType)

    def test_id_jag_response_fields(self) -> None:
        """Full ID-JAG response: token_type=N_A, issued_token_type=id-jag URN."""
        context = TokenContext(issuer="https://example.com", client_id="client")
        token = Token.from_response(
            {
                "access_token": "eyJhbGciOiJIUzI1NiJ9.e30.abc",
                "token_type": "N_A",
                "expires_in": 300,
                "scope": "chat.read chat.history",
                "issued_token_type": "urn:ietf:params:oauth:token-type:id-jag",
            },
            context=context,
        )
        assert token.token_type is GrantedTokenType.NA
        assert token.issued_token_type == "urn:ietf:params:oauth:token-type:id-jag"
        assert token.scope == ["chat.read", "chat.history"]
        assert token.expires_in == 300
