# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

import asyncio
import json
from urllib.parse import parse_qs, urlsplit

from okta_client.authfoundation import (
    APIRetry,
    ClientIdAuthorization,
    NetworkInterface,
    OAuth2Client,
    OAuth2ClientConfiguration,
    OAuth2ClientListener,
    OAuth2Error,
    RawResponse,
    Token,
    TokenContext,
)

_REFRESH_GRANT = "refresh_token"


class DummyNetwork(NetworkInterface):
    def __init__(self, token_body: dict, status_code: int = 200) -> None:
        self.token_body = token_body
        self.status_code = status_code
        self.last_token_body: dict[str, list[str]] | None = None
        self.token_requests = 0

    def send(self, request) -> RawResponse:
        path = urlsplit(request.url).path
        if path.endswith(".well-known/openid-configuration"):
            body = {
                "issuer": "https://example.com",
                "authorization_endpoint": "https://example.com/auth",
                "token_endpoint": "https://example.com/token",
                "jwks_uri": "https://example.com/keys",
            }
            return RawResponse(status_code=200, headers={}, body=json.dumps(body).encode("utf-8"))
        if "/keys" in request.url:
            return RawResponse(status_code=200, headers={}, body=json.dumps({"keys": []}).encode("utf-8"))
        if request.url.endswith("/token"):
            self.token_requests += 1
            if request.body:
                self.last_token_body = parse_qs(request.body.decode("utf-8"))
            return RawResponse(status_code=self.status_code, headers={}, body=json.dumps(self.token_body).encode("utf-8"))
        return RawResponse(status_code=200, headers={}, body=b"{}")


class ListenerStub(OAuth2ClientListener):
    def __init__(self) -> None:
        self.will_refresh = 0
        self.did_refresh = 0
        self.last_old: Token | None = None
        self.last_new: Token | None = None

    def will_send(self, client, request) -> None:  # type: ignore[override]
        return None

    def did_send(self, client, request, response) -> None:  # type: ignore[override]
        return None

    def did_send_error(self, client, request, error) -> None:  # type: ignore[override]
        return None

    def should_retry(self, client, request, rate_limit):  # type: ignore[override]
        return APIRetry.default()

    def will_refresh_token(self, client: OAuth2Client, token: Token) -> None:
        self.will_refresh += 1
        self.last_old = token

    def did_refresh_token(self, client: OAuth2Client, token: Token, refreshed_token: Token | None) -> None:
        self.did_refresh += 1
        self.last_old = token
        self.last_new = refreshed_token


def _build_client(network: NetworkInterface) -> OAuth2Client:
    config = OAuth2ClientConfiguration(
        issuer="https://example.com",
        scope=["openid"],
        client_authorization=ClientIdAuthorization(id="client"),
    )
    return OAuth2Client(configuration=config, network=network)


def _build_token(context: TokenContext, refresh_token: str) -> Token:
    return Token(
        access_token="access",
        token_type="Bearer",
        _expires_in=3600,
        _issued_at=1000.0,
        context=context,
        refresh_token=refresh_token,
        scope=["openid"],
        raw_fields={"access_token": "access"},
    )


def test_refresh_token_flow_success() -> None:
    network = DummyNetwork(
        token_body={
            "access_token": "new-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
    )
    client = _build_client(network)
    context = TokenContext(issuer="https://example.com", client_id="client")
    token = _build_token(context, refresh_token="refresh")

    refreshed = asyncio.run(client.refresh(token))

    assert refreshed.access_token == "new-token"
    assert network.last_token_body is not None
    assert network.last_token_body.get("grant_type") == [_REFRESH_GRANT]
    assert network.last_token_body.get("refresh_token") == ["refresh"]
    assert "scope" not in network.last_token_body


def test_refresh_token_flow_applies_scope() -> None:
    network = DummyNetwork(
        token_body={
            "access_token": "new-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
    )
    client = _build_client(network)
    context = TokenContext(issuer="https://example.com", client_id="client")
    token = _build_token(context, refresh_token="refresh")

    refreshed = asyncio.run(client.refresh(token, scope=["openid", "profile"]))

    assert refreshed.access_token == "new-token"
    assert network.last_token_body is not None
    assert network.last_token_body.get("scope") == ["openid profile"]


def test_refresh_token_missing_refresh_token() -> None:
    network = DummyNetwork(
        token_body={
            "access_token": "new-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
    )
    client = _build_client(network)
    context = TokenContext(issuer="https://example.com", client_id="client")
    token = Token(
        access_token="access",
        token_type="Bearer",
        _expires_in=3600,
        _issued_at=1000.0,
        context=context,
    )

    try:
        asyncio.run(client.refresh(token))
    except OAuth2Error as error:
        assert error.error == "missing_refresh_token"
        return
    raise AssertionError("Expected OAuth2Error for missing refresh_token")


def test_refresh_token_coalesces_requests() -> None:
    network = DummyNetwork(
        token_body={
            "access_token": "new-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh-new",
        }
    )
    client = _build_client(network)
    listener = ListenerStub()
    client.listeners.add(listener)
    context = TokenContext(issuer="https://example.com", client_id="client")
    token = _build_token(context, refresh_token="refresh")

    async def run_refresh() -> tuple[Token, Token]:
        results = await asyncio.gather(client.refresh(token), client.refresh(token))
        return results[0], results[1]

    result1, result2 = asyncio.run(run_refresh())

    assert result1 == result2
    assert network.token_requests == 1
    assert listener.will_refresh == 1
    assert listener.did_refresh == 1
    assert listener.last_new is not None


def test_refresh_token_scope_does_not_coalesce() -> None:
    network = DummyNetwork(
        token_body={
            "access_token": "new-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh-new",
        }
    )
    client = _build_client(network)
    context = TokenContext(issuer="https://example.com", client_id="client")
    token = _build_token(context, refresh_token="refresh")

    async def run_refresh() -> tuple[Token, Token]:
        results = await asyncio.gather(
            client.refresh(token, scope=["openid"]),
            client.refresh(token, scope=["openid", "profile"]),
        )
        return results[0], results[1]

    result1, result2 = asyncio.run(run_refresh())

    assert result1 != result2
    assert network.token_requests == 2
