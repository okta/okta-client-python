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
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest

from okta_client.authfoundation import (
    LocalKeyProvider,
    NetworkInterface,
    OAuth2Client,
    OAuth2ClientConfiguration,
    OAuth2Error,
    RawResponse,
    StandardAuthenticationContext,
    get_key_provider,
    set_key_provider,
)
from okta_client.authfoundation.oauth2.client_authorization import ClientIdAuthorization
from okta_client.oauth2auth import (
    JWTBearerClaims,
    JWTBearerFlow,
)
from tests.utils import KeyProviderStub

_JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
_RESOURCES = Path(__file__).parent / "resources"
_PRIVATE_KEY = (_RESOURCES / "test_key.pem").read_text()
_PUBLIC_KEY = (_RESOURCES / "test_key.pub").read_text()

class DummyNetwork(NetworkInterface):
    def __init__(self, token_body: dict, status_code: int = 200, grant_types=None) -> None:
        self.token_body = token_body
        self.status_code = status_code
        self.grant_types = grant_types
        self.last_token_body: dict[str, list[str]] | None = None

    def send(self, request) -> RawResponse:
        path = urlsplit(request.url).path
        if path.endswith(".well-known/oauth-authorization-server") or path.endswith(".well-known/openid-configuration"):
            body = {
                "issuer": "https://example.com",
                "authorization_endpoint": "https://example.com/auth",
                "token_endpoint": "https://example.com/token",
                "jwks_uri": "https://example.com/keys",
                "grant_types_supported": self.grant_types,
            }
            return RawResponse(status_code=200, headers={}, body=json.dumps(body).encode("utf-8"))
        elif path.endswith("/keys"):
            return RawResponse(status_code=200, headers={}, body=json.dumps({"keys": []}).encode("utf-8"))
        elif path.endswith("/token"):
            if request.body:
                self.last_token_body = parse_qs(request.body.decode("utf-8"))
            return RawResponse(status_code=self.status_code, headers={}, body=json.dumps(self.token_body).encode("utf-8"))
        else:
            pytest.fail(f"Unexpected request to {request.url}")
            return RawResponse(status_code=200, headers={}, body=b"{}")


def _build_client(network: NetworkInterface) -> OAuth2Client:
    config = OAuth2ClientConfiguration(
        issuer="https://example.com",
        scope=["openid"],
        client_authorization=ClientIdAuthorization(id="client"),
    )
    return OAuth2Client(configuration=config, network=network)


def _sign_assertion(payload: dict) -> str:
    """Sign a JWT assertion using the test RSA private key."""
    import time

    payload.setdefault("iat", int(time.time()))
    return jwt.encode(payload, _PRIVATE_KEY, algorithm="RS256")


def test_jwt_bearer_flow_with_prebuilt_assertion() -> None:
    network = DummyNetwork(
        token_body={"access_token": "token", "token_type": "Bearer", "expires_in": 3600},
        grant_types=[_JWT_BEARER_GRANT],
    )
    client = _build_client(network)
    flow = JWTBearerFlow(client=client)

    assertion = _sign_assertion({
        "iss": "client",
        "sub": "client",
        "aud": "https://example.com/token",
        "exp": 9999999999,
    })

    token = asyncio.run(flow.start(assertion=assertion))

    assert token.access_token == "token"
    assert network.last_token_body is not None
    assert network.last_token_body.get("grant_type") == [_JWT_BEARER_GRANT]
    assert network.last_token_body.get("assertion") == [assertion]


def test_jwt_bearer_flow_with_generated_assertion() -> None:
    previous = get_key_provider()
    try:
        provider = LocalKeyProvider(key=_PRIVATE_KEY, algorithm="RS256")
        set_key_provider(provider)
        network = DummyNetwork(
            token_body={"access_token": "token", "token_type": "Bearer", "expires_in": 3600},
            grant_types=[_JWT_BEARER_GRANT],
        )
        client = _build_client(network)
        flow = JWTBearerFlow(client=client)

        claims = JWTBearerClaims(
            issuer="client",
            subject="client",
            audience="https://example.com/token",
            expires_in=300,
        )

        token = asyncio.run(flow.start(assertion_claims=claims))

        assert token.access_token == "token"
        assert network.last_token_body is not None
        assertion = network.last_token_body.get("assertion", [None])[0]
        assert assertion is not None
        decoded = jwt.decode(assertion, _PUBLIC_KEY, algorithms=["RS256"], options={"verify_aud": False})
        assert decoded["iss"] == "client"
    finally:
        set_key_provider(previous)


def test_jwt_bearer_flow_invalid_response() -> None:
    network = DummyNetwork(
        token_body={"error": "invalid_grant", "error_description": "invalid token"},
        status_code=400,
        grant_types=[_JWT_BEARER_GRANT],
    )
    client = _build_client(network)
    flow = JWTBearerFlow(client=client)

    assertion = _sign_assertion({
        "iss": "client",
        "sub": "client",
        "aud": "https://example.com/token",
        "exp": 9999999999,
    })

    try:
        asyncio.run(flow.start(assertion=assertion))
    except OAuth2Error as error:
        assert error.error == "invalid_grant"
        return
    raise AssertionError("Expected OAuth2Error for invalid grant")


def test_jwt_bearer_flow_unsupported_server() -> None:
    network = DummyNetwork(
        token_body={"access_token": "token", "token_type": "Bearer", "expires_in": 3600},
        grant_types=["authorization_code"],
    )
    client = _build_client(network)
    flow = JWTBearerFlow(client=client)

    assertion = _sign_assertion({
        "iss": "client",
        "sub": "client",
        "aud": "https://example.com/token",
        "exp": 9999999999,
    })

    try:
        asyncio.run(flow.start(assertion=assertion))
    except ValueError:
        return
    raise AssertionError("Expected ValueError for unsupported JWT bearer grant")


def test_jwt_bearer_flow_parameter_merge_order() -> None:
    network = DummyNetwork(
        token_body={"access_token": "token", "token_type": "Bearer", "expires_in": 3600},
        grant_types=[_JWT_BEARER_GRANT],
    )
    client = _build_client(network)
    flow = JWTBearerFlow(
        client=client,
        additional_parameters={"scope": "flow-scope"},
    )
    context = StandardAuthenticationContext(
        _additional_parameters={"scope": "context-scope"},
    )

    assertion = _sign_assertion({
        "iss": "client",
        "sub": "client",
        "aud": "https://example.com/token",
        "exp": 9999999999,
    })

    asyncio.run(flow.start(assertion=assertion, context=context))

    assert network.last_token_body is not None
    assert network.last_token_body.get("scope") == ["context-scope"]


def test_jwt_bearer_flow_rejects_conflicting_inputs() -> None:
    network = DummyNetwork(
        token_body={"access_token": "token", "token_type": "Bearer", "expires_in": 3600},
        grant_types=[_JWT_BEARER_GRANT],
    )
    client = _build_client(network)
    flow = JWTBearerFlow(client=client)

    claims = JWTBearerClaims(
        issuer="client",
        subject="client",
        audience="https://example.com/token",
        expires_in=300,
    )

    try:
        asyncio.run(flow.start(assertion="jwt", assertion_claims=claims))
    except ValueError:
        return
    raise AssertionError("Expected ValueError for conflicting assertion inputs")


def test_jwt_bearer_flow_requires_assertion_or_claims() -> None:
    network = DummyNetwork(
        token_body={"access_token": "token", "token_type": "Bearer", "expires_in": 3600},
        grant_types=[_JWT_BEARER_GRANT],
    )
    client = _build_client(network)
    flow = JWTBearerFlow(client=client)

    try:
        asyncio.run(flow.start())
    except ValueError:
        return
    raise AssertionError("Expected ValueError when assertion and claims are missing")


def test_jwt_bearer_flow_uses_custom_key_provider() -> None:
    network = DummyNetwork(
        token_body={"access_token": "token", "token_type": "Bearer", "expires_in": 3600},
        grant_types=[_JWT_BEARER_GRANT],
    )
    client = _build_client(network)
    flow = JWTBearerFlow(client=client)

    claims = JWTBearerClaims(
        issuer="client",
        subject="client",
        audience="https://example.com/token",
        expires_in=300,
    )

    asyncio.run(flow.start(assertion_claims=claims, key_provider=KeyProviderStub()))

    assert network.last_token_body is not None
    assertion = network.last_token_body.get("assertion", [None])[0]
    assert assertion is not None
    decoded = jwt.decode(assertion, _PUBLIC_KEY, algorithms=["RS256"], options={"verify_aud": False})
    assert decoded["iss"] == "client"
