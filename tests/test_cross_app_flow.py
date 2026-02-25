# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

"""Unit tests for CrossAppAccessFlow (ID-JAG exchange)."""

import asyncio
import json
from base64 import urlsafe_b64encode
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from okta_client.authfoundation import (
    NetworkInterface,
    OAuth2Client,
    OAuth2ClientConfiguration,
    RawResponse,
    Token,
)
from okta_client.authfoundation.authentication import AuthenticationState
from okta_client.authfoundation.oauth2.client_authorization import (
    ClientAssertionAuthorization,
    ClientIdAuthorization,
    ClientSecretAuthorization,
)
from okta_client.authfoundation.oauth2.jwt_bearer_claims import JWTBearerClaims
from okta_client.oauth2auth.cross_app import (
    CrossAppAccessContext,
    CrossAppAccessFlow,
    CrossAppAccessTarget,
    CrossAppExchangeResult,
)

# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------

_TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
_JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"

# Minimal unsigned JWT with typ=id-jag+jwt so jwt_bearer.py can parse the header.
_ID_JAG_JWT = "eyJ0eXAiOiAiaWQtamFnK2p3dCIsICJhbGciOiAibm9uZSJ9.eyJzdWIiOiAidXNlciJ9."

# Pre-built client assertion JWT with iss/sub (used by Path 2 tests).
_PREBUILT_ASSERTION = (
    urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).rstrip(b"=").decode()
    + "."
    + urlsafe_b64encode(json.dumps({"iss": "client-id", "sub": "client-id", "aud": "https://example.com/v1/token"}).encode()).rstrip(b"=").decode()
    + "."
)

_ID_JAG_RESPONSE = {
    "access_token": _ID_JAG_JWT,
    "token_type": "N_A",
    "expires_in": 300,
    "issued_token_type": "urn:ietf:params:oauth:token-type:id-jag",
}

_ACCESS_TOKEN_RESPONSE = {
    "access_token": "resource-access-token",
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "custom_scope",
}


class DummyNetwork(NetworkInterface):
    """Fake network that serves two issuers: org-level and auth-server."""

    def __init__(
        self,
        *,
        exchange_body: dict[str, Any] = _ID_JAG_RESPONSE,
        bearer_body: dict[str, Any] = _ACCESS_TOKEN_RESPONSE,
        exchange_status: int = 200,
        bearer_status: int = 200,
        exchange_grant_types: list[str] | None = None,
        bearer_grant_types: list[str] | None = None,
    ) -> None:
        self.exchange_body = exchange_body
        self.bearer_body = bearer_body
        self.exchange_status = exchange_status
        self.bearer_status = bearer_status
        self.exchange_grant_types = exchange_grant_types or [_TOKEN_EXCHANGE_GRANT]
        self.bearer_grant_types = bearer_grant_types or [_JWT_BEARER_GRANT]
        self.last_exchange_body: dict[str, list[str]] | None = None
        self.last_bearer_body: dict[str, list[str]] | None = None

    def send(self, request) -> RawResponse:
        parsed = urlsplit(request.url)
        path = parsed.path

        # ---------- Org-level endpoints (token exchange) ----------
        # Only match root-level paths (no /oauth2/ prefix) for the org issuer.
        is_org_level = parsed.netloc == "example.com" and not path.startswith("/oauth2/")
        if is_org_level:
            if path.endswith((".well-known/oauth-authorization-server", ".well-known/openid-configuration")):
                return self._metadata_response(
                    "https://example.com",
                    self.exchange_grant_types,
                )
            if path.endswith("/keys"):
                return RawResponse(status_code=200, headers={}, body=json.dumps({"keys": []}).encode())
            if path.endswith("/token"):
                if request.body:
                    self.last_exchange_body = parse_qs(request.body.decode())
                return RawResponse(
                    status_code=self.exchange_status,
                    headers={},
                    body=json.dumps(self.exchange_body).encode(),
                )

        # ---------- Resource auth-server endpoints (JWT bearer) ----------
        if path.endswith((".well-known/oauth-authorization-server", ".well-known/openid-configuration")):
            issuer = f"{parsed.scheme}://{parsed.netloc}/oauth2/my-auth-server"
            return self._metadata_response(issuer, self.bearer_grant_types)
        if path.endswith("/keys"):
            return RawResponse(status_code=200, headers={}, body=json.dumps({"keys": []}).encode())
        if path.endswith("/token"):
            if request.body:
                self.last_bearer_body = parse_qs(request.body.decode())
            return RawResponse(
                status_code=self.bearer_status,
                headers={},
                body=json.dumps(self.bearer_body).encode(),
            )

        pytest.fail(f"Unexpected request: {request.url}")
        return RawResponse(status_code=500, headers={}, body=b"")

    @staticmethod
    def _metadata_response(issuer: str, grant_types: list[str]) -> RawResponse:
        body = {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/v1/authorize",
            "token_endpoint": f"{issuer}/v1/token",
            "jwks_uri": f"{issuer}/v1/keys",
            "grant_types_supported": grant_types,
        }
        return RawResponse(status_code=200, headers={}, body=json.dumps(body).encode())


def _build_client(network: NetworkInterface) -> OAuth2Client:
    config = OAuth2ClientConfiguration(
        issuer="https://example.com",
        scope=["openid"],
        client_authorization=ClientIdAuthorization(id="client"),
    )
    return OAuth2Client(configuration=config, network=network)


class DummyKeyProvider:
    """Stub :class:`KeyProvider` that returns a fixed string for every sign call."""

    algorithm: str = "none"
    key_id: str | None = None

    def sign_jwt(self, claims: Any, headers: Any = None) -> str:
        return "dummy-signed-assertion"


def _build_assertion_client(
    network: NetworkInterface,
    *,
    assertion: str | None = None,
    assertion_claims: JWTBearerClaims | None = None,
    key_provider: Any | None = None,
) -> OAuth2Client:
    """Build an :class:`OAuth2Client` that uses :class:`ClientAssertionAuthorization`."""
    config = OAuth2ClientConfiguration(
        issuer="https://example.com",
        scope=["openid"],
        client_authorization=ClientAssertionAuthorization(
            assertion=assertion,
            assertion_claims=assertion_claims,
            key_provider=key_provider,
        ),
    )
    return OAuth2Client(configuration=config, network=network)


def _build_secret_client(network: NetworkInterface) -> OAuth2Client:
    """Build an :class:`OAuth2Client` with :class:`ClientSecretAuthorization`."""
    config = OAuth2ClientConfiguration(
        issuer="https://example.com",
        scope=["openid"],
        client_authorization=ClientSecretAuthorization(
            id="client",
            secret="secret",
        ),
    )
    return OAuth2Client(configuration=config, network=network)


# ---------------------------------------------------------------------------
# Listener spy
# ---------------------------------------------------------------------------


class ListenerSpy:
    """Records cross-app lifecycle callbacks."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.id_jag_token: Token | None = None
        self.access_token: Token | None = None

    def authentication_started(self, flow: Any) -> None:
        pass

    def authentication_updated(self, flow: Any, context: Any) -> None:
        pass

    def authentication_completed(self, flow: Any, result: Any) -> None:
        pass

    def authentication_failed(self, flow: Any, error: Exception) -> None:
        pass

    def will_exchange_token_for_id_jag(self, flow: Any, subject_token_type: str) -> None:
        self.calls.append(f"will_exchange:{subject_token_type}")

    def did_exchange_token_for_id_jag(self, flow: Any, id_jag_token: Token) -> None:
        self.calls.append("did_exchange_id_jag")
        self.id_jag_token = id_jag_token

    def will_exchange_id_jag_for_access_token(self, flow: Any, id_jag_token: Token) -> None:
        self.calls.append("will_exchange_id_jag_for_access")

    def did_exchange_id_jag_for_access_token(self, flow: Any, access_token: Token) -> None:
        self.calls.append("did_exchange_access")
        self.access_token = access_token


# ---------------------------------------------------------------------------
# Tests - start (Step 1: token exchange → ID-JAG)
# ---------------------------------------------------------------------------


def test_start_exchanges_id_token_for_id_jag() -> None:
    """start() should exchange the subject token for an ID-JAG."""
    network = DummyNetwork()
    client = _build_client(network)
    flow = CrossAppAccessFlow(
        client=client,
        target=CrossAppAccessTarget(issuer="https://example.com/oauth2/my-auth-server"),
    )

    result = asyncio.run(
        flow.start(
            token="my-id-token",
            audience="https://api.example.com",
        )
    )

    # start() returns CrossAppExchangeResult; ID-JAG is in context
    assert isinstance(result, CrossAppExchangeResult)
    assert result.resume_assertion_claims is None  # Path 3 (ClientIdAuthorization)

    assert flow.context is not None
    id_jag = flow.context.id_jag_token
    assert id_jag is not None
    assert id_jag.access_token == _ID_JAG_JWT
    assert id_jag.issued_token_type == "urn:ietf:params:oauth:token-type:id-jag"

    # Verify the token exchange body
    body = network.last_exchange_body
    assert body is not None
    assert body["grant_type"] == ["urn:ietf:params:oauth:grant-type:token-exchange"]
    assert body["subject_token"] == ["my-id-token"]
    assert body["subject_token_type"] == ["urn:ietf:params:oauth:token-type:id_token"]
    assert body["requested_token_type"] == ["urn:ietf:params:oauth:token-type:id-jag"]
    assert body["audience"] == ["https://api.example.com"]


def test_start_exchanges_access_token_for_id_jag() -> None:
    """start() with token_type='access_token' uses the correct subject_token_type."""
    network = DummyNetwork()
    client = _build_client(network)
    flow = CrossAppAccessFlow(
        client=client,
        target=CrossAppAccessTarget(issuer="https://example.com/oauth2/my-auth-server"),
    )

    asyncio.run(
        flow.start(
            token="my-access-token",
            audience="https://api.example.com",
            token_type="access_token",
        )
    )

    body = network.last_exchange_body
    assert body is not None
    assert body["subject_token_type"] == ["urn:ietf:params:oauth:token-type:access_token"]


def test_start_audience_defaults_to_target_issuer() -> None:
    """When audience is omitted, start() should use target.issuer."""
    network = DummyNetwork()
    client = _build_client(network)
    target = CrossAppAccessTarget(issuer="https://example.com/oauth2/my-auth-server")
    flow = CrossAppAccessFlow(client=client, target=target)

    asyncio.run(flow.start(token="my-id-token"))

    body = network.last_exchange_body
    assert body is not None
    assert body["audience"] == [target.issuer]


def test_start_with_scope() -> None:
    """start() forwards optional scopes to the token exchange."""
    network = DummyNetwork()
    client = _build_client(network)
    flow = CrossAppAccessFlow(
        client=client,
        target=CrossAppAccessTarget(issuer="https://example.com/oauth2/my-auth-server"),
    )

    asyncio.run(
        flow.start(
            token="tok",
            audience="https://api.example.com",
            scope=["openid", "custom_scope"],
        )
    )

    body = network.last_exchange_body
    assert body is not None
    assert body["scope"] == ["openid custom_scope"]


def test_start_stores_id_jag_in_context() -> None:
    """start() stores the ID-JAG token and exchange result in the flow context."""
    network = DummyNetwork()
    client = _build_client(network)
    flow = CrossAppAccessFlow(
        client=client,
        target=CrossAppAccessTarget(issuer="https://example.com/oauth2/my-auth-server"),
    )

    asyncio.run(flow.start(token="tok", audience="https://api.example.com"))

    ctx = flow.context
    assert ctx is not None
    assert ctx.id_jag_token is not None
    assert ctx.id_jag_token.access_token == _ID_JAG_JWT
    assert ctx.exchange_result is not None
    assert isinstance(ctx.exchange_result, CrossAppExchangeResult)


# ---------------------------------------------------------------------------
# Tests - resume (Step 2: ID-JAG → resource access token)
# ---------------------------------------------------------------------------


def test_resume_with_issuer() -> None:
    """resume() exchanges the ID-JAG for an access token via JWT bearer."""
    network = DummyNetwork()
    client = _build_client(network)
    flow = CrossAppAccessFlow(
        client=client,
        target=CrossAppAccessTarget(issuer="https://example.com/oauth2/my-auth-server"),
    )

    asyncio.run(flow.start(token="tok", audience="https://api.example.com"))
    access_token = asyncio.run(flow.resume())

    assert access_token.access_token == "resource-access-token"
    assert access_token.token_type == "Bearer"

    # Verify the JWT bearer body
    body = network.last_bearer_body
    assert body is not None
    assert body["grant_type"] == ["urn:ietf:params:oauth:grant-type:jwt-bearer"]
    assert body["assertion"] == [_ID_JAG_JWT]


def test_resume_with_authorization_server_id() -> None:
    """resume() derives the issuer from the authorization_server_id."""
    network = DummyNetwork()
    client = _build_client(network)
    flow = CrossAppAccessFlow(client=client, target_authorization_server_id="my-auth-server")

    asyncio.run(flow.start(token="tok", audience="https://api.example.com"))
    access_token = asyncio.run(flow.resume())

    assert access_token.access_token == "resource-access-token"


def test_resume_without_start_raises() -> None:
    """resume() raises RuntimeError when no ID-JAG is available."""
    network = DummyNetwork()
    client = _build_client(network)
    flow = CrossAppAccessFlow(
        client=client,
        target=CrossAppAccessTarget(issuer="https://example.com/oauth2/my-auth-server"),
    )

    with pytest.raises(RuntimeError, match="No ID-JAG token available"):
        asyncio.run(flow.resume())


def test_requires_issuer_or_auth_server_id() -> None:
    """Constructor raises ValueError when neither issuer nor authorization_server_id is given."""
    network = DummyNetwork()
    client = _build_client(network)

    with pytest.raises(ValueError, match="Either 'target' or 'target_authorization_server_id'"):
        CrossAppAccessFlow(client=client)


# ---------------------------------------------------------------------------
# Tests - issuer resolution
# ---------------------------------------------------------------------------


def test_resolve_target_prefers_explicit_target() -> None:
    """When both target and target_authorization_server_id are given, target wins."""
    network = DummyNetwork()
    client = _build_client(network)
    flow = CrossAppAccessFlow(
        client=client,
        target=CrossAppAccessTarget(issuer="https://example.com/oauth2/my-auth-server"),
    )

    result = flow._resolve_target(
        target=CrossAppAccessTarget(issuer="https://explicit.example.com/oauth2/custom"),
        target_authorization_server_id="ignored",
    )
    assert result.issuer == "https://explicit.example.com/oauth2/custom"


def test_resolve_target_from_auth_server_id() -> None:
    """target_authorization_server_id is composed from the client's base URL."""
    network = DummyNetwork()
    client = _build_client(network)
    flow = CrossAppAccessFlow(
        client=client,
        target=CrossAppAccessTarget(issuer="https://example.com/oauth2/my-auth-server"),
    )

    result = flow._resolve_target(target=None, target_authorization_server_id="default")
    assert result.issuer == "https://example.com/oauth2/default"


# ---------------------------------------------------------------------------
# Tests - listener lifecycle
# ---------------------------------------------------------------------------


def test_listener_lifecycle_start_and_resume() -> None:
    """CrossAppAccessFlowListener receives all four lifecycle calls."""
    network = DummyNetwork()
    client = _build_client(network)
    flow = CrossAppAccessFlow(
        client=client,
        target=CrossAppAccessTarget(issuer="https://example.com/oauth2/my-auth-server"),
    )

    spy = ListenerSpy()
    flow.listeners.add(spy)

    asyncio.run(flow.start(token="tok", audience="https://api.example.com"))
    assert spy.calls == ["will_exchange:id_token", "did_exchange_id_jag"]
    assert spy.id_jag_token is not None
    assert spy.id_jag_token.access_token == _ID_JAG_JWT

    flow.reset()
    # Manually set context with the ID-JAG so resume can proceed.
    # exchange_result=None means no assertion claims needed (Path 3).
    flow._context = CrossAppAccessContext(id_jag_token=spy.id_jag_token)
    flow._state = AuthenticationState.AUTHENTICATING

    asyncio.run(flow.resume())
    assert spy.calls == [
        "will_exchange:id_token",
        "did_exchange_id_jag",
        "will_exchange_id_jag_for_access",
        "did_exchange_access",
    ]
    assert spy.access_token is not None
    assert spy.access_token.access_token == "resource-access-token"


# ---------------------------------------------------------------------------
# Tests - sub-flow accessibility
# ---------------------------------------------------------------------------


def test_sub_flows_are_accessible() -> None:
    """token_exchange_flow and jwt_bearer_flow properties expose the sub-flows."""
    network = DummyNetwork()
    client = _build_client(network)
    flow = CrossAppAccessFlow(
        client=client,
        target=CrossAppAccessTarget(issuer="https://example.com/oauth2/my-auth-server"),
    )

    assert isinstance(flow.token_exchange_flow, object)
    assert isinstance(flow.jwt_bearer_flow, object)
    assert flow.token_exchange_flow is flow._token_exchange_flow
    assert flow.jwt_bearer_flow is flow._jwt_bearer_flow


# ---------------------------------------------------------------------------
# Tests - state transitions
# ---------------------------------------------------------------------------


def test_flow_state_after_start() -> None:
    """After start() the outer flow is still AUTHENTICATING (ready for resume)."""
    network = DummyNetwork()
    client = _build_client(network)
    flow = CrossAppAccessFlow(
        client=client,
        target=CrossAppAccessTarget(issuer="https://example.com/oauth2/my-auth-server"),
    )

    assert flow.state == AuthenticationState.IDLE
    asyncio.run(flow.start(token="tok", audience="https://api.example.com"))
    # start() does NOT call _complete — only resume() completes the outer flow
    assert flow.state == AuthenticationState.AUTHENTICATING


def test_flow_state_after_full_exchange() -> None:
    """After start() + resume() the outer flow is COMPLETED."""
    network = DummyNetwork()
    client = _build_client(network)
    flow = CrossAppAccessFlow(
        client=client,
        target=CrossAppAccessTarget(issuer="https://example.com/oauth2/my-auth-server"),
    )

    asyncio.run(flow.start(token="tok", audience="https://api.example.com"))
    asyncio.run(flow.resume())
    assert flow.state == AuthenticationState.COMPLETED


def test_reset_clears_state() -> None:
    """reset() returns the flow and sub-flows to idle."""
    network = DummyNetwork()
    client = _build_client(network)
    flow = CrossAppAccessFlow(
        client=client,
        target=CrossAppAccessTarget(issuer="https://example.com/oauth2/my-auth-server"),
    )

    asyncio.run(flow.start(token="tok", audience="https://api.example.com"))
    flow.reset()

    assert flow.state == AuthenticationState.IDLE
    assert flow.context is None
    assert flow.token_exchange_flow.state == AuthenticationState.IDLE
    assert flow.jwt_bearer_flow.state == AuthenticationState.IDLE


# ---------------------------------------------------------------------------
# Tests - auth path resolution
# ---------------------------------------------------------------------------


class TestPath1AutoSign:
    """Path 1: ClientAssertionAuthorization with assertion_claims + key_provider.

    The flow clones the claims with the target token_endpoint as audience,
    builds a new ClientAssertionAuthorization, and sets it on the resource
    client.  ``resume()`` works with no extra arguments.
    """

    _TARGET = CrossAppAccessTarget(
        issuer="https://example.com/oauth2/my-auth-server"
    )

    def _make_flow(self, network: DummyNetwork) -> CrossAppAccessFlow:
        claims = JWTBearerClaims(
            issuer="client-id",
            subject="client-id",
            audience="https://example.com/v1/token",  # org-level audience
            expires_in=300.0,
        )
        client = _build_assertion_client(
            network,
            assertion_claims=claims,
            key_provider=DummyKeyProvider(),
        )
        return CrossAppAccessFlow(client=client, target=self._TARGET)

    def test_start_returns_no_resume_claims(self) -> None:
        """resume_assertion_claims should be None (auto-sign)."""
        network = DummyNetwork()
        flow = self._make_flow(network)
        result = asyncio.run(flow.start(token="tok", audience="aud"))
        assert result.resume_assertion_claims is None

    def test_resume_works_without_args(self) -> None:
        """resume() succeeds with no arguments when auto-sign is available."""
        network = DummyNetwork()
        flow = self._make_flow(network)
        asyncio.run(flow.start(token="tok", audience="aud"))
        access_token = asyncio.run(flow.resume())
        assert access_token.access_token == "resource-access-token"

    def test_resource_client_auth_has_target_audience(self) -> None:
        """The resource client's assertion claims should use the target token endpoint."""
        network = DummyNetwork()
        flow = self._make_flow(network)
        asyncio.run(flow.start(token="tok", audience="aud"))

        resource_auth = flow.jwt_bearer_flow.client.configuration.client_authorization
        assert isinstance(resource_auth, ClientAssertionAuthorization)
        assert resource_auth.assertion_claims is not None
        assert resource_auth.assertion_claims.audience == (
            "https://example.com/oauth2/my-auth-server/v1/token"
        )
        # Issuer should be preserved from original claims
        assert resource_auth.assertion_claims.issuer == "client-id"


class TestPath2PrebuiltAssertion:
    """Path 2: ClientAssertionAuthorization with pre-built assertion (no key_provider).

    ``start()`` returns ``resume_assertion_claims`` telling the developer
    which claims to sign.  ``resume()`` requires either ``client_assertion``
    or ``key_provider``.
    """

    _TARGET = CrossAppAccessTarget(
        issuer="https://example.com/oauth2/my-auth-server"
    )

    def _make_flow(self, network: DummyNetwork) -> CrossAppAccessFlow:
        client = _build_assertion_client(network, assertion=_PREBUILT_ASSERTION)
        return CrossAppAccessFlow(client=client, target=self._TARGET)

    def test_start_returns_resume_claims(self) -> None:
        """resume_assertion_claims should be populated with the target audience."""
        network = DummyNetwork()
        flow = self._make_flow(network)
        result = asyncio.run(flow.start(token="tok", audience="aud"))

        assert result.resume_assertion_claims is not None
        assert result.resume_assertion_claims.audience == (
            "https://example.com/oauth2/my-auth-server/v1/token"
        )

    def test_resume_with_client_assertion(self) -> None:
        """resume(client_assertion=...) sets the assertion on the resource client."""
        network = DummyNetwork()
        flow = self._make_flow(network)
        asyncio.run(flow.start(token="tok", audience="aud"))
        access_token = asyncio.run(
            flow.resume(client_assertion="developer-signed-jwt")
        )
        assert access_token.access_token == "resource-access-token"

    def test_resume_with_key_provider(self) -> None:
        """resume(key_provider=...) signs the claims automatically."""
        network = DummyNetwork()
        flow = self._make_flow(network)
        asyncio.run(flow.start(token="tok", audience="aud"))
        access_token = asyncio.run(flow.resume(key_provider=DummyKeyProvider()))
        assert access_token.access_token == "resource-access-token"

    def test_resume_without_auth_raises(self) -> None:
        """resume() with no assertion or key_provider raises ValueError."""
        network = DummyNetwork()
        flow = self._make_flow(network)
        asyncio.run(flow.start(token="tok", audience="aud"))
        with pytest.raises(ValueError, match="client assertion"):
            asyncio.run(flow.resume())


class TestPath3NonAssertionAuth:
    """Path 3: Non-assertion auth (ClientIdAuthorization, ClientSecretAuthorization).

    The flow copies the auth to the resource client as-is.
    ``resume()`` works with no arguments.
    """

    _TARGET = CrossAppAccessTarget(
        issuer="https://example.com/oauth2/my-auth-server"
    )

    def test_client_id_auth_resume_claims_none(self) -> None:
        """ClientIdAuthorization → resume_assertion_claims is None."""
        network = DummyNetwork()
        client = _build_client(network)
        flow = CrossAppAccessFlow(client=client, target=self._TARGET)
        result = asyncio.run(flow.start(token="tok", audience="aud"))
        assert result.resume_assertion_claims is None

    def test_client_secret_auth_resume_claims_none(self) -> None:
        """ClientSecretAuthorization → resume_assertion_claims is None."""
        network = DummyNetwork()
        client = _build_secret_client(network)
        flow = CrossAppAccessFlow(client=client, target=self._TARGET)
        result = asyncio.run(flow.start(token="tok", audience="aud"))
        assert result.resume_assertion_claims is None

    def test_client_secret_auth_resume_works(self) -> None:
        """resume() succeeds for ClientSecretAuthorization without extra args."""
        network = DummyNetwork()
        client = _build_secret_client(network)
        flow = CrossAppAccessFlow(client=client, target=self._TARGET)
        asyncio.run(flow.start(token="tok", audience="aud"))
        access_token = asyncio.run(flow.resume())
        assert access_token.access_token == "resource-access-token"
