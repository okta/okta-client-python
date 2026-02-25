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

import pytest

from okta_client.authfoundation import (
    GrantedTokenType,
    NetworkInterface,
    OAuth2Client,
    OAuth2ClientConfiguration,
    OAuth2Error,
    RawResponse,
    Token,
)
from okta_client.authfoundation.oauth2.client_authorization import ClientIdAuthorization
from okta_client.oauth2auth import (
    TokenDescriptor,
    TokenExchangeContext,
    TokenExchangeFlow,
    TokenExchangeParameters,
    TokenType,
)
from okta_client.oauth2auth.token_exchange import OAuth2APIRequestCategory

_TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"


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


def test_token_exchange_flow_success() -> None:
    network = DummyNetwork(
        token_body={"access_token": "token", "token_type": "Bearer", "expires_in": 3600},
        grant_types=[_TOKEN_EXCHANGE_GRANT],
    )
    client = _build_client(network)
    flow = TokenExchangeFlow(client=client)

    parameters = TokenExchangeParameters(
        subject=TokenDescriptor(token_type=TokenType.ACCESS_TOKEN, value="subject-token"),
        actor=TokenDescriptor(token_type=TokenType.ACCESS_TOKEN, value="actor-token"),
        audience="api://default",
        resource=["https://resource.example.com"],
    )
    token = asyncio.run(
        flow.start(parameters, context=TokenExchangeContext(scope=["openid", "profile"]))
    )

    assert token.access_token == "token"
    assert network.last_token_body is not None
    assert network.last_token_body.get("grant_type") == [_TOKEN_EXCHANGE_GRANT]
    assert network.last_token_body.get("subject_token") == ["subject-token"]
    assert network.last_token_body.get("subject_token_type") == ["urn:ietf:params:oauth:token-type:access_token"]
    assert network.last_token_body.get("actor_token") == ["actor-token"]
    assert network.last_token_body.get("actor_token_type") == ["urn:ietf:params:oauth:token-type:access_token"]
    assert network.last_token_body.get("audience") == ["api://default"]
    assert network.last_token_body.get("resource") == ["https://resource.example.com"]
    assert network.last_token_body.get("scope") == ["openid profile"]


def test_token_exchange_flow_invalid_response() -> None:
    network = DummyNetwork(
        token_body={"error": "invalid_grant", "error_description": "invalid token"},
        status_code=400,
        grant_types=[_TOKEN_EXCHANGE_GRANT],
    )
    client = _build_client(network)
    flow = TokenExchangeFlow(client=client)

    parameters = {
        "subject": {
            "type": TokenType.ACCESS_TOKEN,
            "value": "subject-token",
        }
    }

    try:
        asyncio.run(flow.start(parameters, context=TokenExchangeContext()))
    except OAuth2Error as error:
        assert error.error == "invalid_grant"
        return
    raise AssertionError("Expected OAuth2Error for invalid grant")


def test_token_exchange_flow_unsupported_server() -> None:
    network = DummyNetwork(
        token_body={"access_token": "token", "token_type": "Bearer", "expires_in": 3600},
        grant_types=["authorization_code"],
    )
    client = _build_client(network)
    flow = TokenExchangeFlow(client=client)

    parameters = {
        "subject": {
            "type": TokenType.ACCESS_TOKEN,
            "value": "subject-token",
        }
    }

    try:
        asyncio.run(flow.start(parameters, context=TokenExchangeContext()))
    except ValueError:
        return
    raise AssertionError("Expected ValueError for unsupported token exchange grant")


def test_token_exchange_parameter_merge_order() -> None:
    network = DummyNetwork(
        token_body={"access_token": "token", "token_type": "Bearer", "expires_in": 3600},
        grant_types=[_TOKEN_EXCHANGE_GRANT],
    )
    client = _build_client(network)
    flow = TokenExchangeFlow(
        client=client,
        additional_parameters={"audience": "flow-audience"},
    )

    context = TokenExchangeContext(
        _additional_parameters={
            "audience": "context-audience",
            "resource": "resource-from-context",
        }
    )

    parameters = {
        "subject": {
            "type": TokenType.ACCESS_TOKEN,
            "value": "subject-token",
        },
        "audience": "param-audience",
        "resource": ["resource-from-params"],
    }

    asyncio.run(flow.start(parameters, context=context))

    assert network.last_token_body is not None
    assert network.last_token_body.get("audience") == ["param-audience"]
    assert network.last_token_body.get("resource") == ["resource-from-params"]


# ===========================================================================
# URN serialization — ID_JAG must not be double-prefixed
# ===========================================================================


class TestIdJagUrnSerialization:
    def test_token_descriptor_urn_not_double_prefixed(self) -> None:
        descriptor = TokenDescriptor(token_type=TokenType.ID_JAG, value="x")
        assert descriptor.token_type_urn() == "urn:ietf:params:oauth:token-type:id-jag"

    def test_context_parameters_requested_token_type(self) -> None:
        ctx = TokenExchangeContext(requested_token_type=TokenType.ID_JAG)
        params = ctx.parameters(OAuth2APIRequestCategory.TOKEN)
        assert params is not None
        assert params["requested_token_type"] == "urn:ietf:params:oauth:token-type:id-jag"

    def test_normal_token_type_gets_prefixed(self) -> None:
        descriptor = TokenDescriptor(token_type=TokenType.ID_TOKEN, value="x")
        assert descriptor.token_type_urn() == "urn:ietf:params:oauth:token-type:id_token"


# ===========================================================================
# TokenExchangeFlow.start() — keyword form
# ===========================================================================


class TestTokenExchangeKeywordForm:
    def _run(self, flow: TokenExchangeFlow, **kwargs) -> Token:
        return asyncio.run(flow.start(**kwargs))

    def test_basic_keyword_form(self) -> None:
        network = DummyNetwork(
            {"access_token": "tok", "token_type": "Bearer", "expires_in": 3600},
            grant_types=[_TOKEN_EXCHANGE_GRANT],
        )
        flow = TokenExchangeFlow(client=_build_client(network))

        token = self._run(
            flow,
            subject_token="my-subject",
            subject_token_type=TokenType.ACCESS_TOKEN,
        )

        assert token.access_token == "tok"
        assert network.last_token_body is not None
        assert network.last_token_body["grant_type"] == [_TOKEN_EXCHANGE_GRANT]
        assert network.last_token_body["subject_token"] == ["my-subject"]
        assert network.last_token_body["subject_token_type"] == [
            "urn:ietf:params:oauth:token-type:access_token"
        ]

    def test_keyword_form_with_scope_and_requested_type(self) -> None:
        network = DummyNetwork(
            {
                "access_token": "jag",
                "token_type": "N_A",
                "expires_in": 300,
                "issued_token_type": "urn:ietf:params:oauth:token-type:id-jag",
            },
            grant_types=[_TOKEN_EXCHANGE_GRANT],
        )
        flow = TokenExchangeFlow(client=_build_client(network))

        token = self._run(
            flow,
            subject_token="id-tok",
            subject_token_type=TokenType.ID_TOKEN,
            audience="https://example.com/oauth2/default",
            scope=["chat.read", "chat.history"],
            requested_token_type=TokenType.ID_JAG,
        )

        assert token.access_token == "jag"
        assert token.token_type is GrantedTokenType.NA
        body = network.last_token_body
        assert body is not None
        assert body["subject_token_type"] == ["urn:ietf:params:oauth:token-type:id_token"]
        assert body["audience"] == ["https://example.com/oauth2/default"]
        assert body["scope"] == ["chat.read chat.history"]
        assert body["requested_token_type"] == ["urn:ietf:params:oauth:token-type:id-jag"]

    def test_keyword_form_with_actor(self) -> None:
        network = DummyNetwork(
            {"access_token": "tok", "token_type": "Bearer", "expires_in": 3600},
            grant_types=[_TOKEN_EXCHANGE_GRANT],
        )
        flow = TokenExchangeFlow(client=_build_client(network))

        self._run(
            flow,
            subject_token="subj",
            subject_token_type=TokenType.ACCESS_TOKEN,
            actor_token="act",
            actor_token_type=TokenType.ID_TOKEN,
        )

        body = network.last_token_body
        assert body is not None
        assert body["actor_token"] == ["act"]
        assert body["actor_token_type"] == ["urn:ietf:params:oauth:token-type:id_token"]

    def test_keyword_form_with_resource(self) -> None:
        network = DummyNetwork(
            {"access_token": "tok", "token_type": "Bearer", "expires_in": 3600},
            grant_types=[_TOKEN_EXCHANGE_GRANT],
        )
        flow = TokenExchangeFlow(client=_build_client(network))

        self._run(
            flow,
            subject_token="subj",
            subject_token_type=TokenType.ACCESS_TOKEN,
            resource=["https://api.example.com"],
        )

        body = network.last_token_body
        assert body is not None
        assert body["resource"] == ["https://api.example.com"]

    def test_keyword_form_missing_subject_raises(self) -> None:
        network = DummyNetwork(
            {"access_token": "tok", "token_type": "Bearer", "expires_in": 3600},
            grant_types=[_TOKEN_EXCHANGE_GRANT],
        )
        flow = TokenExchangeFlow(client=_build_client(network))

        with pytest.raises(TypeError, match="subject_token and subject_token_type are required"):
            self._run(flow, audience="https://example.com")

    def test_keyword_form_missing_subject_type_raises(self) -> None:
        network = DummyNetwork(
            {"access_token": "tok", "token_type": "Bearer", "expires_in": 3600},
            grant_types=[_TOKEN_EXCHANGE_GRANT],
        )
        flow = TokenExchangeFlow(client=_build_client(network))

        with pytest.raises(TypeError, match="subject_token and subject_token_type are required"):
            self._run(flow, subject_token="tok")

    def test_keyword_form_actor_token_without_type_raises(self) -> None:
        network = DummyNetwork(
            {"access_token": "tok", "token_type": "Bearer", "expires_in": 3600},
            grant_types=[_TOKEN_EXCHANGE_GRANT],
        )
        flow = TokenExchangeFlow(client=_build_client(network))

        with pytest.raises(TypeError, match="actor_token and actor_token_type must be provided together"):
            self._run(
                flow,
                subject_token="subj",
                subject_token_type=TokenType.ACCESS_TOKEN,
                actor_token="act",
            )

    def test_keyword_form_actor_type_without_token_raises(self) -> None:
        network = DummyNetwork(
            {"access_token": "tok", "token_type": "Bearer", "expires_in": 3600},
            grant_types=[_TOKEN_EXCHANGE_GRANT],
        )
        flow = TokenExchangeFlow(client=_build_client(network))

        with pytest.raises(TypeError, match="actor_token and actor_token_type must be provided together"):
            self._run(
                flow,
                subject_token="subj",
                subject_token_type=TokenType.ACCESS_TOKEN,
                actor_token_type=TokenType.ID_TOKEN,
            )


class TestTokenExchangeKeywordFormContextMerge:
    def _run(self, flow: TokenExchangeFlow, **kwargs) -> Token:
        return asyncio.run(flow.start(**kwargs))

    def test_context_merge_keyword_takes_precedence(self) -> None:
        network = DummyNetwork(
            {"access_token": "tok", "token_type": "Bearer", "expires_in": 3600},
            grant_types=[_TOKEN_EXCHANGE_GRANT],
        )
        flow = TokenExchangeFlow(client=_build_client(network))

        ctx = TokenExchangeContext(
            scope=["old-scope"],
            requested_token_type=TokenType.ACCESS_TOKEN,
        )
        self._run(
            flow,
            subject_token="subj",
            subject_token_type=TokenType.ACCESS_TOKEN,
            scope=["new-scope"],
            requested_token_type=TokenType.ID_JAG,
            context=ctx,
        )

        body = network.last_token_body
        assert body is not None
        assert body["scope"] == ["new-scope"]
        assert body["requested_token_type"] == ["urn:ietf:params:oauth:token-type:id-jag"]

    def test_context_fallback_when_keywords_omitted(self) -> None:
        network = DummyNetwork(
            {"access_token": "tok", "token_type": "Bearer", "expires_in": 3600},
            grant_types=[_TOKEN_EXCHANGE_GRANT],
        )
        flow = TokenExchangeFlow(client=_build_client(network))

        ctx = TokenExchangeContext(
            scope=["ctx-scope"],
            requested_token_type=TokenType.ACCESS_TOKEN,
        )
        self._run(
            flow,
            subject_token="subj",
            subject_token_type=TokenType.ACCESS_TOKEN,
            context=ctx,
        )

        body = network.last_token_body
        assert body is not None
        assert body["scope"] == ["ctx-scope"]
        assert body["requested_token_type"] == [
            "urn:ietf:params:oauth:token-type:access_token"
        ]


class TestTokenExchangeStructuredFormUnchanged:
    """Verify the existing structured calling convention still works identically."""

    def test_structured_form_with_parameters_object(self) -> None:
        network = DummyNetwork(
            {"access_token": "tok", "token_type": "Bearer", "expires_in": 3600},
            grant_types=[_TOKEN_EXCHANGE_GRANT],
        )
        flow = TokenExchangeFlow(client=_build_client(network))

        params = TokenExchangeParameters(
            subject=TokenDescriptor(token_type=TokenType.ACCESS_TOKEN, value="subj"),
            audience="api://default",
        )
        token = asyncio.run(
            flow.start(params, context=TokenExchangeContext(scope=["openid"]))
        )

        assert token.access_token == "tok"
        body = network.last_token_body
        assert body is not None
        assert body["subject_token"] == ["subj"]
        assert body["audience"] == ["api://default"]
        assert body["scope"] == ["openid"]

    def test_structured_form_with_mapping(self) -> None:
        network = DummyNetwork(
            {"access_token": "tok", "token_type": "Bearer", "expires_in": 3600},
            grant_types=[_TOKEN_EXCHANGE_GRANT],
        )
        flow = TokenExchangeFlow(client=_build_client(network))

        params = {
            "subject": {"type": TokenType.ID_TOKEN, "value": "id-tok"},
            "audience": "api://default",
        }
        token = asyncio.run(flow.start(params))

        assert token.access_token == "tok"
        body = network.last_token_body
        assert body is not None
        assert body["subject_token_type"] == ["urn:ietf:params:oauth:token-type:id_token"]


class TestTokenExchangeIdJagEndToEnd:
    """Full ID-JAG request scenario using the keyword form."""

    def test_id_jag_request(self) -> None:
        network = DummyNetwork(
            {
                "access_token": "eyJhbGciOiJSUzI1NiJ9.e30.sig",
                "token_type": "N_A",
                "expires_in": 300,
                "scope": "chat.read chat.history",
                "issued_token_type": "urn:ietf:params:oauth:token-type:id-jag",
            },
            grant_types=[_TOKEN_EXCHANGE_GRANT],
        )
        flow = TokenExchangeFlow(client=_build_client(network))

        token = asyncio.run(
            flow.start(
                subject_token="user-id-token",
                subject_token_type=TokenType.ID_TOKEN,
                audience="https://example.com/oauth2/default",
                scope=["chat.read", "chat.history"],
                requested_token_type=TokenType.ID_JAG,
            )
        )

        # Verify token fields
        assert token.token_type is GrantedTokenType.NA
        assert token.issued_token_type == "urn:ietf:params:oauth:token-type:id-jag"
        assert token.scope == ["chat.read", "chat.history"]
        assert token.expires_in == 300
        assert token.access_token == "eyJhbGciOiJSUzI1NiJ9.e30.sig"

        # Verify wire request
        body = network.last_token_body
        assert body is not None
        assert body["grant_type"] == [_TOKEN_EXCHANGE_GRANT]
        assert body["subject_token"] == ["user-id-token"]
        assert body["subject_token_type"] == ["urn:ietf:params:oauth:token-type:id_token"]
        assert body["audience"] == ["https://example.com/oauth2/default"]
        assert body["scope"] == ["chat.read chat.history"]
        assert body["requested_token_type"] == ["urn:ietf:params:oauth:token-type:id-jag"]
