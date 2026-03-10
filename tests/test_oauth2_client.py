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
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from okta_client.authfoundation import HTTPRequest, NetworkInterface, OAuth2Client, OAuth2ClientConfiguration, RawResponse
from okta_client.authfoundation.networking import APIContentType, APIRequestMethod, DefaultNetworkInterface, RequestValue
from okta_client.authfoundation.oauth2 import NullIDTokenValidatorContext
from okta_client.authfoundation.oauth2.client_authorization import (
    ClientAssertionAuthorization,
    ClientIdAuthorization,
    ClientSecretAuthorization,
)
from okta_client.authfoundation.oauth2.models import OAuthAuthorizationServer, OpenIdConfiguration
from okta_client.authfoundation.oauth2.parameters import OAuth2APIRequestCategory
from okta_client.authfoundation.oauth2.request_protocols import IDTokenValidatorContext, OAuth2TokenRequest
from okta_client.authfoundation.token import Token, TokenContext


class DummyNetwork(NetworkInterface):
    def __init__(self) -> None:
        self.last_request: HTTPRequest | None = None
        self.openid_requests = 0

    def send(self, request: HTTPRequest) -> RawResponse:
        self.last_request = request
        path = urlsplit(request.url).path
        if path.endswith(".well-known/openid-configuration"):
            self.openid_requests += 1
            body = json.dumps(
                {
                    "issuer": "https://example.com",
                    "authorization_endpoint": "https://example.com/auth",
                    "token_endpoint": "https://example.com/token",
                    "revocation_endpoint": "https://example.com/revoke",
                    "introspection_endpoint": "https://example.com/introspect",
                    "userinfo_endpoint": "https://example.com/userinfo",
                    "jwks_uri": "https://example.com/keys",
                }
            ).encode("utf-8")
            return RawResponse(status_code=200, headers={}, body=body)
        if "/keys" in request.url:
            body = json.dumps({"keys": [{"kty": "RSA", "kid": "1"}]}).encode("utf-8")
            return RawResponse(status_code=200, headers={}, body=body)
        if request.url.endswith("/introspect"):
            body = json.dumps({"active": True}).encode("utf-8")
            return RawResponse(status_code=200, headers={}, body=body)
        if request.url.endswith("/userinfo"):
            body = json.dumps({"sub": "user"}).encode("utf-8")
            return RawResponse(status_code=200, headers={}, body=body)
        return RawResponse(status_code=200, headers={}, body=b"{}")


def test_oauth2_client_requests() -> None:
    network = DummyNetwork()
    oauth_config = OAuth2ClientConfiguration(
        issuer="https://example.com",
        scope=["openid"],
        client_authorization=ClientIdAuthorization(id="client"),
    )
    client = OAuth2Client(configuration=oauth_config, network=network)

    discovery = asyncio.run(client.fetch_openid_configuration())
    assert discovery.jwks_uri.endswith("/keys")

    jwks = asyncio.run(client.fetch_jwks())
    assert jwks.keys[0].data["kid"] == "1"

    token_info = asyncio.run(client.introspect(token="token"))
    assert token_info.active is True

    token = Token(
        access_token="token",
        token_type="Bearer",
        _expires_in=3600,
        context=TokenContext(issuer="https://example.com", client_id="client"),
    )
    userinfo = asyncio.run(client.userinfo(token=token))
    assert userinfo.claims["sub"] == "user"

    asyncio.run(client.revoke(token="token"))


def test_openid_configuration_cache_policy() -> None:
    network = DummyNetwork()
    oauth_config = OAuth2ClientConfiguration(
        issuer="https://example.com",
        scope=["openid"],
        client_authorization=ClientIdAuthorization(id="client"),
        metadata_cache_ttl=60.0,
    )
    current_time = [1000.0]

    def time_provider() -> float:
        return current_time[0]

    client = OAuth2Client(configuration=oauth_config, network=network, time_provider=time_provider)

    discovery_1 = asyncio.run(client.fetch_openid_configuration())
    discovery_2 = asyncio.run(client.fetch_openid_configuration())

    assert discovery_1.authorization_endpoint == discovery_2.authorization_endpoint
    assert discovery_1["authorization_endpoint"].endswith("/auth")
    assert network.openid_requests == 1

    current_time[0] += 120.0
    asyncio.run(client.fetch_openid_configuration())
    assert network.openid_requests == 2


def test_openid_configuration_validates_required_fields() -> None:
    from okta_client.authfoundation.oauth2 import OpenIdConfiguration
    try:
        OpenIdConfiguration.from_json({"jwks_uri": "https://example.com/keys"})
    except ValueError:
        return
    raise AssertionError("Expected ValueError when required fields are missing")


class DiscoveryIssuerNetwork(NetworkInterface):
    def __init__(self, openid_issuer: str, oauth_issuer: str) -> None:
        self._openid_issuer = openid_issuer
        self._oauth_issuer = oauth_issuer

    def send(self, request: HTTPRequest) -> RawResponse:
        path = urlsplit(request.url).path
        if path.endswith(".well-known/openid-configuration"):
            body = json.dumps(
                {
                    "issuer": self._openid_issuer,
                    "authorization_endpoint": "https://example.com/auth",
                    "token_endpoint": "https://example.com/token",
                    "jwks_uri": "https://example.com/keys",
                }
            ).encode("utf-8")
            return RawResponse(status_code=200, headers={}, body=body)
        if path.endswith(".well-known/oauth-authorization-server"):
            body = json.dumps(
                {
                    "issuer": self._oauth_issuer,
                    "authorization_endpoint": "https://example.com/auth",
                    "token_endpoint": "https://example.com/token",
                    "jwks_uri": "https://example.com/keys",
                }
            ).encode("utf-8")
            return RawResponse(status_code=200, headers={}, body=body)
        return RawResponse(status_code=200, headers={}, body=b"{}")


def test_openid_configuration_rejects_mismatched_issuer() -> None:
    network = DiscoveryIssuerNetwork(
        openid_issuer="https://attacker.example.com",
        oauth_issuer="https://example.com",
    )
    oauth_config = OAuth2ClientConfiguration(
        issuer="https://example.com",
        scope=["openid"],
        client_authorization=ClientIdAuthorization(id="client"),
    )
    client = OAuth2Client(configuration=oauth_config, network=network)

    try:
        asyncio.run(client.fetch_openid_configuration())
    except ValueError as exc:
        assert "expected" in str(exc)
        assert "attacker" in str(exc)
        return
    raise AssertionError("Expected ValueError for mismatched OpenID issuer")


def test_oauth_server_metadata_rejects_mismatched_issuer() -> None:
    network = DiscoveryIssuerNetwork(
        openid_issuer="https://example.com",
        oauth_issuer="https://attacker.example.com",
    )
    oauth_config = OAuth2ClientConfiguration(
        issuer="https://example.com",
        scope=["openid"],
        client_authorization=ClientIdAuthorization(id="client"),
    )
    client = OAuth2Client(configuration=oauth_config, network=network)

    try:
        asyncio.run(client.fetch_oauth_server_metadata())
    except ValueError as exc:
        assert "expected" in str(exc)
        assert "attacker" in str(exc)
        return
    raise AssertionError("Expected ValueError for mismatched OAuth issuer")


def test_openid_configuration_allows_trailing_slash_variants() -> None:
    network = DiscoveryIssuerNetwork(
        openid_issuer="https://example.com",
        oauth_issuer="https://example.com",
    )
    oauth_config = OAuth2ClientConfiguration(
        issuer="https://example.com/",
        scope=["openid"],
        client_authorization=ClientIdAuthorization(id="client"),
    )
    client = OAuth2Client(configuration=oauth_config, network=network)

    asyncio.run(client.fetch_openid_configuration())


def test_oauth_server_metadata_allows_trailing_slash_variants() -> None:
    network = DiscoveryIssuerNetwork(
        openid_issuer="https://example.com",
        oauth_issuer="https://example.com/",
    )
    oauth_config = OAuth2ClientConfiguration(
        issuer="https://example.com",
        scope=["openid"],
        client_authorization=ClientIdAuthorization(id="client"),
    )
    client = OAuth2Client(configuration=oauth_config, network=network)

    asyncio.run(client.fetch_oauth_server_metadata())


@dataclass
class JwtContextRequest(OAuth2TokenRequest):
    _discovery_configuration: OpenIdConfiguration | OAuthAuthorizationServer
    _client_configuration: OAuth2ClientConfiguration

    @property
    def discovery_configuration(self) -> OpenIdConfiguration | OAuthAuthorizationServer:
        return self._discovery_configuration

    @property
    def client_configuration(self) -> OAuth2ClientConfiguration:
        return self._client_configuration

    @property
    def token_validator_context(self) -> IDTokenValidatorContext:
        return NullIDTokenValidatorContext()

    @property
    def category(self) -> OAuth2APIRequestCategory:
        return OAuth2APIRequestCategory.TOKEN

    @property
    def http_method(self) -> APIRequestMethod:
        return APIRequestMethod.POST

    @property
    def url(self) -> str:
        return "https://example.com/token"

    @property
    def query(self) -> dict[str, RequestValue] | None:
        return None

    @property
    def headers(self) -> dict[str, RequestValue] | None:
        return None

    @property
    def accepts_type(self) -> APIContentType | None:
        return APIContentType.JSON

    @property
    def content_type(self) -> APIContentType | None:
        return APIContentType.FORM_URLENCODED

    def body(self) -> bytes | None:
        return None

    def parse_error(self, data: Mapping[str, Any]) -> Exception | None:
        return None


def test_build_jwt_context_uses_configured_issuer() -> None:
    discovery = OpenIdConfiguration.from_json(
        {
            "issuer": "https://attacker.example.com",
            "authorization_endpoint": "https://example.com/auth",
            "token_endpoint": "https://example.com/token",
            "jwks_uri": "https://example.com/keys",
        }
    )
    oauth_config = OAuth2ClientConfiguration(
        issuer="https://example.com",
        scope=["openid"],
        client_authorization=ClientIdAuthorization(id="client"),
    )
    request = JwtContextRequest(
        _discovery_configuration=discovery,
        _client_configuration=oauth_config,
    )

    context = OAuth2Client._build_jwt_context(request)

    assert context.issuer == "https://example.com"


# ---------------------------------------------------------------------------
# update_client_authorization
# ---------------------------------------------------------------------------


def _make_client(auth=None) -> OAuth2Client:
    """Helper to build an OAuth2Client with a specific authorization."""
    config = OAuth2ClientConfiguration(
        issuer="https://example.com",
        scope=["openid"],
        client_authorization=auth,
    )
    return OAuth2Client(configuration=config, network=DummyNetwork())


class TestUpdateClientAuthorization:
    """Tests for OAuth2Client.update_client_authorization()."""

    def test_update_with_same_type_and_compatible_client_id(self) -> None:
        """Replacing auth with the same type and client_id should succeed."""
        client = _make_client(ClientIdAuthorization(id="client-a"))
        new_auth = ClientIdAuthorization(id="client-a")

        client.update_client_authorization(new_auth)

        assert client.configuration.client_authorization is new_auth

    def test_rejects_different_client_id(self) -> None:
        """Changing client_id to a different non-None value must raise ValueError."""
        client = _make_client(ClientIdAuthorization(id="client-a"))
        new_auth = ClientIdAuthorization(id="client-b")

        try:
            client.update_client_authorization(new_auth)
        except ValueError as exc:
            assert "client-a" in str(exc)
            assert "client-b" in str(exc)
        else:
            raise AssertionError("Expected ValueError for mismatched client_id")

    def test_rejects_different_auth_type(self) -> None:
        """Changing authorization type must raise TypeError."""
        client = _make_client(ClientIdAuthorization(id="client-a"))
        new_auth = ClientAssertionAuthorization(assertion="jwt-value")

        try:
            client.update_client_authorization(new_auth)
        except TypeError as exc:
            assert "ClientIdAuthorization" in str(exc)
            assert "ClientAssertionAuthorization" in str(exc)
        else:
            raise AssertionError("Expected TypeError for mismatched auth type")

    def test_rejects_subclass_type_change(self) -> None:
        """Switching between a base type and its subclass must raise TypeError."""
        client = _make_client(ClientIdAuthorization(id="client-a"))
        new_auth = ClientSecretAuthorization(id="client-a", secret="s3cret")

        try:
            client.update_client_authorization(new_auth)
        except TypeError as exc:
            assert "ClientIdAuthorization" in str(exc)
            assert "ClientSecretAuthorization" in str(exc)
        else:
            raise AssertionError("Expected TypeError for subclass type change")

    def test_allows_update_with_same_assertion_type(self) -> None:
        """Replacing assertion auth with another assertion auth should succeed."""
        client = _make_client(ClientAssertionAuthorization(assertion="jwt-old"))
        new_auth = ClientAssertionAuthorization(assertion="jwt-new")

        client.update_client_authorization(new_auth)

        assert client.configuration.client_authorization is new_auth

    def test_clear_authorization_with_none(self) -> None:
        """Passing None should clear the client_authorization."""
        client = _make_client(ClientIdAuthorization(id="client-a"))

        client.update_client_authorization(None)

        assert client.configuration.client_authorization is None

    def test_set_authorization_from_none(self) -> None:
        """Setting auth when no existing auth is present should succeed."""
        client = _make_client(None)

        new_auth = ClientSecretAuthorization(id="client-a", secret="s3cret")
        client.update_client_authorization(new_auth)

        assert client.configuration.client_authorization is new_auth


# ---------------------------------------------------------------------------
# Default network tests
# ---------------------------------------------------------------------------


def _make_default_network_config() -> OAuth2ClientConfiguration:
    return OAuth2ClientConfiguration(
        issuer="https://example.com",
        scope=["openid"],
        client_authorization=ClientIdAuthorization(id="client"),
    )


class TestDefaultNetwork:
    """Tests for OAuth2Client.get/set_default_network class-level property."""

    def teardown_method(self) -> None:
        """Reset the class-level default after every test."""
        OAuth2Client.set_default_network(None)

    def test_default_is_none(self) -> None:
        """get_default_network returns None when nothing has been set."""
        assert OAuth2Client.get_default_network() is None

    def test_no_network_uses_default_network_interface(self) -> None:
        """When no network or default_network is set, DefaultNetworkInterface is used."""
        client = OAuth2Client(configuration=_make_default_network_config())
        assert isinstance(client.network, DefaultNetworkInterface)

    def test_class_level_override(self) -> None:
        """Setting a class-level default causes new clients to pick it up."""
        custom = DummyNetwork()
        OAuth2Client.set_default_network(custom)

        client = OAuth2Client(configuration=_make_default_network_config())
        assert client.network is custom

    def test_per_instance_override_takes_precedence(self) -> None:
        """Explicit network= in the constructor wins over default_network."""
        class_network = DummyNetwork()
        instance_network = DummyNetwork()
        OAuth2Client.set_default_network(class_network)

        client = OAuth2Client(
            configuration=_make_default_network_config(),
            network=instance_network,
        )
        assert client.network is instance_network
        assert client.network is not class_network

    def test_reset_to_none_reverts_to_default(self) -> None:
        """Clearing the class-level default reverts to DefaultNetworkInterface."""
        custom = DummyNetwork()
        OAuth2Client.set_default_network(custom)

        # Verify the custom default is in effect.
        client1 = OAuth2Client(configuration=_make_default_network_config())
        assert client1.network is custom

        # Reset and verify revert.
        OAuth2Client.set_default_network(None)
        client2 = OAuth2Client(configuration=_make_default_network_config())
        assert isinstance(client2.network, DefaultNetworkInterface)

    def test_existing_instance_not_affected(self) -> None:
        """Changing the class default does not retroactively change existing instances."""
        client = OAuth2Client(configuration=_make_default_network_config())
        original_network = client.network

        custom = DummyNetwork()
        OAuth2Client.set_default_network(custom)

        assert client.network is original_network
        assert client.network is not custom
