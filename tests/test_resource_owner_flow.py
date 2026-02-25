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
from urllib.parse import urlsplit

from okta_client.authfoundation import (
    NetworkInterface,
    OAuth2Client,
    OAuth2ClientConfiguration,
    OAuth2Error,
    RawResponse,
    StandardAuthenticationContext,
)
from okta_client.authfoundation.oauth2.client_authorization import ClientIdAuthorization
from okta_client.oauth2auth import ResourceOwnerFlow


class DummyNetwork(NetworkInterface):
    def __init__(self, token_body: dict, status_code: int = 200, grant_types=None) -> None:
        self.token_body = token_body
        self.status_code = status_code
        self.grant_types = grant_types

    def send(self, request) -> RawResponse:
        path = urlsplit(request.url).path
        if path.endswith(".well-known/openid-configuration"):
            body = {
                "issuer": "https://example.com",
                "authorization_endpoint": "https://example.com/auth",
                "token_endpoint": "https://example.com/token",
                "jwks_uri": "https://example.com/keys",
                "grant_types_supported": self.grant_types,
            }
            return RawResponse(status_code=200, headers={}, body=json.dumps(body).encode("utf-8"))
        if request.url.endswith("/keys"):
            return RawResponse(status_code=200, headers={}, body=json.dumps({"keys": []}).encode("utf-8"))
        if request.url.endswith("/token"):
            return RawResponse(status_code=self.status_code, headers={}, body=json.dumps(self.token_body).encode("utf-8"))
        return RawResponse(status_code=200, headers={}, body=b"{}")


def _build_client(network: NetworkInterface) -> OAuth2Client:
    config = OAuth2ClientConfiguration(
        issuer="https://example.com",
        scope=["openid"],
        client_authorization=ClientIdAuthorization(id="client"),
    )
    return OAuth2Client(configuration=config, network=network)


def test_resource_owner_flow_success() -> None:
    network = DummyNetwork(
        token_body={"access_token": "token", "token_type": "Bearer", "expires_in": 3600},
        grant_types=["password"],
    )
    client = _build_client(network)
    flow = ResourceOwnerFlow(client=client)

    token = asyncio.run(flow.start("user", "pass", context=StandardAuthenticationContext()))

    assert token.access_token == "token"


def test_resource_owner_flow_invalid_credentials() -> None:
    network = DummyNetwork(
        token_body={"error": "invalid_grant", "error_description": "invalid credentials"},
        status_code=400,
        grant_types=["password"],
    )
    client = _build_client(network)
    flow = ResourceOwnerFlow(client=client)

    try:
        asyncio.run(flow.start("user", "pass", context=StandardAuthenticationContext()))
    except OAuth2Error as error:
        assert error.error == "invalid_grant"
        return
    raise AssertionError("Expected OAuth2Error for invalid credentials")


def test_resource_owner_flow_unsupported_server() -> None:
    network = DummyNetwork(
        token_body={"access_token": "token", "token_type": "Bearer", "expires_in": 3600},
        grant_types=["authorization_code"],
    )
    client = _build_client(network)
    flow = ResourceOwnerFlow(client=client)

    try:
        asyncio.run(flow.start("user", "pass", context=StandardAuthenticationContext()))
    except ValueError:
        return
    raise AssertionError("Expected ValueError for unsupported password grant")
