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
from urllib.parse import urlsplit

from okta_client.authfoundation import (
    APIRequestBody,
    NetworkInterface,
    OAuth2Client,
    OAuth2ClientConfiguration,
    OAuth2Error,
    RawResponse,
    RequestValue,
)
from okta_client.authfoundation.oauth2.client_authorization import ClientIdAuthorization
from okta_client.authfoundation.oauth2.models import OpenIdConfiguration
from okta_client.authfoundation.oauth2.parameters import OAuth2APIRequestCategory
from okta_client.authfoundation.oauth2.request_protocols import (
    IDTokenValidatorContext,
    OAuth2TokenRequestDefaults,
)


class DummyNetwork(NetworkInterface):
    def __init__(self, responses: Mapping[str, RawResponse]) -> None:
        self._responses = responses

    def send(self, request) -> RawResponse:
        parts = urlsplit(request.url)
        normalized_url = f"{parts.scheme}://{parts.netloc}{parts.path}"
        response = self._responses.get(request.url) or self._responses.get(normalized_url)
        if response is None:
            raise AssertionError(f"Unexpected request URL: {request.url}")
        return response


class NullValidatorContext(IDTokenValidatorContext):
    pass


@dataclass
class TokenExchangeRequest(OAuth2TokenRequestDefaults, APIRequestBody):
    _openid_configuration: OpenIdConfiguration
    _client_configuration: OAuth2ClientConfiguration
    username: str
    password: str

    @property
    def openid_configuration(self) -> OpenIdConfiguration:
        return self._openid_configuration

    @property
    def client_configuration(self) -> OAuth2ClientConfiguration:
        return self._client_configuration

    @property
    def category(self) -> OAuth2APIRequestCategory:
        return OAuth2APIRequestCategory.TOKEN

    @property
    def token_validator_context(self) -> IDTokenValidatorContext:
        return NullValidatorContext()

    @property
    def query(self) -> Mapping[str, RequestValue] | None:
        return None

    @property
    def headers(self) -> Mapping[str, RequestValue] | None:
        return None

    @property
    def authorization(self):
        return None

    @property
    def timeout(self) -> float | None:
        return None

    def body(self) -> bytes | None:
        return None

    def parse_response(self, response: RawResponse, parsing_context=None):
        return json.loads(response.body.decode("utf-8"))

    @property
    def body_parameters(self) -> Mapping[str, RequestValue]:
        return {
            "grant_type": "password",
            "username": self.username,
            "password": self.password,
        }


def test_oauth2_exchange_success() -> None:
    openid = OpenIdConfiguration.from_json(
        {
            "authorization_endpoint": "https://example.com/auth",
            "token_endpoint": "https://example.com/token",
            "jwks_uri": "https://example.com/keys",
        }
    )
    token_body = json.dumps(
        {
            "access_token": "token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
    ).encode("utf-8")
    discovery_body = json.dumps(
        {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/auth",
            "token_endpoint": "https://example.com/token",
            "jwks_uri": "https://example.com/keys",
        }
    ).encode("utf-8")
    jwks_body = json.dumps({"keys": []}).encode("utf-8")
    network = DummyNetwork(
        responses={
            "https://example.com/.well-known/openid-configuration": RawResponse(
                status_code=200,
                headers={},
                body=discovery_body,
            ),
            "https://example.com/keys?client_id=client": RawResponse(
                status_code=200,
                headers={},
                body=jwks_body,
            ),
            "https://example.com/token": RawResponse(
                status_code=200,
                headers={},
                body=token_body,
            ),
        }
    )
    client = OAuth2Client(
        configuration=OAuth2ClientConfiguration(issuer="https://example.com",
                                                scope=["openid"],
                                                client_authorization=ClientIdAuthorization(id="client"),
                                                ),
        network=network,
    )
    request = TokenExchangeRequest(
        _openid_configuration=openid,
        _client_configuration=client.configuration,
        username="user",
        password="pass",
    )

    response = asyncio.run(client.exchange(request))

    assert response.result.access_token == "token"


def test_oauth2_exchange_oauth_error() -> None:
    openid = OpenIdConfiguration.from_json(
        {
            "authorization_endpoint": "https://example.com/auth",
            "token_endpoint": "https://example.com/token",
            "jwks_uri": "https://example.com/keys",
        }
    )
    token_body = json.dumps(
        {
            "error": "invalid_grant",
            "error_description": "invalid credentials",
        }
    ).encode("utf-8")
    discovery_body = json.dumps(
        {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/auth",
            "token_endpoint": "https://example.com/token",
            "jwks_uri": "https://example.com/keys",
        }
    ).encode("utf-8")
    jwks_body = json.dumps({"keys": []}).encode("utf-8")
    network = DummyNetwork(
        responses={
            "https://example.com/.well-known/openid-configuration": RawResponse(
                status_code=200,
                headers={},
                body=discovery_body,
            ),
            "https://example.com/keys?client_id=client": RawResponse(
                status_code=200,
                headers={},
                body=jwks_body,
            ),
            "https://example.com/token": RawResponse(
                status_code=400,
                headers={},
                body=token_body,
            ),
        }
    )
    client = OAuth2Client(
        configuration=OAuth2ClientConfiguration(issuer="https://example.com",
                                                scope=["openid"],
                                                client_authorization=ClientIdAuthorization(id="client")),
        network=network,
    )
    request = TokenExchangeRequest(
        _openid_configuration=openid,
        _client_configuration=client.configuration,
        username="user",
        password="pass",
    )

    try:
        asyncio.run(client.exchange(request))
    except OAuth2Error as error:
        assert error.error == "invalid_grant"
        assert error.error_description == "invalid credentials"
        return
    raise AssertionError("Expected OAuth2Error for invalid_grant")
