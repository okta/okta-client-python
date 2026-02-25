# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

import jwt
import pytest

from okta_client.authfoundation import (
    ClientAssertionAuthorization,
    ClientIdAuthorization,
    ClientSecretAuthorization,
    JWTBearerClaims,
    LocalKeyProvider,
    OAuth2ClientConfiguration,
    get_key_provider,
    set_key_provider,
)
from okta_client.authfoundation.oauth2.parameters import OAuth2APIRequestCategory
from tests.utils import KeyProviderStub


def test_client_id_authorization_parameters() -> None:
    authorization = ClientIdAuthorization(id="client")

    assert authorization.parameters(OAuth2APIRequestCategory.CONFIGURATION) is None
    assert authorization.parameters(OAuth2APIRequestCategory.TOKEN) == {"client_id": "client"}
    assert authorization.parameters(OAuth2APIRequestCategory.AUTHORIZATION) == {"client_id": "client"}
    assert authorization.client_id == "client"


def test_client_secret_authorization_parameters() -> None:
    authorization = ClientSecretAuthorization(id="client", secret="secret")

    assert authorization.parameters(OAuth2APIRequestCategory.CONFIGURATION) is None
    assert authorization.parameters(OAuth2APIRequestCategory.TOKEN) == {"client_id": "client", "client_secret": "secret"}
    assert authorization.parameters(OAuth2APIRequestCategory.AUTHORIZATION) == {"client_id": "client", "client_secret": "secret"}
    assert authorization.client_id == "client"


def test_jwt_bearer_authorization_parameters() -> None:
    authorization = ClientAssertionAuthorization(assertion="jwt")

    assert authorization.parameters(OAuth2APIRequestCategory.CONFIGURATION) is None
    params = authorization.parameters(OAuth2APIRequestCategory.TOKEN)
    assert params is not None
    assert params["client_assertion"] == "jwt"
    assert params["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


def test_jwt_bearer_authorization_claims_with_default_provider() -> None:
    previous = get_key_provider()
    try:
        secret = "super-long-and-secure-secret-key"
        provider = LocalKeyProvider(key=secret, algorithm="HS256")
        set_key_provider(provider)
        claims = JWTBearerClaims(
            issuer="client",
            subject="client",
            audience="https://example.com/token",
            expires_in=300,
        )
        authorization = ClientAssertionAuthorization(assertion_claims=claims)
        params = authorization.parameters(OAuth2APIRequestCategory.TOKEN)
        assert params is not None
        assertion = params["client_assertion"]
        assert isinstance(assertion, str)
        decoded = jwt.decode(assertion, secret, algorithms=["HS256"], options={"verify_aud": False})
        assert decoded["iss"] == "client"
        assert authorization.client_id == "client"
    finally:
        set_key_provider(previous)


def test_jwt_bearer_authorization_rejects_conflicting_inputs() -> None:
    claims = JWTBearerClaims(
        issuer="client",
        subject="client",
        audience="https://example.com/token",
        expires_in=300,
    )
    with pytest.raises(ValueError, match="either 'assertion' or 'assertion_claims'"):
        ClientAssertionAuthorization(assertion="jwt", assertion_claims=claims)


def test_jwt_bearer_authorization_requires_assertion_or_claims() -> None:
    with pytest.raises(ValueError, match="Either 'assertion' or 'assertion_claims'"):
        ClientAssertionAuthorization()


def test_jwt_bearer_authorization_claims_require_key_provider() -> None:
    """assertion_claims without an explicit or global key provider raises immediately."""
    claims = JWTBearerClaims(
        issuer="client",
        subject="client",
        audience="https://example.com/token",
        expires_in=300,
    )
    with pytest.raises(ValueError, match="key provider"):
        ClientAssertionAuthorization(assertion_claims=claims)


def test_jwt_bearer_authorization_uses_custom_key_provider() -> None:
    claims = JWTBearerClaims(
        issuer="client",
        subject="client",
        audience="https://example.com/token",
        expires_in=300,
    )
    authorization = ClientAssertionAuthorization(assertion_claims=claims, key_provider=KeyProviderStub())
    params = authorization.parameters(OAuth2APIRequestCategory.TOKEN)
    assert params is not None

    assertion = params["client_assertion"]
    assert isinstance(assertion, str)
    decoded = jwt.decode(assertion, options={"verify_signature": False})
    assert decoded["iss"] == "client"
    assert decoded["sub"] == "client"
    assert authorization.client_id == "client"


def test_jwt_bearer_authorization_client_id_from_assertion() -> None:
    assertion = jwt.encode({"iss": "client-from-assertion"}, "secret-super-duper-long-secure-key", algorithm="HS256")
    authorization = ClientAssertionAuthorization(assertion=assertion)
    assert authorization.client_id == "client-from-assertion"


def test_jwt_bearer_authorization_client_id_none_with_invalid_assertion() -> None:
    """client_id is None when the assertion cannot be decoded."""
    authorization = ClientAssertionAuthorization(assertion="not-a-valid-jwt")
    assert authorization.client_id is None


def test_configuration_merges_client_authorization_parameters() -> None:
    configuration = OAuth2ClientConfiguration(
        issuer="https://example.com",
        scope=["openid"],
        client_authorization=ClientAssertionAuthorization(assertion="jwt"),
        additional_parameters={"custom": "value"},
    )

    params = configuration.parameters(OAuth2APIRequestCategory.TOKEN)
    assert params is not None
    assert params["scope"] == "openid"
    assert params["custom"] == "value"
    assert params["client_assertion"] == "jwt"
    assert params["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
