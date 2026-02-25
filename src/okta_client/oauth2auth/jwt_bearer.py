# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

import jwt as jwt_module

from okta_client.authfoundation import (
    APIAuthorization,
    BaseAuthenticationFlow,
    KeyProvider,
    OAuth2APIRequestCategory,
    OAuth2Client,
    OAuth2ClientConfiguration,
    OAuth2TokenRequestDefaults,
    RequestValue,
    Token,
)
from okta_client.authfoundation.authentication import StandardAuthenticationContext
from okta_client.authfoundation.oauth2.jwt_bearer_claims import JWTBearerClaims
from okta_client.authfoundation.oauth2.jwt_bearer_utils import resolve_jwt_bearer_assertion
from okta_client.authfoundation.oauth2.jwt_token import JWTType
from okta_client.authfoundation.oauth2.models import OAuthAuthorizationServer
from okta_client.authfoundation.oauth2.request_protocols import IDTokenValidatorContext
from okta_client.authfoundation.oauth2.utils import NullIDTokenValidatorContext

_JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer"


class JWTBearerFlow(BaseAuthenticationFlow[StandardAuthenticationContext]):
    """JWT Bearer Grant authentication flow (RFC 7523)."""

    def __init__(
        self,
        client: OAuth2Client,
        additional_parameters: Mapping[str, RequestValue] | None = None,
    ) -> None:
        super().__init__(additional_parameters=additional_parameters)
        self.client = client

    async def start(
        self,
        *,
        assertion: str | None = None,
        assertion_claims: JWTBearerClaims | None = None,
        context: StandardAuthenticationContext | None = None,
        key_provider: KeyProvider | None = None,
    ) -> Token:
        """Exchange a JWT bearer assertion for a token."""
        await self._begin(context)
        ctx = context or StandardAuthenticationContext()
        self._update_context(ctx)
        try:
            jwt_assertion = resolve_jwt_bearer_assertion(
                assertion=assertion,
                assertion_claims=assertion_claims,
                key_provider=key_provider,
            )

            oauth_authorization_server = await self.client.fetch_oauth_server_metadata()

            # Verify the authorization server supports the JWT bearer grant type before
            # attempting the exchange to provide a clearer error message if it's not supported.
            #
            # Note: If the JWT header is an ID-JAG, the authorization server metadata may not
            # indicate support for the JWT bearer grant type since it's a custom extension, so
            # we skip this check for ID-JAG assertions.
            typ = jwt_module.get_unverified_header(jwt_assertion).get("typ")
            try:
                jwt_type = JWTType(typ) if typ else None
            except ValueError:
                jwt_type = None

            if jwt_type not in (JWTType.ID_JAG, JWTType.OAUTH_ID_JAG):
                self._ensure_jwt_bearer_supported(oauth_authorization_server)

            request = JWTBearerTokenRequest(
                _oauth_authorization_server=oauth_authorization_server,
                _client_configuration=self.client.configuration,
                additional_parameters=self.additional_parameters,
                context=ctx,
                assertion=jwt_assertion,
            )

            response = await self.client.exchange(request)
            self._complete(response.result)
            return response.result
        except Exception as error:
            self._fail(error)
            raise

    async def resume(self, *args, context: StandardAuthenticationContext, **kwargs) -> Token:
        raise NotImplementedError("JWT bearer flow does not support resume")

    @staticmethod
    def generate_assertion(
        claims: JWTBearerClaims | None,
        key_provider: KeyProvider | None,
    ) -> str:
        return resolve_jwt_bearer_assertion(
            assertion_claims=claims,
            key_provider=key_provider,
        )

    @staticmethod
    def _ensure_jwt_bearer_supported(oauth_authorization_server: OAuthAuthorizationServer) -> None:
        if oauth_authorization_server.grant_types_supported is None:
            raise ValueError("JWT bearer flow is not supported by the server")
        if _JWT_BEARER_GRANT_TYPE not in oauth_authorization_server.grant_types_supported:
            raise ValueError("JWT bearer flow is not supported by the server")


@dataclass
class JWTBearerTokenRequest(OAuth2TokenRequestDefaults):
    """Token request for JWT Bearer Grant (RFC 7523)."""

    _oauth_authorization_server: OAuthAuthorizationServer
    _client_configuration: OAuth2ClientConfiguration
    additional_parameters: Mapping[str, RequestValue] | None
    context: StandardAuthenticationContext
    assertion: str

    @property
    def oauth_authorization_server(self) -> OAuthAuthorizationServer:
        return self._oauth_authorization_server

    @property
    def client_configuration(self) -> OAuth2ClientConfiguration:
        return self._client_configuration

    @property
    def category(self) -> OAuth2APIRequestCategory:
        return OAuth2APIRequestCategory.TOKEN

    @property
    def token_validator_context(self) -> IDTokenValidatorContext:
        return NullIDTokenValidatorContext()

    @property
    def query(self) -> Mapping[str, RequestValue] | None:
        return None

    @property
    def headers(self) -> Mapping[str, RequestValue] | None:
        return None

    @property
    def authorization(self) -> APIAuthorization | None:
        return None

    @property
    def timeout(self) -> float | None:
        return None

    @property
    def body_parameters(self) -> Mapping[str, RequestValue]:
        parameters: dict[str, RequestValue] = {}
        if self.additional_parameters:
            parameters.update(self.additional_parameters)
        config_parameters = self.client_configuration.parameters(self.category)
        if config_parameters:
            parameters.update(config_parameters)
        context_parameters = self.context.parameters(self.category)
        if context_parameters:
            parameters.update(context_parameters)
        parameters.update(
            {
                "grant_type": _JWT_BEARER_GRANT_TYPE,
                "assertion": self.assertion,
            }
        )
        return parameters
