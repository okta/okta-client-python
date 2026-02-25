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

from okta_client.authfoundation import (
    APIAuthorization,
    BaseAuthenticationFlow,
    OAuth2APIRequestCategory,
    OAuth2Client,
    OAuth2ClientConfiguration,
    OAuth2TokenRequestDefaults,
    RequestValue,
    Token,
)
from okta_client.authfoundation.authentication import StandardAuthenticationContext
from okta_client.authfoundation.oauth2.models import OpenIdConfiguration
from okta_client.authfoundation.oauth2.request_protocols import IDTokenValidatorContext
from okta_client.authfoundation.oauth2.utils import NullIDTokenValidatorContext


class ResourceOwnerFlow(BaseAuthenticationFlow[StandardAuthenticationContext]):
    """Resource Owner Password authentication flow.

    Warning: This flow is not recommended for production use. Prefer DirectAuth when available.
    """

    def __init__(
        self,
        client: OAuth2Client,
        additional_parameters: Mapping[str, RequestValue] | None = None,
    ) -> None:
        """Create a Resource Owner flow using an OAuth2 client."""
        super().__init__(additional_parameters=additional_parameters)
        self.client = client

    async def start(
        self,
        username: str,
        password: str,
        *,
        context: StandardAuthenticationContext | None = None,
    ) -> Token:
        """Authenticate using username and password and return a Token."""
        await self._begin(context)
        ctx = context or StandardAuthenticationContext()
        self._update_context(ctx)
        try:
            openid_configuration = await self.client.fetch_openid_configuration()
            _ensure_password_grant_supported(openid_configuration)
            request = ResourceOwnerTokenRequest(
                _openid_configuration=openid_configuration,
                _client_configuration=self.client.configuration,
                additional_parameters=self.additional_parameters,
                context=ctx,
                username=username,
                password=password,
            )
            response = await self.client.exchange(request)
            self._complete(response.result)
            return response.result
        except Exception as error:
            self._fail(error)
            raise

    async def resume(self, *args, context: StandardAuthenticationContext, **kwargs) -> Token:
        """Resource Owner flow does not support resume."""
        raise NotImplementedError("Resource owner flow does not support resume")


@dataclass
class ResourceOwnerTokenRequest(OAuth2TokenRequestDefaults):
    """Token request for resource owner password flow."""

    _openid_configuration: OpenIdConfiguration
    _client_configuration: OAuth2ClientConfiguration
    additional_parameters: Mapping[str, RequestValue] | None
    context: StandardAuthenticationContext
    username: str
    password: str

    @property
    def openid_configuration(self) -> OpenIdConfiguration:
        """OpenID configuration used for endpoint resolution."""
        return self._openid_configuration

    @property
    def client_configuration(self) -> OAuth2ClientConfiguration:
        """OAuth2 client configuration used for parameter merging."""
        return self._client_configuration

    @property
    def category(self) -> OAuth2APIRequestCategory:
        """Return the token request category."""
        return OAuth2APIRequestCategory.TOKEN

    @property
    def token_validator_context(self) -> IDTokenValidatorContext:
        """Return the validation context for the token response."""
        return NullIDTokenValidatorContext()

    @property
    def query(self) -> Mapping[str, RequestValue] | None:
        """No query parameters for token requests."""
        return None

    @property
    def headers(self) -> Mapping[str, RequestValue] | None:
        """No extra headers for token requests."""
        return None

    @property
    def authorization(self) -> APIAuthorization | None:
        """No authorization header for password grant requests."""
        return None

    @property
    def timeout(self) -> float | None:
        """No custom timeout."""
        return None

    @property
    def body_parameters(self) -> Mapping[str, RequestValue]:
        """Build parameters using configuration, context, and request values."""
        parameters: dict[str, RequestValue] = {}
        config_parameters = self.client_configuration.parameters(self.category)
        if config_parameters:
            parameters.update(config_parameters)
        context_parameters = self.context.parameters(self.category)
        if context_parameters:
            parameters.update(context_parameters)
        if self.additional_parameters:
            parameters.update(self.additional_parameters)
        parameters.update(
            {
                "grant_type": "password",
                "username": self.username,
                "password": self.password,
            }
        )
        return parameters


def _ensure_password_grant_supported(openid_configuration: OpenIdConfiguration) -> None:
    """Ensure the server advertises support for the password grant."""
    if openid_configuration.grant_types_supported is None:
        raise ValueError("Resource owner password flow is not supported by the server")
    if "password" not in openid_configuration.grant_types_supported:
        raise ValueError("Resource owner password flow is not supported by the server")
