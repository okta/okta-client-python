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

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from okta_client.authfoundation.authentication import BaseAuthenticationFlow, StandardAuthenticationContext
from okta_client.authfoundation.networking import APIRequestBody, RequestValue
from okta_client.authfoundation.utils import coerce_optional_sequence

from ..networking import APIAuthorization
from .config import OAuth2ClientConfiguration
from .errors import OAuth2Error
from .models import OpenIdConfiguration
from .parameters import OAuth2APIRequestCategory
from .request_protocols import IDTokenValidatorContext, OAuth2TokenRequestDefaults
from .utils import NullIDTokenValidatorContext

_REFRESH_TOKEN_GRANT_TYPE = "refresh_token"


class RefreshTokenFlow(BaseAuthenticationFlow[StandardAuthenticationContext]):
    """OAuth 2.0 Refresh Token flow."""

    def __init__(
        self,
        client: OAuth2Client,
        additional_parameters: Mapping[str, RequestValue] | None = None,
    ) -> None:
        super().__init__(additional_parameters=additional_parameters)
        self.client = client

    async def start(
        self,
        refresh_token: str,
        *,
        scope: Sequence[str] | None = None,
        context: StandardAuthenticationContext | None = None,
    ) -> Token:
        """Refresh using a refresh token string."""
        await self._begin(context)
        ctx = context or StandardAuthenticationContext()
        self._update_context(ctx)
        try:
            if not refresh_token:
                raise OAuth2Error(
                    error="missing_refresh_token",
                    error_description="Refresh token value is required",
                )
            refreshed = await self._exchange_refresh_token(
                refresh_token,
                scope=scope,
                context=ctx,
            )
            self._complete(refreshed)
            return refreshed
        except Exception as error:
            self._fail(error)
            raise

    async def resume(self, *args, context: StandardAuthenticationContext, **kwargs) -> Token:
        raise NotImplementedError("Refresh token flow does not support resume")

    async def _exchange_refresh_token(
        self,
        refresh_token: str,
        *,
        scope: Sequence[str] | None = None,
        context: StandardAuthenticationContext,
    ) -> Token:
        openid_configuration = await self.client.fetch_openid_configuration()
        request = RefreshTokenRequest(
            _openid_configuration=openid_configuration,
            _client_configuration=self.client.configuration,
            additional_parameters=self.additional_parameters,
            context=context,
            refresh_token=refresh_token,
            scope=scope,
        )
        response = await self.client.exchange(request)
        return response.result


@dataclass
class RefreshTokenRequest(OAuth2TokenRequestDefaults, APIRequestBody):
    """Token request for refresh token grant."""

    _openid_configuration: OpenIdConfiguration
    _client_configuration: OAuth2ClientConfiguration
    additional_parameters: Mapping[str, RequestValue] | None
    context: StandardAuthenticationContext
    refresh_token: str
    scope: Sequence[str] | None = None

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
                "grant_type": _REFRESH_TOKEN_GRANT_TYPE,
                "refresh_token": self.refresh_token,
            }
        )
        scope_values = coerce_optional_sequence(self.scope)
        if scope_values is not None:
            parameters["scope"] = " ".join(scope_values)
        else:
            parameters.pop("scope", None)
        return parameters


if TYPE_CHECKING:
    from okta_client.authfoundation.token import Token

    from .client import OAuth2Client
