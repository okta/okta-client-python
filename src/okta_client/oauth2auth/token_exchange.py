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

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any, Union, overload

from okta_client.authfoundation import (
    APIRequestBody,
    AuthenticationContext,
    BaseAuthenticationFlow,
    OAuth2APIRequestCategory,
    OAuth2Client,
    OAuth2ClientConfiguration,
    OAuth2TokenRequestDefaults,
    RequestValue,
    Token,
)
from okta_client.authfoundation.networking import APIAuthorization, APIParsingContext, RawResponse
from okta_client.authfoundation.oauth2.models import OAuthAuthorizationServer
from okta_client.authfoundation.oauth2.requests import IDTokenValidatorContext
from okta_client.authfoundation.oauth2.utils import NullIDTokenValidatorContext
from okta_client.authfoundation.utils import coerce_optional_sequence, coerce_optional_str

_TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
_TOKEN_TYPE_PREFIX = "urn:ietf:params:oauth:token-type:"


class TokenType(str, Enum):
    """Known token type names used in RFC 8693."""

    ID_TOKEN = "id_token"
    ACCESS_TOKEN = "access_token"
    DEVICE_SECRET = "device-secret"
    REFRESH_TOKEN = "refresh_token"
    ID_JAG = "urn:ietf:params:oauth:token-type:id-jag"


@dataclass(frozen=True)
class TokenDescriptor:
    """Descriptor for an exchanged token (type + value)."""

    token_type: Union[TokenType, str]
    value: str

    def token_type_urn(self) -> str:
        """Return the RFC 8693 token type URN."""
        raw = self.token_type.value if isinstance(self.token_type, TokenType) else str(self.token_type)
        if raw.startswith("urn:"):
            return raw
        return f"{_TOKEN_TYPE_PREFIX}{raw}"


@dataclass(frozen=True)
class TokenExchangeParameters:
    """Structured parameters for RFC 8693 token exchange."""

    subject: TokenDescriptor
    actor: TokenDescriptor | None = None
    audience: str | None = None
    resource: Sequence[str] | None = None

    def validate(self) -> None:
        if not self.subject.value:
            raise ValueError("subject token value is required")


@dataclass(frozen=True)
class TokenExchangeContext(AuthenticationContext):
    """Context for Token Exchange flow parameters and request customization."""

    scope: Sequence[str] | None = None
    requested_token_type: Union[TokenType, str] | None = None
    _additional_parameters: Mapping[str, RequestValue] | None = None
    _persist_values: Mapping[str, str] | None = None

    @property
    def acr_values(self) -> list[str] | None:
        return None

    @property
    def persist_values(self) -> Mapping[str, str] | None:
        return self._persist_values

    @property
    def additional_parameters(self) -> Mapping[str, RequestValue] | None:
        return self._additional_parameters

    def parameters(self, category: OAuth2APIRequestCategory) -> Mapping[str, RequestValue] | None:
        if category != OAuth2APIRequestCategory.TOKEN:
            return None
        result: dict[str, RequestValue] = dict(self.additional_parameters or {})
        if self.scope:
            result["scope"] = " ".join([str(item) for item in self.scope])
        if self.requested_token_type:
            requested = self.requested_token_type
            raw = requested.value if isinstance(requested, TokenType) else str(requested)
            if not raw.startswith("urn:"):
                raw = f"{_TOKEN_TYPE_PREFIX}{raw}"
            result["requested_token_type"] = raw
        return result or None


class TokenExchangeFlow(BaseAuthenticationFlow[TokenExchangeContext]):
    """OAuth 2.0 Token Exchange authentication flow (RFC 8693)."""

    def __init__(
        self,
        client: OAuth2Client,
        additional_parameters: Mapping[str, RequestValue] | None = None,
    ) -> None:
        super().__init__(additional_parameters=additional_parameters)
        self.client = client

    @overload
    async def start(
        self,
        parameters: Union[TokenExchangeParameters, Mapping[str, Any]],
        *,
        context: TokenExchangeContext | None = None,
    ) -> Token: ...

    @overload
    async def start(
        self,
        *,
        subject_token: str,
        subject_token_type: Union[TokenType, str],
        actor_token: str | None = None,
        actor_token_type: Union[TokenType, str] | None = None,
        audience: str | None = None,
        resource: Sequence[str] | None = None,
        scope: Sequence[str] | None = None,
        requested_token_type: Union[TokenType, str] | None = None,
        context: TokenExchangeContext | None = None,
    ) -> Token: ...

    async def start(
        self,
        parameters: Union[TokenExchangeParameters, Mapping[str, Any], None] = None,
        **kwargs: Any,
    ) -> Token:
        """Exchange a subject token (and optional actor token) for a new token.

        Supports two calling conventions:

        **Structured form** (existing)::

            await flow.start(
                TokenExchangeParameters(subject=..., audience=...),
                context=TokenExchangeContext(scope=...),
            )

        **Keyword form** (new)::

            await flow.start(
                subject_token="...",
                subject_token_type=TokenType.ID_TOKEN,
                audience="...",
                scope=["openid"],
                requested_token_type=TokenType.ID_JAG,
            )
        """
        if parameters is not None:
            context: TokenExchangeContext | None = kwargs.get("context")  # type: ignore[no-redef]
            return await self._start_exchange(parameters, context=context)

        # Keyword form — extract and validate arguments
        subject_token = kwargs.get("subject_token")
        subject_token_type = kwargs.get("subject_token_type")
        if subject_token is None or subject_token_type is None:
            raise TypeError("subject_token and subject_token_type are required")

        actor_token = kwargs.get("actor_token")
        actor_token_type = kwargs.get("actor_token_type")
        if (actor_token is None) != (actor_token_type is None):
            raise TypeError("actor_token and actor_token_type must be provided together")

        audience = kwargs.get("audience")
        resource = kwargs.get("resource")
        scope = kwargs.get("scope")
        requested_token_type = kwargs.get("requested_token_type")
        kw_context: TokenExchangeContext | None = kwargs.get("context")

        params = TokenExchangeParameters(
            subject=TokenDescriptor(token_type=subject_token_type, value=subject_token),
            actor=(
                TokenDescriptor(token_type=actor_token_type, value=actor_token)
                if actor_token is not None and actor_token_type is not None
                else None
            ),
            audience=audience,
            resource=list(resource) if resource else None,
        )

        effective_context: TokenExchangeContext
        if kw_context is not None:
            effective_context = TokenExchangeContext(
                scope=scope if scope is not None else kw_context.scope,
                requested_token_type=(
                    requested_token_type
                    if requested_token_type is not None
                    else kw_context.requested_token_type
                ),
                _additional_parameters=kw_context.additional_parameters,
                _persist_values=kw_context.persist_values,
            )
        elif scope is not None or requested_token_type is not None:
            effective_context = TokenExchangeContext(
                scope=scope,
                requested_token_type=requested_token_type,
            )
        else:
            effective_context = TokenExchangeContext()

        return await self._start_exchange(params, context=effective_context)

    async def _start_exchange(
        self,
        parameters: Union[TokenExchangeParameters, Mapping[str, Any]],
        *,
        context: TokenExchangeContext | None = None,
    ) -> Token:
        """Internal implementation for both calling conventions."""
        await self._begin(context)
        ctx = context or TokenExchangeContext()
        self._update_context(ctx)
        try:
            normalized = self._normalize_parameters(parameters)
            normalized.validate()
            oauth_authorization_server = await self.client.fetch_oauth_server_metadata()
            self._ensure_token_exchange_supported(oauth_authorization_server)
            request = TokenExchangeTokenRequest(
                _oauth_authorization_server=oauth_authorization_server,
                _client_configuration=self.client.configuration,
                additional_parameters=self.additional_parameters,
                context=ctx,
                parameters=normalized,
            )
            response = await self.client.exchange(request)
            self._complete(response.result)
            return response.result
        except Exception as error:
            self._fail(error)
            raise

    async def resume(self, *args, context: TokenExchangeContext, **kwargs) -> Token:
        """Token Exchange flow does not support resume."""
        raise NotImplementedError("Token exchange flow does not support resume")

    @staticmethod
    def _ensure_token_exchange_supported(oauth_authorization_server: OAuthAuthorizationServer) -> None:
        if oauth_authorization_server.grant_types_supported is None:
            raise ValueError("Token exchange flow is not supported by the server")
        if _TOKEN_EXCHANGE_GRANT_TYPE not in oauth_authorization_server.grant_types_supported:
            raise ValueError("Token exchange flow is not supported by the server")

    @staticmethod
    def _normalize_parameters(parameters: Union[TokenExchangeParameters, Mapping[str, Any]]) -> TokenExchangeParameters:
        if isinstance(parameters, TokenExchangeParameters):
            return parameters
        if not isinstance(parameters, Mapping):
            raise TypeError("parameters must be TokenExchangeParameters or a mapping")

        subject = TokenExchangeFlow._parse_token_descriptor(parameters.get("subject"))
        actor = TokenExchangeFlow._parse_token_descriptor(parameters.get("actor")) if parameters.get("actor") else None

        return TokenExchangeParameters(
            subject=subject,
            actor=actor,
            audience=coerce_optional_str(parameters.get("audience")),
            resource=coerce_optional_sequence(parameters.get("resource")),
        )

    @staticmethod
    def _parse_token_descriptor(value: Any) -> TokenDescriptor:
        if isinstance(value, TokenDescriptor):
            return value
        if not isinstance(value, Mapping):
            raise TypeError("token descriptor must be a mapping with 'type' and 'value'")
        token_type = value.get("type")
        token_value = value.get("value")
        if token_value is None:
            raise ValueError("token descriptor requires a 'value'")
        return TokenDescriptor(token_type=token_type or TokenType.ACCESS_TOKEN, value=str(token_value))

@dataclass
class TokenExchangeTokenRequest(OAuth2TokenRequestDefaults, APIRequestBody):
    """Token request for RFC 8693 token exchange."""

    _oauth_authorization_server: OAuthAuthorizationServer
    _client_configuration: OAuth2ClientConfiguration
    additional_parameters: Mapping[str, RequestValue] | None
    context: TokenExchangeContext
    parameters: TokenExchangeParameters

    @property
    def discovery_configuration(self) -> OAuthAuthorizationServer:
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
                "grant_type": _TOKEN_EXCHANGE_GRANT_TYPE,
                "subject_token": self.parameters.subject.value,
                "subject_token_type": self.parameters.subject.token_type_urn(),
            }
        )

        if self.parameters.actor is not None:
            parameters["actor_token"] = self.parameters.actor.value
            parameters["actor_token_type"] = self.parameters.actor.token_type_urn()

        if self.parameters.audience:
            parameters["audience"] = self.parameters.audience

        if self.parameters.resource:
            parameters["resource"] = " ".join(self.parameters.resource)

        return parameters

    def body(self) -> bytes | None:
        return None

    def parse_response(self, response: RawResponse, parsing_context: APIParsingContext | None = None) -> Any:
        if not response.body:
            return {}
        return json.loads(response.body.decode("utf-8"))


