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
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from ..authentication import AuthenticationContext

from ..networking import (
    APIContentType,
    APIParsingContext,
    APIRequest,
    APIRequestBody,
    APIRequestMethod,
    BaseAPIRequest,
    RawResponse,
    RequestValue,
)
from ..networking.body import APIRequestBodyMixin
from .config import OAuth2ClientConfiguration
from .errors import OAuth2Error
from .models import OAuthAuthorizationServer, OpenIdConfiguration
from .parameters import OAuth2APIRequestCategory


@runtime_checkable
class IDTokenValidatorContext(Protocol):
    """Context hints for ID token validation.

    .. deprecated::
        Subsumed by :class:`AuthenticationContext`, which now provides
        ``nonce``, ``max_age``, and ``audience`` directly. Kept for
        backward compatibility.
    """

    @property
    def nonce(self) -> str | None:
        """Nonce value expected in the ID token, if any."""
        ...

    @property
    def max_age(self) -> float | None:
        """Maximum token age in seconds, if any."""
        ...


class JSONRequest(BaseAPIRequest[Any]):
    """Base request type for JSON APIs with default parsing."""

    @property
    def query(self) -> Mapping[str, RequestValue] | None:
        """Default query parameters (none)."""
        return None

    @property
    def headers(self) -> Mapping[str, RequestValue] | None:
        """Default headers (none)."""
        return None

    @property
    def accepts_type(self) -> APIContentType | None:
        """Accept JSON responses by default."""
        return APIContentType.JSON

    @property
    def content_type(self) -> APIContentType | None:
        """Send JSON content by default."""
        return APIContentType.JSON

    @property
    def timeout(self) -> float | None:
        """Default timeout (none)."""
        return None

    def body(self) -> bytes | None:
        """Default body (none)."""
        return None

    def parse_response(self, response: RawResponse, parsing_context: APIParsingContext | None = None) -> Any:
        """Parse JSON responses into a mapping or list."""
        import json

        if not response.body:
            return {}
        return json.loads(response.body.decode("utf-8"))


@runtime_checkable
class OAuth2APIRequest(APIRequest[Any], Protocol):
    """Protocol for OAuth2 requests tied to OpenID configuration and category."""

    @property
    def discovery_configuration(self) -> OpenIdConfiguration | OAuthAuthorizationServer:
        """Discovery configuration used to resolve endpoint URLs."""
        ...

    @property
    def category(self) -> OAuth2APIRequestCategory:
        """Category used to choose which parameters apply to the request."""
        ...


@runtime_checkable
class OAuth2TokenRequest(OAuth2APIRequest, APIRequest[Mapping[str, Any]], APIRequestBody, APIParsingContext, Protocol):
    """Protocol for token-exchange requests that return token payloads."""

    @property
    def discovery_configuration(self) -> OpenIdConfiguration | OAuthAuthorizationServer:
        """Discovery configuration for resolving the token endpoint."""
        ...

    @property
    def client_configuration(self) -> OAuth2ClientConfiguration:
        """OAuth2 client configuration used for token context creation."""
        ...

    @property
    def token_validator_context(self) -> AuthenticationContext:
        """Validation context used when verifying ID tokens."""
        ...

    def parse_error(self, data: Mapping[str, Any]) -> Exception | None:
        """Optional hook for parsing OAuth2 error responses."""
        ...


class OAuth2TokenRequestDefaults(APIRequestBodyMixin, OAuth2TokenRequest):
    """Default behaviors for token requests (endpoint, method, content types)."""

    @property
    def discovery_configuration(self) -> OpenIdConfiguration | OAuthAuthorizationServer:
        """Discovery configuration for resolving endpoints.

        Defaults to the OpenID configuration when available for backward compatibility.
        """
        if hasattr(self, "openid_configuration"):
            return self.openid_configuration
        if hasattr(self, "oauth_authorization_server"):
            return self.oauth_authorization_server
        raise AttributeError("discovery_configuration is required")

    @property
    def url(self) -> str:
        """Token endpoint resolved from discovery configuration."""
        return self.discovery_configuration.token_endpoint

    @property
    def http_method(self) -> APIRequestMethod:
        """Token requests use POST."""
        return APIRequestMethod.POST

    @property
    def content_type(self) -> APIContentType | None:
        """Token requests are form-url-encoded."""
        return APIContentType.FORM_URLENCODED

    @property
    def accepts_type(self) -> APIContentType | None:
        """Token responses are JSON."""
        return APIContentType.JSON

    def parse_error(self, data: Mapping[str, Any]) -> Exception | None:
        """Parse standard OAuth2 error fields when present."""
        if not data.get("error"):
            return None
        return OAuth2Error.from_response(data)
