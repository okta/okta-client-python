# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

"""Authorization Code Flow (PKCE) with PAR support."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Protocol, runtime_checkable
from urllib.parse import quote, urlencode

from okta_client.authfoundation import (
    APIContentType,
    APIRequestBodyMixin,
    APIRequestMethod,
    AuthenticationContext,
    AuthenticationListener,
    BaseAPIRequest,
    BaseAuthenticationFlow,
    Codable,
    OAuth2APIRequestCategory,
    OAuth2Client,
    OAuth2ClientConfiguration,
    OAuth2TokenRequestDefaults,
    PKCEData,
    RequestValue,
    Token,
)
from okta_client.authfoundation.authentication import generate_pkce
from okta_client.authfoundation.oauth2.errors import OAuth2Error
from okta_client.authfoundation.oauth2.models import OpenIdConfiguration
from okta_client.authfoundation.oauth2.request_protocols import IDTokenValidatorContext
from okta_client.authfoundation.utils import serialize_parameters

from .utils import parse_redirect_uri

# ---------------------------------------------------------------------------
# Prompt Enum
# ---------------------------------------------------------------------------


class Prompt(str, Enum):
    """How the user is prompted to sign in."""

    NONE = "none"
    CONSENT = "consent"
    LOGIN = "login"
    LOGIN_AND_CONSENT = "login consent"


# ---------------------------------------------------------------------------
# AuthorizationCodeContext
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthorizationCodeContext(Codable, AuthenticationContext, IDTokenValidatorContext):
    """Per-session context for the Authorization Code flow.

    Implements both :class:`AuthenticationContext` (for parameter merging) and
    :class:`IDTokenValidatorContext` (for ID-token ``nonce`` / ``max_age`` validation).

    The context is **immutable** (frozen dataclass).  The flow updates it
    internally via :func:`dataclasses.replace` and
    :meth:`BaseAuthenticationFlow._update_context`.
    """

    pkce: PKCEData | None = field(default=None)
    nonce: str | None = field(default=None)  # type: ignore[assignment]
    max_age: float | None = None  # type: ignore[assignment]
    state: str = field(default_factory=lambda: str(uuid.uuid4()))

    acr_values: list[str] | None = None  # type: ignore[assignment]
    login_hint: str | None = None
    id_token_hint: str | None = None
    display: str | None = None
    prompt: Prompt | None = None
    ui_locales: list[str] | None = None
    claims_locales: list[str] | None = None
    pushed_authorization_request_enabled: bool = True

    authentication_url: str | None = None

    _additional_parameters: Mapping[str, RequestValue] | None = field(
        default=None, repr=False
    )

    def __post_init__(self) -> None:
        """Auto-generate PKCE and nonce when not provided."""
        if self.pkce is None:
            object.__setattr__(self, "pkce", generate_pkce())
        if self.nonce is None:
            object.__setattr__(self, "nonce", str(uuid.uuid4()))

    # -- AuthenticationContext -----------------------------------------------

    @property
    def persist_values(self) -> Mapping[str, str] | None:
        """No values to persist by default."""
        return None

    @property
    def additional_parameters(self) -> Mapping[str, RequestValue] | None:
        """Return caller-supplied additional parameters."""
        return self._additional_parameters

    def parameters(self, category: OAuth2APIRequestCategory) -> Mapping[str, RequestValue] | None:
        """Return merged parameters for the given request category."""
        result: dict[str, RequestValue] = dict(self._additional_parameters or {})

        if category == OAuth2APIRequestCategory.AUTHORIZATION:
            result["response_type"] = "code"
            result["state"] = self.state
            if self.nonce:
                result["nonce"] = self.nonce
            if self.max_age is not None:
                result["max_age"] = str(int(self.max_age))
            if self.acr_values:
                result["acr_values"] = " ".join(self.acr_values)
            if self.pkce:
                result["code_challenge"] = self.pkce.code_challenge
                result["code_challenge_method"] = self.pkce.code_challenge_method
            if self.login_hint:
                result["login_hint"] = self.login_hint
            if self.id_token_hint:
                result["id_token_hint"] = self.id_token_hint
            if self.display:
                result["display"] = self.display
            if self.prompt is not None:
                result["prompt"] = self.prompt.value
            if self.ui_locales:
                result["ui_locales"] = " ".join(self.ui_locales)
            if self.claims_locales:
                result["claims_locales"] = " ".join(self.claims_locales)
        elif category == OAuth2APIRequestCategory.TOKEN:
            if self.pkce:
                result["code_verifier"] = self.pkce.code_verifier
        return result or None

    # -- Codable --------------------------------------------------------------

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AuthorizationCodeContext:
        """Reconstruct an AuthorizationCodeContext from a plain dict."""
        pkce_data = data.get("pkce")
        pkce: PKCEData | None = None
        if isinstance(pkce_data, Mapping):
            pkce = PKCEData(
                code_verifier=pkce_data["code_verifier"],
                code_challenge=pkce_data["code_challenge"],
                code_challenge_method=pkce_data.get("code_challenge_method", "S256"),
            )

        prompt_value = data.get("prompt")
        prompt = Prompt(prompt_value) if prompt_value is not None else None

        return cls(
            pkce=pkce,
            nonce=data.get("nonce"),
            max_age=data.get("max_age"),
            state=data.get("state", str(uuid.uuid4())),
            acr_values=data.get("acr_values"),
            login_hint=data.get("login_hint"),
            id_token_hint=data.get("id_token_hint"),
            display=data.get("display"),
            prompt=prompt,
            ui_locales=data.get("ui_locales"),
            claims_locales=data.get("claims_locales"),
            pushed_authorization_request_enabled=data.get("pushed_authorization_request_enabled", True),
            authentication_url=data.get("authentication_url"),
            _additional_parameters=data.get("_additional_parameters"),
        )


# ---------------------------------------------------------------------------
# AuthorizationCodeFlowListener
# ---------------------------------------------------------------------------


@runtime_checkable
class AuthorizationCodeFlowListener(AuthenticationListener, Protocol):
    """Extended listener for authorization code flow events."""

    def authentication_customize_url(
        self,
        flow: AuthorizationCodeFlow,
        url_parts: dict[str, str],
    ) -> dict[str, str]:
        """Called before the authorize URL is finalized.

        Receives the merged and serialized query parameters as a mutable dict.
        Return the (possibly modified) dict that will be used for final URL
        construction.
        """
        ...

    def authentication_should_authenticate(
        self,
        flow: AuthorizationCodeFlow,
        url: str,
    ) -> None:
        """Called when the authorization URL has been created.

        The listener can log, record, or present this URL to the user.
        """
        ...


# ---------------------------------------------------------------------------
# PushedAuthorizationRequest  (non-token request, POSTed to PAR endpoint)
# ---------------------------------------------------------------------------


@dataclass
class PushedAuthorizationRequest(BaseAPIRequest, APIRequestBodyMixin):
    """POST merged authorization parameters to the PAR endpoint.

    Response is a JSON object with ``request_uri`` and ``expires_in``.
    This is sent via :meth:`OAuth2Client.send`, not ``exchange()``.
    """

    _url: str
    _client_configuration: OAuth2ClientConfiguration
    additional_parameters: Mapping[str, RequestValue] | None
    context: AuthorizationCodeContext

    @property
    def url(self) -> str:
        """PAR endpoint URL."""
        return self._url

    @property
    def http_method(self) -> APIRequestMethod:
        """PAR requests use POST."""
        return APIRequestMethod.POST

    @property
    def content_type(self) -> APIContentType | None:
        """PAR requests are form-urlencoded."""
        return APIContentType.FORM_URLENCODED

    @property
    def accepts_type(self) -> APIContentType | None:
        """PAR responses are JSON."""
        return APIContentType.JSON

    @property
    def query(self) -> Mapping[str, RequestValue] | None:
        """No query parameters for PAR requests."""
        return None

    @property
    def headers(self) -> Mapping[str, RequestValue] | None:
        """No extra headers for PAR requests."""
        return None

    @property
    def authorization(self) -> None:
        """No authorization header for PAR requests."""
        return None

    @property
    def timeout(self) -> float | None:
        """No custom timeout."""
        return None

    @property
    def body_parameters(self) -> Mapping[str, RequestValue]:
        """Merge parameters: flow additional → config(AUTHORIZATION) → context(AUTHORIZATION)."""
        parameters: dict[str, RequestValue] = {}
        if self.additional_parameters:
            parameters.update(self.additional_parameters)
        config_parameters = self._client_configuration.parameters(OAuth2APIRequestCategory.AUTHORIZATION)
        if config_parameters:
            parameters.update(config_parameters)
        context_parameters = self.context.parameters(OAuth2APIRequestCategory.AUTHORIZATION)
        if context_parameters:
            parameters.update(context_parameters)
        return parameters


# ---------------------------------------------------------------------------
# AuthorizationCodeTokenRequest
# ---------------------------------------------------------------------------


@dataclass
class AuthorizationCodeTokenRequest(OAuth2TokenRequestDefaults):
    """Token request for the authorization_code grant type."""

    _openid_configuration: OpenIdConfiguration
    _client_configuration: OAuth2ClientConfiguration
    additional_parameters: Mapping[str, RequestValue] | None
    context: AuthorizationCodeContext
    authorization_code: str

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
        """Return the context itself — provides ``nonce`` and ``max_age`` for ID token validation."""
        return self.context

    @property
    def query(self) -> Mapping[str, RequestValue] | None:
        """No query parameters for token requests."""
        return None

    @property
    def headers(self) -> Mapping[str, RequestValue] | None:
        """No extra headers for token requests."""
        return None

    @property
    def authorization(self) -> None:
        """No authorization header for authorization_code token requests."""
        return None

    @property
    def timeout(self) -> float | None:
        """No custom timeout."""
        return None

    @property
    def body_parameters(self) -> Mapping[str, RequestValue]:
        """Build parameters using merge order: additional → config(TOKEN) → context(TOKEN) → grant fields."""
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
                "grant_type": "authorization_code",
                "code": self.authorization_code,
            }
        )
        return parameters


# ---------------------------------------------------------------------------
# AuthorizationCodeFlow
# ---------------------------------------------------------------------------


class AuthorizationCodeFlow(BaseAuthenticationFlow[AuthorizationCodeContext]):
    """Authorization Code + PKCE authentication flow with PAR support.

    Two-phase flow:

    1. :meth:`start` builds an authorization URL (optionally via PAR)
       that the caller presents in a browser.
    2. :meth:`resume` accepts the redirect URI containing the authorization
       code, exchanges it for tokens, and returns a :class:`Token`.
    """

    def __init__(
        self,
        client: OAuth2Client,
        additional_parameters: Mapping[str, RequestValue] | None = None,
    ) -> None:
        """Create an Authorization Code flow.

        Raises:
            OAuth2Error: If ``client.configuration.redirect_uri`` is not set.
        """
        if not client.configuration.redirect_uri:
            raise OAuth2Error(
                error="redirect_uri_required",
                error_description="redirect_uri must be set in the client configuration for the authorization code flow.",
            )
        super().__init__(additional_parameters=additional_parameters)
        self.client = client

    async def start(
        self,
        *,
        context: AuthorizationCodeContext | None = None,
    ) -> str:
        """Build and return the authorization URL.

        Steps:
        1. Begin the flow (acquires lock, sets AUTHENTICATING state).
        2. Fetch OpenID configuration.
        3. Validate ``authorization_code`` grant is supported.
        4. If PAR enabled and server advertises the PAR endpoint, POST to PAR
           and build a minimal authorize URL with ``client_id`` + ``request_uri``.
        5. Otherwise build a full authorize URL with all merged query parameters.
        6. Invoke listener ``authentication_customize_url`` hooks.
        7. Finalize URL string.
        8. Update context with ``authentication_url`` via ``_update_context()``.
        9. Invoke listener ``authentication_should_authenticate`` hooks.
        10. Return the URL string.
        """
        await self._begin(context)
        ctx = context or AuthorizationCodeContext()
        self._update_context(ctx)
        try:
            openid_configuration = await self.client.fetch_openid_configuration()
            _ensure_authorization_code_grant_supported(openid_configuration)

            # Attempt PAR if enabled and advertised
            par_url: str | None = None
            if (
                ctx.pushed_authorization_request_enabled
                and openid_configuration.pushed_authorization_request_endpoint
            ):
                par_url = await self._send_par(openid_configuration, ctx)

            if par_url is not None:
                url_parts = _parse_query_string(par_url)
            else:
                url_parts = self._build_authorization_params(openid_configuration, ctx)

            # Let listeners customize the URL query parameters
            for listener in self.listeners:
                if isinstance(listener, AuthorizationCodeFlowListener):
                    url_parts = listener.authentication_customize_url(self, url_parts)

            # Build the final URL
            base_url = openid_configuration.authorization_endpoint
            final_url = f"{base_url}?{urlencode(url_parts, quote_via=quote)}" if url_parts else base_url

            # Update context with the authentication URL
            ctx = replace(ctx, authentication_url=final_url)
            self._update_context(ctx)

            # Notify listeners
            for listener in self.listeners:
                if isinstance(listener, AuthorizationCodeFlowListener):
                    listener.authentication_should_authenticate(self, final_url)

            return final_url
        except Exception as error:
            self._fail(error)
            raise

    async def resume(self, redirect_uri: str) -> Token:
        """Exchange the authorization code from the redirect URI for a Token.

        Steps:
        1. Validate the flow has a context (state == AUTHENTICATING).
        2. Parse and validate the redirect URI.
        3. Build an ``AuthorizationCodeTokenRequest`` with merged parameters.
        4. Exchange via ``client.exchange(request)`` → Token.
        5. Complete the flow and return the token.
        """
        ctx = self.context
        if ctx is None:
            raise OAuth2Error(
                error="invalid_context",
                error_description="Cannot resume: no active authentication context. Call start() first.",
            )
        try:
            config_redirect_uri = self.client.configuration.redirect_uri
            assert config_redirect_uri is not None  # validated in __init__
            code = parse_redirect_uri(
                redirect_uri,
                expected_state=ctx.state,
                expected_redirect_uri=config_redirect_uri,
            )

            openid_configuration = await self.client.fetch_openid_configuration()
            request = AuthorizationCodeTokenRequest(
                _openid_configuration=openid_configuration,
                _client_configuration=self.client.configuration,
                additional_parameters=self.additional_parameters,
                context=ctx,
                authorization_code=code,
            )
            response = await self.client.exchange(request)
            self._complete(response.result)
            return response.result
        except Exception as error:
            self._fail(error)
            raise

    # -- Private helpers -------------------------------------------------

    async def _send_par(
        self,
        openid_configuration: OpenIdConfiguration,
        ctx: AuthorizationCodeContext,
    ) -> str | None:
        """POST to the PAR endpoint and return a minimal authorize URL, or None on failure."""
        par_endpoint = openid_configuration.pushed_authorization_request_endpoint
        if not par_endpoint:
            return None
        try:
            request = PushedAuthorizationRequest(
                _url=par_endpoint,
                _client_configuration=self.client.configuration,
                additional_parameters=self.additional_parameters,
                context=ctx,
            )
            response = await asyncio.to_thread(self.client.send, request)
            result = response.result
            if not isinstance(result, Mapping):
                return None
            request_uri = result.get("request_uri")
            if not request_uri:
                return None

            # Build minimal authorize URL: client_id + request_uri only
            client_id = self.client.configuration.client_id
            if not client_id:
                raise OAuth2Error("Missing client_id in client configuration when building PAR authorize URL.")

            params = {
                "client_id": client_id,
                "request_uri": str(request_uri),
            }
            base_url = openid_configuration.authorization_endpoint
            return f"{base_url}?{urlencode(params, quote_via=quote)}"
        except OAuth2Error:
            # Configuration errors should surface clearly to the caller.
            raise
        except Exception:
            # PAR failure is non-fatal; fall back to full authorize URL
            return None

    def _build_authorization_params(
        self,
        openid_configuration: OpenIdConfiguration,
        ctx: AuthorizationCodeContext,
    ) -> dict[str, str]:
        """Merge parameters and serialize them for the authorize URL query string."""
        parameters: dict[str, RequestValue] = {}
        if self.additional_parameters:
            parameters.update(self.additional_parameters)
        config_parameters = self.client.configuration.parameters(OAuth2APIRequestCategory.AUTHORIZATION)
        if config_parameters:
            parameters.update(config_parameters)
        context_parameters = ctx.parameters(OAuth2APIRequestCategory.AUTHORIZATION)
        if context_parameters:
            parameters.update(context_parameters)

        # Ensure client_id is always present for authorization requests.
        client_id = parameters.get("client_id") or self.client.configuration.client_id
        if not client_id:
            raise OAuth2Error(
                "client_id is required for authorization requests and could not be resolved"
            )
        parameters["client_id"] = client_id
        return serialize_parameters(parameters)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ensure_authorization_code_grant_supported(openid_configuration: OpenIdConfiguration) -> None:
    """Validate the server advertises support for the authorization_code grant."""
    if openid_configuration.grant_types_supported is None:
        raise ValueError("Authorization code flow is not supported by the server")
    if "authorization_code" not in openid_configuration.grant_types_supported:
        raise ValueError("Authorization code flow is not supported by the server")


def _parse_query_string(url: str) -> dict[str, str]:
    """Parse query string from a URL into a flat dict (first value for each key)."""
    from urllib.parse import parse_qs, urlparse
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    return {k: v[0] for k, v in qs.items()}
