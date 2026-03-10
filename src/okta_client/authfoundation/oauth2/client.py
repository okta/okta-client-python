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

import asyncio
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from okta_client.authfoundation.oauth2.requests.oauth_authorization_server import OAuthAuthorizationServerRequest
from okta_client.authfoundation.utils import coerce_optional_sequence, coerce_optional_str

from ..coalesced_result import CoalescedResult
from ..networking import APIClient, APIClientListener, APIResponse, NetworkInterface
from ..time_coordinator import get_time_coordinator
from ..user_agent import sdk_user_agent
from .client_authorization import ClientAuthorization
from .config import OAuth2ClientConfiguration
from .errors import OAuth2Error
from .jwt_context import JWTValidationContext
from .models import JWKS, OAuthAuthorizationServer, OpenIdConfiguration, TokenInfo, UserInfo
from .refresh_token import RefreshTokenFlow, RefreshTokenRequest
from .requests import (
    IntrospectRequest,
    JWKSRequest,
    OAuth2TokenRequest,
    OpenIDConfigurationRequest,
    RevokeRequest,
    UserInfoRequest,
)

if TYPE_CHECKING:
    from ..token import Token


@runtime_checkable
class OAuth2ClientListener(APIClientListener, Protocol):
    """Listener for OAuth2-specific lifecycle events."""

    def will_refresh_token(self, client: OAuth2Client, token: Token) -> None:
        """Called before a token refresh begins."""
        ...

    def did_refresh_token(
        self,
        client: OAuth2Client,
        token: Token,
        refreshed_token: Token | None,
    ) -> None:
        """Called after a token refresh completes."""
        ...


class OAuth2Client(APIClient):
    """OAuth 2.0-aware HTTP client that extends :class:`APIClient`.

    Args:
        configuration: The OAuth2 client configuration.
        network: Optional transport implementation. When ``None``, falls back
            to :meth:`get_default_network` if set, otherwise
            :class:`DefaultNetworkInterface`.
        time_provider: Optional callable returning the current time as a float.
    """

    _default_network: NetworkInterface | None = None
    _default_network_lock: threading.Lock = threading.Lock()

    @classmethod
    def get_default_network(cls) -> NetworkInterface | None:
        """Return the current class-level default network interface.

        Thread-safe.  Returns ``None`` when no default has been set.
        """
        with cls._default_network_lock:
            return cls._default_network

    @classmethod
    def set_default_network(cls, network: NetworkInterface | None) -> None:
        """Set (or clear) the class-level default network interface.

        Only affects newly-created instances; existing instances retain
        their current network interface.  Pass ``None`` to revert to the
        platform default (:class:`DefaultNetworkInterface`).

        Thread-safe.
        """
        with cls._default_network_lock:
            cls._default_network = network

    def __init__(
        self,
        configuration: OAuth2ClientConfiguration,
        network: NetworkInterface | None = None,
        time_provider: Callable[[], float] | None = None,
    ) -> None:
        resolved_network = network or self.get_default_network() or None
        super().__init__(configuration=configuration, network=resolved_network)
        self.configuration = configuration
        self._sdk_user_agent = sdk_user_agent()
        self._time_provider = time_provider or time.time
        self._openid_configuration_fetch = CoalescedResult[OpenIdConfiguration](
            ttl=self.configuration.metadata_cache_ttl,
            time_provider=self._time_provider,
        )
        self._oauth_server_metadata_fetch = CoalescedResult[OAuthAuthorizationServer](
            ttl=self.configuration.metadata_cache_ttl,
            time_provider=self._time_provider,
        )
        self._jwks_fetch = CoalescedResult[JWKS](
            ttl=0,
            time_provider=self._time_provider,
        )
        self._refresh_lock = asyncio.Lock()
        self._refresh_actions: dict[tuple[str, tuple[str, ...] | None], CoalescedResult[Token]] = {}

    def _build_headers(self, request: Any) -> Mapping[str, str]:
        """Append SDK metadata to the User-Agent header."""
        headers = dict(super()._build_headers(request))
        base_ua = headers.get("User-Agent", "")
        headers["User-Agent"] = f"{base_ua} {self._sdk_user_agent}".strip()
        return headers

    def update_client_authorization(self, authorization: ClientAuthorization | None) -> None:
        """Replace the client's :class:`ClientAuthorization` strategy.

        Validates that the new authorization is semantically compatible
        with the existing one (e.g. the ``client_id`` must not change) so
        that the client does not silently switch identity mid-session.

        Args:
            authorization: The new :class:`ClientAuthorization` to use, or
                ``None`` to clear it.

        Raises:
            ValueError: If the new authorization has a different
                ``client_id`` than the current one (when both are set).
            TypeError: If the new authorization is a different type than
                the current one (when both are set).
        """
        existing = self.configuration.client_authorization
        existing_id = existing.client_id if existing is not None else None
        new_id = authorization.client_id if authorization is not None else None
        if existing is not None and authorization is not None and type(existing) is not type(authorization):
            raise TypeError(
                f"Cannot change client authorization type from "
                f"{type(existing).__name__!r} to "
                f"{type(authorization).__name__!r}. "
                f"Create a new OAuth2Client instead."
            )
        if existing_id is not None and new_id is not None and existing_id != new_id:
            raise ValueError(
                f"Cannot change client_id from {existing_id!r} to "
                f"{new_id!r}. Create a new OAuth2Client instead."
            )
        object.__setattr__(self.configuration, "client_authorization", authorization)

    async def fetch_openid_configuration(self, *, reset: bool = False) -> OpenIdConfiguration:
        """Fetch and cache OpenID discovery configuration.

        Cache policy:
        - ttl > 0: cache for ttl seconds (default 3600)
        - ttl == 0: no caching (always fetch)
        - ttl is None: cache indefinitely
        """
        async def operation() -> OpenIdConfiguration:
            request = OpenIDConfigurationRequest(
                issuer=self.configuration.issuer,
                client_id=self.configuration.client_id,
            )
            response = await asyncio.to_thread(self.send, request)
            discovery = OpenIdConfiguration.from_json(_ensure_mapping(response.result))
            configured = self.configuration.issuer.rstrip("/")

            discovery_issuer = discovery.issuer
            if discovery_issuer is None:
                raise ValueError("Discovery document is missing required 'issuer' value")

            discovery_issuer_normalized = discovery_issuer.rstrip("/")
            if not discovery_issuer_normalized:
                raise ValueError("Discovery document contains empty 'issuer' value")

            if discovery_issuer_normalized != configured:
                raise ValueError(
                    f"Discovery issuer mismatch: expected {configured!r}, got {discovery_issuer!r}"
                )
            return discovery

        return await self._openid_configuration_fetch.perform(operation=operation, reset=reset)

    async def fetch_oauth_server_metadata(self, *, reset: bool = False) -> OAuthAuthorizationServer:
        """Fetch and cache OAuth authorization server metadata (cached by discovery configuration)."""
        async def operation() -> OAuthAuthorizationServer:
            request = OAuthAuthorizationServerRequest(issuer=self.configuration.issuer,
                                                      client_id=self.configuration.client_id)
            response = await asyncio.to_thread(self.send, request)
            metadata = OAuthAuthorizationServer.from_json(_ensure_mapping(response.result))
            configured = self.configuration.issuer.rstrip("/")
            if metadata.issuer.rstrip("/") != configured:
                raise ValueError(
                    f"Discovery issuer mismatch: expected {configured!r}, got {metadata.issuer!r}"
                )
            return metadata

        return await self._oauth_server_metadata_fetch.perform(operation=operation, reset=reset)

    def current_discovery_configuration(self) -> OpenIdConfiguration | OAuthAuthorizationServer | None:
        """Get the currently loaded discovery configuration, either OpenID or OAuth server metadata."""
        discovery_configuration = self._openid_configuration_fetch.value
        if discovery_configuration is None:
            discovery_configuration = self._oauth_server_metadata_fetch.value
        return discovery_configuration

    async def fetch_jwks(self, *, reset: bool = False) -> JWKS:
        """Fetch the JWKS for the issuer (cached by discovery configuration)."""
        async def operation() -> JWKS:
            discovery_configuration = self.current_discovery_configuration()

            # If the current discovery configuration doesn't have a jwks_uri, attempt to
            # fetch the OpenID configuration directly as a fallback to get the jwks_uri.
            #
            # This allows clients that only fetch the OAuth authorization server metadata
            # to still obtain the JWKS.
            if discovery_configuration is None or not getattr(discovery_configuration, "jwks_uri", None):
                discovery_configuration = await self.fetch_openid_configuration()
            request = JWKSRequest(discovery_configuration=discovery_configuration,
                                  client_id=self.configuration.client_id)
            response = await asyncio.to_thread(self.send, request)
            return JWKS.from_json(_ensure_mapping(response.result))

        return await self._jwks_fetch.perform(operation=operation, reset=reset)

    async def revoke(self, token: str, token_type_hint: str | None = None) -> None:
        """Revoke an access or refresh token."""
        openid_config = await self.fetch_openid_configuration()
        if not openid_config.revocation_endpoint:
            raise ValueError("revocation_endpoint is not available")
        request = RevokeRequest(
            url=openid_config.revocation_endpoint,
            token=token,
            token_type_hint=token_type_hint,
            client_id=self.configuration.client_id,
        )
        await asyncio.to_thread(self.send, request)

    async def introspect(self, token: str) -> TokenInfo:
        """Introspect a token and return token metadata."""
        openid_config = await self.fetch_openid_configuration()
        if not openid_config.introspection_endpoint:
            raise ValueError("introspection_endpoint is not available")
        request = IntrospectRequest(
            url=openid_config.introspection_endpoint,
            token=token,
            client_id=self.configuration.client_id,
        )
        response = await asyncio.to_thread(self.send, request)
        return TokenInfo(claims=_ensure_mapping(response.result))

    async def userinfo(self, token: Token) -> UserInfo:
        """Fetch the OIDC userinfo response using a Token."""
        openid_config = await self.fetch_openid_configuration()
        if not openid_config.userinfo_endpoint:
            raise ValueError("userinfo_endpoint is not available")
        request = UserInfoRequest(
            url=openid_config.userinfo_endpoint,
            authorization=token,
        )
        response = await asyncio.to_thread(self.send, request)
        return UserInfo(claims=_ensure_mapping(response.result))

    async def exchange(self, request: OAuth2TokenRequest) -> APIResponse[Token]:
        """Exchange a token request for a Token response with validation hooks."""
        from ..token import Token, TokenContext

        send_task = asyncio.create_task(asyncio.to_thread(self.send, request))
        jwks_task = asyncio.create_task(self.fetch_jwks())
        response = await send_task
        result = _ensure_mapping(response.result)
        _raise_for_oauth2_error(request, result, response)

        issued_at = get_time_coordinator().now()
        token_context = TokenContext(
            issuer=request.discovery_configuration.issuer or request.client_configuration.issuer,
            client_id=request.client_configuration.client_id,
            client_settings=(request.client_configuration.additional_parameters or None),
        )
        jwt_context = self._build_jwt_context(request)
        jwks = await jwks_task
        token = Token.from_response(
            result,
            context=token_context,
            issued_at=issued_at,
            jwks=jwks,
            jwt_context=jwt_context,
        )

        return APIResponse(
            result=token,
            status_code=response.status_code,
            headers=response.headers,
            request_id=response.request_id,
            rate_limit=response.rate_limit,
            links=response.links,
        )

    async def refresh(self, token: Token, scope: Sequence[str] | None = None) -> Token:
        """Refresh the supplied token using its refresh token."""
        from ..token import Token

        refresh_token = token.refresh_token
        if not refresh_token:
            raise OAuth2Error(
                error="missing_refresh_token",
                error_description="Token does not contain a refresh_token",
            )
        normalized_scope = coerce_optional_sequence(scope)
        refresh_key = (refresh_token, tuple(normalized_scope) if normalized_scope else None)
        async with self._refresh_lock:
            refresh_action = self._refresh_actions.get(refresh_key)
            if refresh_action is None:
                refresh_action = CoalescedResult[Token](ttl=0, time_provider=self._time_provider)
                self._refresh_actions[refresh_key] = refresh_action

        flow = RefreshTokenFlow(client=self)

        async def operation() -> Token:
            self._notify_will_refresh(token)
            try:
                refreshed = await flow.start(refresh_token, scope=scope)
            except Exception:
                self._notify_did_refresh(token, None)
                raise
            merged = refreshed.merge(token)
            self._notify_did_refresh(token, merged)
            return merged

        try:
            return await refresh_action.perform(operation=operation, reset=True)
        finally:
            async with self._refresh_lock:
                self._refresh_actions.pop(refresh_key, None)

    @staticmethod
    async def from_refresh_token(
        refresh_token: str,
        *,
        scope: Sequence[str] | None = None,
        client: OAuth2Client,
    ) -> Token:
        """Create a new Token from a refresh token using the provided client."""
        from okta_client.authfoundation.authentication import StandardAuthenticationContext

        openid_configuration = await client.fetch_openid_configuration()
        request = RefreshTokenRequest(
            _openid_configuration=openid_configuration,
            _client_configuration=client.configuration,
            additional_parameters=None,
            context=StandardAuthenticationContext(),
            refresh_token=refresh_token,
            scope=scope,
        )
        response = await client.exchange(request)
        return response.result

    @staticmethod
    def _build_jwt_context(
        request: OAuth2TokenRequest,
    ) -> JWTValidationContext:
        validator_context = getattr(request, "token_validator_context", None)
        issuer = request.client_configuration.issuer
        audience = request.client_configuration.client_id
        return JWTValidationContext(
            issuer=issuer,
            audience=audience,
            nonce=validator_context.nonce if validator_context else None,
            max_age=validator_context.max_age if validator_context else None,
        )

    def _notify_will_refresh(self, token: Token) -> None:
        for listener in self._listeners:
            if isinstance(listener, OAuth2ClientListener):
                listener.will_refresh_token(self, token)

    def _notify_did_refresh(self, token: Token, refreshed: Token | None) -> None:
        for listener in self._listeners:
            if isinstance(listener, OAuth2ClientListener):
                listener.did_refresh_token(self, token, refreshed)


def _ensure_mapping(result: Any) -> Mapping[str, Any]:
    if isinstance(result, Mapping):
        return result
    raise ValueError("Token response is not a JSON object")


def _raise_for_oauth2_error(
    request: OAuth2TokenRequest,
    result: Mapping[str, Any],
    response: APIResponse[Any],
) -> None:
    error = None
    if hasattr(request, "parse_error"):
        try:
            error = request.parse_error(result)
        except Exception:
            error = None
    if error is None and ("error" in result or response.status_code >= 400):
        error = OAuth2Error(
            error=str(result.get("error", "oauth2_error")),
            error_description=coerce_optional_str(result.get("error_description")),
            error_uri=coerce_optional_str(result.get("error_uri")),
            status_code=response.status_code,
            request_id=response.request_id,
        )
    if error is None:
        return
    raise error


def _build_jwt_context(
    request: OAuth2TokenRequest,
) -> JWTValidationContext:
    validator_context = getattr(request, "token_validator_context", None)
    issuer = request.discovery_configuration.issuer or request.client_configuration.issuer
    audience = request.client_configuration.client_id
    return JWTValidationContext(
        issuer=issuer,
        audience=audience,
        nonce=validator_context.nonce if validator_context else None,
        max_age=validator_context.max_age if validator_context else None,
    )
