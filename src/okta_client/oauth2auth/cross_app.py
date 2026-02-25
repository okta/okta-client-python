# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

"""Cross-App Authorization Flow using Identity Assertion Authorization Grant (ID-JAG).

This module implements a two-step convenience flow that wraps
:class:`TokenExchangeFlow` and :class:`JWTBearerFlow` to
perform the ID-JAG cross-application authorization exchange:

1. **start** — exchange a user ID token or access token for an ID-JAG via
   RFC 8693 token exchange.
2. **resume** — exchange the ID-JAG for a resource-server access token via
   RFC 7523 JWT bearer grant.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any, Literal, Protocol, runtime_checkable
from urllib.parse import urlparse

from okta_client.authfoundation import (
    AuthenticationListener,
    BaseAuthenticationFlow,
    KeyProvider,
    OAuth2Client,
    OAuth2ClientConfiguration,
    RequestValue,
    Token,
)
from okta_client.authfoundation.authentication import AuthenticationContext
from okta_client.authfoundation.oauth2.client_authorization import (
    ClientAssertionAuthorization,
)
from okta_client.authfoundation.oauth2.jwt_bearer_claims import JWTBearerClaims

from .jwt_bearer import JWTBearerFlow
from .token_exchange import (
    TokenExchangeFlow,
    TokenType,
)

# ---------------------------------------------------------------------------
# CrossAppAccessTarget
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CrossAppAccessTarget:
    """Describes the target resource authorization server for cross-app exchange.

    Encapsulates the resolved issuer URL so that additional target-specific
    settings can be added in the future without changing the
    :class:`CrossAppAccessFlow` constructor signature.
    """

    issuer: str
    """Full issuer URL of the target authorization server
    (e.g. ``"https://example.okta.com/oauth2/my-auth-server"``)."""


# ---------------------------------------------------------------------------
# CrossAppAccessContext
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CrossAppAccessContext(AuthenticationContext):
    """Per-session context for the Cross-App Authorization flow.

    Captures the ID-JAG produced during ``start()`` and the exchange result
    so that ``resume()`` can continue the exchange without the caller
    having to thread state manually.
    """

    id_jag_token: Token | None = None
    exchange_result: CrossAppExchangeResult | None = None

    _additional_parameters: Mapping[str, RequestValue] | None = None

    @property
    def acr_values(self) -> list[str] | None:
        return None

    @property
    def persist_values(self) -> Mapping[str, str] | None:
        return None

    @property
    def additional_parameters(self) -> Mapping[str, RequestValue] | None:
        return self._additional_parameters

    def parameters(self, category: Any) -> Mapping[str, RequestValue] | None:
        return self._additional_parameters or None


# ---------------------------------------------------------------------------
# CrossAppExchangeResult
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CrossAppExchangeResult:
    """Result from the token-exchange step of the cross-app flow.

    Returned by :meth:`CrossAppAccessFlow.start`.

    When :attr:`resume_assertion_claims` is ``None``, the flow can
    automatically generate the client assertion for ``resume()`` — no
    developer intervention required.

    When :attr:`resume_assertion_claims` is populated, the developer must
    sign these claims externally and pass the resulting JWT to
    ``resume(client_assertion=...)`` or supply a ``key_provider`` so the
    flow can sign them: ``resume(key_provider=my_provider)``.  This only
    occurs when the original client uses a pre-built assertion string
    without a :class:`KeyProvider`.
    """

    resume_assertion_claims: JWTBearerClaims | None = None
    """Claims the developer must sign for ``resume()`` when no key
    provider is available, or ``None`` when ``resume()`` handles
    authentication automatically."""


# ---------------------------------------------------------------------------
# CrossAppAccessFlowListener
# ---------------------------------------------------------------------------


@runtime_checkable
class CrossAppAccessFlowListener(AuthenticationListener, Protocol):
    """Extended listener for Cross-App Authorization flow events.

    Extends :class:`AuthenticationListener` with ID-JAG-specific
    lifecycle callbacks.
    """

    def will_exchange_token_for_id_jag(
        self,
        flow: CrossAppAccessFlow,
        subject_token_type: str,
    ) -> None:
        """Called before the token exchange request for an ID-JAG is sent.

        Args:
            flow: The running flow instance.
            subject_token_type: The RFC 8693 subject token type being exchanged
                (e.g. ``"id_token"`` or ``"access_token"``).
        """
        ...

    def did_exchange_token_for_id_jag(
        self,
        flow: CrossAppAccessFlow,
        id_jag_token: Token,
    ) -> None:
        """Called after an ID-JAG token has been received from the token exchange.

        Args:
            flow: The running flow instance.
            id_jag_token: The ID-JAG :class:`Token` received from the exchange.
        """
        ...

    def will_exchange_id_jag_for_access_token(
        self,
        flow: CrossAppAccessFlow,
        id_jag_token: Token,
    ) -> None:
        """Called before the ID-JAG is submitted via JWT bearer grant.

        Args:
            flow: The running flow instance.
            id_jag_token: The ID-JAG :class:`Token` being exchanged.
        """
        ...

    def did_exchange_id_jag_for_access_token(
        self,
        flow: CrossAppAccessFlow,
        access_token: Token,
    ) -> None:
        """Called after the resource-server access token has been received.

        Args:
            flow: The running flow instance.
            access_token: The resource-server :class:`Token`.
        """
        ...


# ---------------------------------------------------------------------------
# CrossAppAccessFlow
# ---------------------------------------------------------------------------


class CrossAppAccessFlow(BaseAuthenticationFlow[CrossAppAccessContext]):
    """Convenience flow combining Token Exchange and JWT Bearer for ID-JAG.

    The target authorization server is resolved at construction time so that
    the JWT bearer sub-flow is fully configured up front.  Supply either a
    :class:`CrossAppAccessTarget` or the convenience
    *target_authorization_server_id* shorthand.

    The flow automatically handles client authentication for the
    ``resume()`` step in the common case (key-provider-based assertion or
    client-secret auth).  When the original client uses a pre-built
    assertion string without a key provider, ``start()`` returns a
    :class:`CrossAppExchangeResult` whose
    :attr:`~CrossAppExchangeResult.resume_assertion_claims` tells the
    developer which claims to sign.

    Usage::

        # Common case — key-provider auth, fully automatic
        flow = CrossAppAccessFlow(client=web_client, target=target)
        result = await flow.start(token=id_token, audience=resource_issuer)
        # result.resume_assertion_claims is None → just call resume()
        access_token = await flow.resume()

        # Pre-built assertion — developer signs the claims
        result = await flow.start(token=id_token, audience=resource_issuer)
        if result.resume_assertion_claims:
            signed = my_signer.sign(result.resume_assertion_claims.to_claims())
            access_token = await flow.resume(client_assertion=signed)
    """

    def __init__(
        self,
        client: OAuth2Client,
        *,
        target: CrossAppAccessTarget | None = None,
        target_authorization_server_id: str | None = None,
        additional_parameters: Mapping[str, RequestValue] | None = None,
    ) -> None:
        super().__init__(additional_parameters=additional_parameters)
        self._client = client

        # Resolve the target authorization server for the JWT bearer step
        self._target = self._resolve_target(target, target_authorization_server_id)

        self._token_exchange_flow = TokenExchangeFlow(client=client)

        # Build a resource-server client for the JWT bearer flow.
        # client_authorization is left as None — it will be configured
        # during start() once the target token_endpoint is known.
        resource_client = self._build_resource_client(self._target.issuer)
        self._jwt_bearer_flow = JWTBearerFlow(client=resource_client)

    # -- Immutable sub-flow accessors ---------------------------------------

    @property
    def token_exchange_flow(self) -> TokenExchangeFlow:
        """The underlying token-exchange flow (read-only).

        Callers may add themselves as listeners on this flow if they need
        fine-grained token-exchange events.
        """
        return self._token_exchange_flow

    @property
    def jwt_bearer_flow(self) -> JWTBearerFlow:
        """The underlying JWT bearer flow (read-only).

        Callers may add themselves as listeners on this flow if they need
        fine-grained JWT bearer events.
        """
        return self._jwt_bearer_flow

    @property
    def target(self) -> CrossAppAccessTarget:
        """The resolved target resource authorization server configuration."""
        return self._target

    # -- start (Step 1) -----------------------------------------------------

    async def start(
        self,
        *,
        token: str,
        audience: str | None = None,
        scope: Sequence[str] | None = None,
        token_type: Literal["id_token", "access_token"] = "id_token",
        context: CrossAppAccessContext | None = None,
    ) -> CrossAppExchangeResult:
        """Exchange a user token for an ID-JAG via RFC 8693 token exchange.

        Runs the token exchange and the target metadata discovery in
        parallel so that ``resume()`` has the information it needs to
        construct a correctly-audienced client assertion.

        Args:
            token: The subject token (ID token or access token) to exchange.
            audience: Target audience for the ID-JAG.  Defaults to
                :attr:`target.issuer <CrossAppAccessTarget.issuer>`
                when not supplied.
            scope: Optional scopes to request on the ID-JAG.
            token_type: Whether *token* is an ``"id_token"`` (default) or
                ``"access_token"``.
            context: Optional context overrides.

        Returns:
            A :class:`CrossAppExchangeResult`.  When
            :attr:`~CrossAppExchangeResult.resume_assertion_claims` is
            ``None``, call ``resume()`` with no arguments.  Otherwise sign
            those claims and pass ``client_assertion=`` or
            ``key_provider=`` to ``resume()``.
        """
        await self._begin(context)
        ctx = context or CrossAppAccessContext()
        self._update_context(ctx)

        # Default audience to the target issuer when not explicitly provided.
        if audience is None:
            audience = self._target.issuer

        try:
            # Map the friendly string to a TokenType enum
            subject_token_type = (
                TokenType.ID_TOKEN if token_type == "id_token" else TokenType.ACCESS_TOKEN
            )

            # Notify listeners
            for listener in self.listeners:
                if isinstance(listener, CrossAppAccessFlowListener):
                    listener.will_exchange_token_for_id_jag(self, token_type)

            # Run the token exchange and target metadata discovery in parallel
            exchange_task = asyncio.ensure_future(
                self._token_exchange_flow.start(
                    subject_token=token,
                    subject_token_type=subject_token_type,
                    audience=audience,
                    scope=scope,
                    requested_token_type=TokenType.ID_JAG,
                )
            )
            metadata_task = asyncio.ensure_future(
                self._jwt_bearer_flow.client.fetch_oauth_server_metadata()
            )

            id_jag_token = await exchange_task
            target_metadata = await metadata_task

            # Notify listeners
            for listener in self.listeners:
                if isinstance(listener, CrossAppAccessFlowListener):
                    listener.did_exchange_token_for_id_jag(self, id_jag_token)

            # Resolve the resource client auth for resume()
            target_token_endpoint = target_metadata.token_endpoint
            exchange_result = self._resolve_resource_client_auth(target_token_endpoint)

            # Store the ID-JAG and exchange result in the context
            self._update_context(replace(
                ctx,
                id_jag_token=id_jag_token,
                exchange_result=exchange_result,
            ))

            return exchange_result

        except Exception as error:
            self._fail(error)
            raise

    # -- resume (Step 2) ----------------------------------------------------

    async def resume(
        self,
        *,
        client_assertion: str | None = None,
        key_provider: KeyProvider | None = None,
        context: CrossAppAccessContext | None = None,
    ) -> Token:
        """Exchange the ID-JAG for a resource-server access token via JWT bearer grant.

        In the common case (key-provider-based or secret-based client auth)
        call with no arguments — the flow handles everything.

        When ``start()`` returned a :class:`CrossAppExchangeResult` with
        :attr:`~CrossAppExchangeResult.resume_assertion_claims` populated,
        supply either:

        * ``client_assertion`` — a pre-signed JWT built from those claims, or
        * ``key_provider`` — a :class:`KeyProvider` the flow will use to
          sign the claims automatically.

        Args:
            client_assertion: A signed JWT client assertion for
                authenticating with the resource authorization server.
            key_provider: A :class:`KeyProvider` used to sign the
                ``resume_assertion_claims`` from the exchange result.
            context: Optional context overrides.  If the context carries an
                ``id_jag_token`` it takes precedence over the one stored
                during ``start()``.

        Returns:
            The resource-server :class:`Token`.

        Raises:
            RuntimeError: If no ID-JAG token is available (``start()`` was
                not called or did not succeed).
            ValueError: If ``resume_assertion_claims`` is set
                but neither ``client_assertion`` nor ``key_provider`` is
                provided.
        """
        # Resolve the ID-JAG from context
        effective_context = context or self._context
        id_jag_token: Token | None = None
        if effective_context is not None:
            id_jag_token = effective_context.id_jag_token

        if id_jag_token is None:
            raise RuntimeError(
                "No ID-JAG token available. Call start() first to obtain one."
            )

        # If the exchange result requires manual assertion, resolve it now
        exchange_result = effective_context.exchange_result if effective_context else None
        if (
            exchange_result is not None
            and exchange_result.resume_assertion_claims is not None
        ):
            self._apply_resume_client_auth(
                exchange_result.resume_assertion_claims,
                client_assertion=client_assertion,
                key_provider=key_provider,
            )

        try:
            # Notify listeners
            for listener in self.listeners:
                if isinstance(listener, CrossAppAccessFlowListener):
                    listener.will_exchange_id_jag_for_access_token(self, id_jag_token)

            access_token = await self._jwt_bearer_flow.start(
                assertion=id_jag_token.access_token,
            )

            # Notify listeners
            for listener in self.listeners:
                if isinstance(listener, CrossAppAccessFlowListener):
                    listener.did_exchange_id_jag_for_access_token(self, access_token)

            self._complete(access_token)
            return access_token

        except Exception as error:
            self._fail(error)
            raise

    # -- Helpers ------------------------------------------------------------

    def _resolve_target(
        self,
        target: CrossAppAccessTarget | None,
        target_authorization_server_id: str | None,
    ) -> CrossAppAccessTarget:
        """Resolve the target from an explicit object or a server ID shorthand."""
        if target is not None:
            return target
        if target_authorization_server_id:
            parsed = urlparse(self._client.configuration.issuer)
            base = f"{parsed.scheme}://{parsed.netloc}"
            issuer = f"{base}/oauth2/{target_authorization_server_id}"
            return CrossAppAccessTarget(issuer=issuer)
        raise ValueError(
            "Either 'target' or 'target_authorization_server_id' must be provided."
        )

    def _build_resource_client(self, issuer: str) -> OAuth2Client:
        """Create an :class:`OAuth2Client` targeting the given issuer.

        Inherits the network layer from the original client but does
        **not** copy ``client_authorization`` (configured later during
        ``start()``) or ``scope`` (the ID-JAG JWT bearer exchange must
        not include a scope parameter).
        """
        original = self._client.configuration
        resource_config = OAuth2ClientConfiguration(
            issuer=issuer,
            base_url=issuer,
            user_agent=original.user_agent,
            additional_http_headers=original.additional_http_headers,
            request_id_header=original.request_id_header,
            timeout=original.timeout,
        )
        return OAuth2Client(
            configuration=resource_config,
            network=self._client.network,
        )

    # -- Auth resolution ----------------------------------------------------

    def _resolve_resource_client_auth(
        self,
        target_token_endpoint: str,
    ) -> CrossAppExchangeResult:
        """Inspect the original client's auth and configure the resource client.

        Delegates to a path-specific method based on the original client's
        authorization type:

        1. **Key-provider available** → :meth:`_resolve_auto_sign_auth`
        2. **Pre-built assertion only** → :meth:`_resolve_prebuilt_assertion_auth`
        3. **Non-assertion auth** → :meth:`_resolve_non_assertion_auth`
        """
        original_auth = self._client.configuration.client_authorization

        if not isinstance(original_auth, ClientAssertionAuthorization):
            return self._resolve_non_assertion_auth(original_auth)

        if original_auth.assertion_claims is not None and original_auth.key_provider is not None:
            return self._resolve_auto_sign_auth(original_auth, target_token_endpoint)

        return self._resolve_prebuilt_assertion_auth(original_auth, target_token_endpoint)

    def _resolve_auto_sign_auth(
        self,
        original_auth: ClientAssertionAuthorization,
        target_token_endpoint: str,
    ) -> CrossAppExchangeResult:
        """Path 1: Clone claims with the target audience and sign automatically.

        The resource client gets a new :class:`ClientAssertionAuthorization`
        whose ``audience`` matches the target token endpoint.
        ``resume()`` works with no extra arguments.
        """
        assert original_auth.assertion_claims is not None  # guaranteed by caller
        new_claims = replace(original_auth.assertion_claims, audience=target_token_endpoint)
        new_auth = ClientAssertionAuthorization(
            assertion_claims=new_claims,
            key_provider=original_auth.key_provider,
            assertion_type=original_auth.assertion_type,
        )
        self._jwt_bearer_flow.client.update_client_authorization(new_auth)
        return CrossAppExchangeResult()

    def _resolve_prebuilt_assertion_auth(
        self,
        original_auth: ClientAssertionAuthorization,
        target_token_endpoint: str,
    ) -> CrossAppExchangeResult:
        """Path 2: Pre-built assertion — developer must sign the claims.

        Extracts issuer/subject from the existing claims or JWT, builds
        :class:`JWTBearerClaims` with the correct ``audience``, and returns
        them via :attr:`CrossAppExchangeResult.resume_assertion_claims`.
        """
        issuer = original_auth.client_id
        if not issuer and original_auth.assertion_claims:
            issuer = original_auth.assertion_claims.issuer

        expires_in = (
            original_auth.assertion_claims.expires_in
            if original_auth.assertion_claims
            else 300.0
        )

        resume_claims = JWTBearerClaims(
            issuer=issuer or "",
            subject=issuer or "",
            audience=target_token_endpoint,
            expires_in=expires_in,
        )
        return CrossAppExchangeResult(resume_assertion_claims=resume_claims)

    def _resolve_non_assertion_auth(
        self,
        original_auth: object,
    ) -> CrossAppExchangeResult:
        """Path 3: Non-assertion auth — copy to the resource client as-is.

        Works for :class:`ClientSecretAuthorization`,
        :class:`ClientIdAuthorization`, and ``None``.
        ``resume()`` works with no extra arguments.
        """
        from okta_client.authfoundation.oauth2.client_authorization import ClientAuthorization

        auth = original_auth if isinstance(original_auth, ClientAuthorization) else None
        self._jwt_bearer_flow.client.update_client_authorization(auth)
        return CrossAppExchangeResult()

    def _apply_resume_client_auth(
        self,
        resume_claims: JWTBearerClaims,
        *,
        client_assertion: str | None = None,
        key_provider: KeyProvider | None = None,
    ) -> None:
        """Apply the developer-supplied assertion to the resource client.

        Called by ``resume()`` when ``resume_assertion_claims`` was set.
        """
        if client_assertion:
            new_auth = ClientAssertionAuthorization(assertion=client_assertion)
        elif key_provider:
            new_auth = ClientAssertionAuthorization(
                assertion_claims=resume_claims,
                key_provider=key_provider,
            )
        else:
            raise ValueError(
                "The cross-app flow requires a client assertion for the "
                "resume step, but no key_provider is available to sign one "
                "automatically. Supply either 'client_assertion' (a signed "
                "JWT) or 'key_provider' to resume()."
            )
        self._jwt_bearer_flow.client.update_client_authorization(new_auth)

    def reset(self) -> None:
        """Reset flow state and sub-flow state."""
        super().reset()
        self._token_exchange_flow.reset()
        self._jwt_bearer_flow.reset()
