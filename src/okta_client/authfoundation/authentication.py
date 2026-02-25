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
import hashlib
import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any, Generic, Protocol, TypeVar, cast, runtime_checkable

from .networking import ListenerCollection, RequestValue
from .oauth2.parameters import OAuth2APIRequestCategory
from .utils import base64url_encode

ContextT = TypeVar("ContextT", bound="AuthenticationContext")


class AuthenticationState(str, Enum):
    """Lifecycle states for authentication flows."""
    IDLE = "idle"
    AUTHENTICATING = "authenticating"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True)
class PKCEData:
    """PKCE values used by authorization code flows."""
    code_verifier: str
    code_challenge: str
    code_challenge_method: str = "S256"


def generate_pkce() -> PKCEData:
    """Generate a PKCE verifier/challenge pair using S256.

    - ``code_verifier``: 32 random bytes, base64url-encoded (no padding).
    - ``code_challenge``: SHA-256 hash of the verifier, base64url-encoded (no padding).
    """
    code_verifier = base64url_encode(os.urandom(32))
    code_challenge = base64url_encode(hashlib.sha256(code_verifier.encode("ascii")).digest())
    return PKCEData(
        code_verifier=code_verifier,
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )


@runtime_checkable
class AuthenticationContext(Protocol):
    """Protocol for per-session authentication context."""
    @property
    def acr_values(self) -> list[str] | None:
        """ACR values requested for the session."""
        ...

    @property
    def persist_values(self) -> Mapping[str, str] | None:
        """Values to persist into token context, if any."""
        ...

    @property
    def additional_parameters(self) -> Mapping[str, RequestValue] | None:
        """Additional parameters for the session."""
        ...

    def parameters(self, category: OAuth2APIRequestCategory) -> Mapping[str, RequestValue] | None:
        """Return OAuth2 parameters to include for the given request category."""
        ...


@runtime_checkable
class AuthenticationListener(Protocol):
    """Listener for authentication flow lifecycle events."""
    def authentication_started(self, flow: AuthenticationFlow[Any]) -> None:
        """Called when a flow starts authenticating."""
        ...

    def authentication_updated(self, flow: AuthenticationFlow[Any], context: AuthenticationContext) -> None:
        """Called when a flow updates its context."""
        ...

    def authentication_completed(self, flow: AuthenticationFlow[Any], result: Any) -> None:
        """Called when a flow completes successfully."""
        ...

    def authentication_failed(self, flow: AuthenticationFlow[Any], error: Exception) -> None:
        """Called when a flow fails with an error."""
        ...


@dataclass(frozen=True)
class StandardAuthenticationContext(AuthenticationContext):
    """Default authentication context for OAuth2 flows."""

    _acr_values: list[str] | None = None
    _persist_values: Mapping[str, str] | None = None
    _additional_parameters: Mapping[str, RequestValue] | None = None

    @property
    def acr_values(self) -> list[str] | None:
        """ACR values requested for the session."""
        return self._acr_values

    @property
    def persist_values(self) -> Mapping[str, str] | None:
        """Values to persist into token context, if any."""
        return self._persist_values

    @property
    def additional_parameters(self) -> Mapping[str, RequestValue] | None:
        """Additional parameters for the session."""
        return self._additional_parameters

    def parameters(self, category: OAuth2APIRequestCategory) -> Mapping[str, RequestValue] | None:
        """Return OAuth2 parameters contributed by this context."""
        result: dict[str, RequestValue] = dict(self._additional_parameters or {})
        if category == OAuth2APIRequestCategory.AUTHORIZATION and self._acr_values:
            result["acr_values"] = " ".join(self._acr_values)
        return result or None


@runtime_checkable
class AuthenticationFlow(Protocol, Generic[ContextT]):
    """Protocol for authentication flows with start/resume/reset semantics."""
    @property
    def context(self) -> ContextT | None:
        """Current session context, if any."""
        ...

    @property
    def state(self) -> AuthenticationState:
        """Current flow state."""
        ...

    @property
    def is_authenticating(self) -> bool:
        """Return True when authentication is in progress."""
        ...

    @property
    def additional_parameters(self) -> Mapping[str, RequestValue] | None:
        """Flow-level parameters applied to all requests."""
        ...

    @property
    def listeners(self) -> ListenerCollection[AuthenticationListener]:
        """Listener collection for flow events."""
        ...

    def reset(self) -> None:
        """Reset flow state and context."""
        ...

    async def start(self, *args: Any, context: ContextT | None = None, **kwargs: Any) -> Any:
        """Start authentication with optional context."""
        ...

    async def resume(self, *args: Any, context: ContextT, **kwargs: Any) -> Any:
        """Resume authentication with additional context."""
        ...


class BaseAuthenticationFlow(Generic[ContextT]):
    """Base class implementing common flow state and listener behavior."""
    def __init__(self, additional_parameters: Mapping[str, RequestValue] | None = None) -> None:
        """Initialize the flow with optional additional parameters."""
        self._context: ContextT | None = None
        self._state = AuthenticationState.IDLE
        self._additional_parameters = additional_parameters
        self._lock = asyncio.Lock()
        self._listeners: ListenerCollection[AuthenticationListener] = ListenerCollection()

    @property
    def context(self) -> ContextT | None:
        """Return the current context."""
        return self._context

    @property
    def state(self) -> AuthenticationState:
        """Return the current flow state."""
        return self._state

    @property
    def is_authenticating(self) -> bool:
        """Return True when the flow is authenticating."""
        return self._state == AuthenticationState.AUTHENTICATING

    @property
    def additional_parameters(self) -> Mapping[str, RequestValue] | None:
        """Return flow-level additional parameters."""
        return self._additional_parameters

    @property
    def listeners(self) -> ListenerCollection[AuthenticationListener]:
        """Return the listener collection."""
        return self._listeners

    def reset(self) -> None:
        """Reset state and clear the current context."""
        self._context = None
        self._state = AuthenticationState.IDLE

    async def _begin(self, context: ContextT | None) -> None:
        """Begin a new authentication session and notify listeners."""
        async with self._lock:
            if self._state == AuthenticationState.AUTHENTICATING:
                raise RuntimeError("Authentication already in progress")
            self._context = context
            self._state = AuthenticationState.AUTHENTICATING
        flow = cast(AuthenticationFlow[Any], self)
        for listener in self._listeners:
            listener.authentication_started(flow)
        if context is not None:
            for listener in self._listeners:
                listener.authentication_updated(flow, context)

    def _update_context(self, context: ContextT) -> None:
        """Update the current context and notify listeners."""
        self._context = context
        flow = cast(AuthenticationFlow[Any], self)
        for listener in self._listeners:
            listener.authentication_updated(flow, context)

    def _complete(self, result: Any) -> None:
        """Mark flow as completed and notify listeners."""
        self._state = AuthenticationState.COMPLETED
        flow = cast(AuthenticationFlow[Any], self)
        for listener in self._listeners:
            listener.authentication_completed(flow, result)

    def _fail(self, error: Exception) -> None:
        """Mark flow as failed and notify listeners."""
        self._state = AuthenticationState.FAILED
        flow = cast(AuthenticationFlow[Any], self)
        for listener in self._listeners:
            listener.authentication_failed(flow, error)
