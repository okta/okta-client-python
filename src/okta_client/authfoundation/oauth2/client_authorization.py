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
from dataclasses import dataclass, field
from enum import Enum

import jwt

from ..key_provider import DefaultKeyProvider, KeyProvider, get_key_provider
from ..networking import RequestValue
from .jwt_bearer_claims import JWTBearerClaims
from .jwt_bearer_utils import resolve_jwt_bearer_assertion
from .parameters import OAuth2APIRequestCategory, ProvidesOAuth2Parameters


class ClientAssertionType(str, Enum):
    """Supported client assertion types."""

    JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


_CLIENT_ID_MISSING = object()


@dataclass(frozen=True)
class ClientAuthorization(ProvidesOAuth2Parameters):
    """Base class for OAuth2 client authorization strategies."""

    @property
    def client_id(self) -> str | None:
        """Return the client ID if available."""
        return None

    def parameters(self, category: OAuth2APIRequestCategory) -> Mapping[str, RequestValue] | None:
        raise NotImplementedError

@dataclass(frozen=True)
class ClientIdAuthorization(ClientAuthorization):
    """Client authentication using a client ID parameter."""

    id: str

    @property
    def client_id(self) -> str | None:
        return self.id

    def parameters(self, category: OAuth2APIRequestCategory) -> Mapping[str, RequestValue] | None:
        if category == OAuth2APIRequestCategory.CONFIGURATION:
            return None
        return {"client_id": self.id}

@dataclass(frozen=True)
class ClientSecretAuthorization(ClientIdAuthorization):
    """Client authentication using a client ID and secret parameter."""

    secret: str

    def parameters(self, category: OAuth2APIRequestCategory) -> Mapping[str, RequestValue] | None:
        if category == OAuth2APIRequestCategory.CONFIGURATION:
            return None
        return {
            "client_id": self.id,
            "client_secret": self.secret,
        }

@dataclass(frozen=True)
class ClientAssertionAuthorization(ClientAuthorization):
    """Client authentication using a JWT assertion (RFC 7523)."""

    assertion: str | None = None
    assertion_claims: JWTBearerClaims | None = None
    key_provider: KeyProvider | None = None
    assertion_type: ClientAssertionType = ClientAssertionType.JWT_BEARER
    _cached_client_id: object = field(default=_CLIENT_ID_MISSING, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate inputs and resolve the key provider eagerly.

        Ensures the instance is usable at construction time:

        * Exactly one of ``assertion`` or ``assertion_claims`` must be
          provided.
        * When ``assertion_claims`` is set without an explicit
          ``key_provider``, the global key provider is captured.  If no
          usable global provider is configured, a :class:`ValueError` is
          raised immediately rather than deferring the error to the first
          token request.
        """
        if self.assertion is not None and self.assertion_claims is not None:
            raise ValueError("Provide either 'assertion' or 'assertion_claims', not both")

        if self.assertion is None and self.assertion_claims is None:
            raise ValueError("Either 'assertion' or 'assertion_claims' is required")

        if self.assertion_claims is not None and self.key_provider is None:
            global_provider = get_key_provider()
            if isinstance(global_provider, DefaultKeyProvider):
                raise ValueError(
                    "'assertion_claims' requires a key provider to sign the "
                    "JWT. Supply an explicit 'key_provider' or configure one "
                    "globally via set_key_provider()."
                )
            object.__setattr__(self, "key_provider", global_provider)

    @property
    def client_id(self) -> str | None:
        if self._cached_client_id is _CLIENT_ID_MISSING:
            resolved = self._resolve_client_id()
            object.__setattr__(self, "_cached_client_id", resolved)
        cached = self._cached_client_id
        return cached if isinstance(cached, str) else None

    def parameters(self, category: OAuth2APIRequestCategory) -> Mapping[str, RequestValue] | None:
        if category == OAuth2APIRequestCategory.CONFIGURATION:
            return None
        assertion = self._resolve_assertion()
        assertion_type = (
            self.assertion_type.value
            if isinstance(self.assertion_type, ClientAssertionType)
            else str(self.assertion_type)
        )
        return {
            "client_assertion_type": assertion_type,
            "client_assertion": assertion,
        }

    def _resolve_assertion(self) -> str:
        return resolve_jwt_bearer_assertion(
            assertion=self.assertion,
            assertion_claims=self.assertion_claims,
            key_provider=self.key_provider,
        )

    def _resolve_client_id(self) -> str | None:
        if self.assertion_claims and self.assertion_claims.issuer:
            return self.assertion_claims.issuer
        if self.assertion_claims is None and self.assertion_type == ClientAssertionType.JWT_BEARER:
            return self._extract_issuer_from_assertion()
        return None

    def _extract_issuer_from_assertion(self) -> str | None:
        assertion = self.assertion
        if not assertion:
            return None
        try:
            claims = jwt.decode(
                assertion,
                options={
                    "enforce_minimum_key_length": False,
                    "verify_signature": False,
                    "verify_aud": False,
                    "verify_exp": False,
                    "verify_iss": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                    "verify_jti": False,
                },
            )
        except Exception:
            return None
        iss = claims.get("iss") if isinstance(claims, dict) else None
        return str(iss) if iss else None
