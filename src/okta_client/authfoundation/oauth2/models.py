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

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class OAuthAuthorizationServer(Mapping[str, Any]):
    """Claim-bearing OAuth2 authorization server configuration model.

    Unknown fields are preserved and accessible via mapping access.
    """

    claims: Mapping[str, Any]
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str | None = None
    revocation_endpoint: str | None = None
    introspection_endpoint: str | None = None
    userinfo_endpoint: str | None = None
    scopes_supported: list[str] | None = None
    response_types_supported: list[str] | None = None
    grant_types_supported: list[str] | None = None
    token_endpoint_auth_methods_supported: list[str] | None = None

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> OAuthAuthorizationServer:
        """Parse an OAuth2 authorization server configuration document into a typed model."""
        required = ["issuer", "authorization_endpoint", "token_endpoint"]
        missing = [key for key in required if not data.get(key)]
        if missing:
            raise ValueError(f"OAuth2 authorization server configuration missing required fields: {', '.join(missing)}")

        claims = dict(data)
        return cls(
            claims=claims,
            issuer=str(claims["issuer"]),
            authorization_endpoint=str(claims["authorization_endpoint"]),
            token_endpoint=str(claims["token_endpoint"]),
            jwks_uri=_coerce_str_optional(claims.get("jwks_uri")),
            revocation_endpoint=_coerce_str_optional(claims.get("revocation_endpoint")),
            introspection_endpoint=_coerce_str_optional(claims.get("introspection_endpoint")),
            userinfo_endpoint=_coerce_str_optional(claims.get("userinfo_endpoint")),
            scopes_supported=_coerce_str_list(claims.get("scopes_supported")),
            response_types_supported=_coerce_str_list(claims.get("response_types_supported")),
            grant_types_supported=_coerce_str_list(claims.get("grant_types_supported")),
            token_endpoint_auth_methods_supported=_coerce_str_list(
                claims.get("token_endpoint_auth_methods_supported")
            ),
        )

    def __getitem__(self, key: str) -> Any:
        """Return a raw claim value by key."""
        return self.claims[key]

    def __iter__(self) -> Iterator[str]:
        """Iterate over raw claim keys."""
        return iter(self.claims)

    def __len__(self) -> int:
        """Return the number of raw claim entries."""
        return len(self.claims)

    def get(self, key: str, default: Any = None) -> Any:
        """Return a raw claim value by key with a default."""
        return self.claims.get(key, default)

@dataclass(frozen=True)
class OpenIdConfiguration(Mapping[str, Any]):
    """Claim-bearing OpenID discovery model.

    Unknown fields are preserved and accessible via mapping access.
    """

    claims: Mapping[str, Any]
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    revocation_endpoint: str | None = None
    introspection_endpoint: str | None = None
    userinfo_endpoint: str | None = None
    issuer: str | None = None
    scopes_supported: list[str] | None = None
    response_types_supported: list[str] | None = None
    grant_types_supported: list[str] | None = None
    token_endpoint_auth_methods_supported: list[str] | None = None
    pushed_authorization_request_endpoint: str | None = None

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> OpenIdConfiguration:
        """Parse an OpenID discovery document into a typed model."""
        required = ["authorization_endpoint", "token_endpoint", "jwks_uri"]
        missing = [key for key in required if not data.get(key)]
        if missing:
            raise ValueError(f"OpenID configuration missing required fields: {', '.join(missing)}")

        claims = dict(data)
        return cls(
            claims=claims,
            authorization_endpoint=str(claims["authorization_endpoint"]),
            token_endpoint=str(claims["token_endpoint"]),
            jwks_uri=str(claims["jwks_uri"]),
            revocation_endpoint=_coerce_str_optional(claims.get("revocation_endpoint")),
            introspection_endpoint=_coerce_str_optional(claims.get("introspection_endpoint")),
            userinfo_endpoint=_coerce_str_optional(claims.get("userinfo_endpoint")),
            issuer=_coerce_str_optional(claims.get("issuer")),
            scopes_supported=_coerce_str_list(claims.get("scopes_supported")),
            response_types_supported=_coerce_str_list(claims.get("response_types_supported")),
            grant_types_supported=_coerce_str_list(claims.get("grant_types_supported")),
            token_endpoint_auth_methods_supported=_coerce_str_list(
                claims.get("token_endpoint_auth_methods_supported")
            ),
            pushed_authorization_request_endpoint=_coerce_str_optional(
                claims.get("pushed_authorization_request_endpoint")
            ),
        )

    def __getitem__(self, key: str) -> Any:
        """Return a raw claim value by key."""
        return self.claims[key]

    def __iter__(self) -> Iterator[str]:
        """Iterate over raw claim keys."""
        return iter(self.claims)

    def __len__(self) -> int:
        """Return the number of raw claim entries."""
        return len(self.claims)

    def get(self, key: str, default: Any = None) -> Any:
        """Return a raw claim value by key with a default."""
        return self.claims.get(key, default)


@dataclass(frozen=True)
class JWK:
    """Single JWK key object."""
    data: Mapping[str, Any]


@dataclass(frozen=True)
class JWKS:
    """JWKS key set container."""
    keys: list[JWK]

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> JWKS:
        """Parse a JWKS document into a key set."""
        keys = [JWK(item) for item in data.get("keys", [])]
        return cls(keys=keys)


@dataclass(frozen=True)
class TokenInfo:
    """Token introspection response model."""
    claims: Mapping[str, Any]

    @property
    def active(self) -> bool | None:
        """Return the active flag if present."""
        value = self.claims.get("active")
        return bool(value) if value is not None else None


@dataclass(frozen=True)
class UserInfo:
    """OIDC userinfo response model."""
    claims: Mapping[str, Any]


def _coerce_str_optional(value: Any) -> str | None:
    """Convert a value to a string if it is not None."""
    if value is None:
        return None
    return str(value)


def _coerce_str_list(value: Any) -> list[str] | None:
    """Convert list/string values into a list of strings."""
    if value is None:
        return None
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        return [value]
    return None
