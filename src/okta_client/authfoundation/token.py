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
from enum import Enum
from typing import Any, Union

from okta_client.authfoundation.utils import coerce_optional_str

from .expires import Expires
from .networking import APIAuthorization, HTTPRequest
from .oauth2.jwt_context import JWTUsageContext
from .oauth2.jwt_token import JWT
from .oauth2.models import JWKS
from .oauth2.validator_registry import get_access_token_validator, get_device_secret_validator


class GrantedTokenType(str, Enum):
    """Known token_type values from OAuth2 token responses.

    Since this is a str enum, instances compare equal to their string values:
        GrantedTokenType.BEARER == "Bearer"  # True

    Unknown token_type values from the server are preserved as raw strings
    via the ``GrantedTokenType | str`` union type on ``Token.token_type``.
    """

    BEARER = "Bearer"
    DPOP = "DPoP"
    NA = "N_A"

    def __format__(self, format_spec: str) -> str:
        return str.__format__(self.value, format_spec)


@dataclass(frozen=True)
class TokenContext:
    """Context describing the issuer and client used to obtain a token."""
    issuer: str
    client_id: str | None = None
    client_settings: Mapping[str, str] | None = None

    @property
    def audience(self) -> str | None:
        return self.client_id

    @property
    def nonce(self) -> str | None:
        return None

    @property
    def max_age(self) -> float | None:
        return None

    @property
    def leeway(self) -> float | None:
        return None


@dataclass(frozen=True)
class Token(Expires, APIAuthorization):
    """Immutable OAuth2 token representation with authorization support."""
    access_token: str
    token_type: Union[GrantedTokenType, str]
    _expires_in: float
    context: TokenContext
    _issued_at: float | None = None
    refresh_token: str | None = None
    id_token: JWT | None = None
    scope: list[str] | None = None
    issued_token_type: str | None = None
    device_secret: str | None = None
    raw_fields: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        """Validate required token fields."""
        if not self.access_token:
            raise ValueError("access_token is required")
        if not self.token_type:
            raise ValueError("token_type is required")
        if self._expires_in is None:
            raise ValueError("expires_in is required")
        if self._expires_in < 0:
            raise ValueError("expires_in must be non-negative")

    @property
    def expires_in(self) -> float:
        """Return the token lifetime in seconds."""
        return self._expires_in

    @property
    def issued_at(self) -> float | None:
        """Return the issue time in seconds since epoch, if known."""
        return self._issued_at

    def authorize(self, request: HTTPRequest) -> HTTPRequest:
        """Apply Bearer/token-type authorization to the request."""
        if self.access_token:
            prefix = self.token_type
            request.headers["Authorization"] = f"{prefix} {self.access_token}"
        return request

    def as_authorization(self) -> APIAuthorization:
        """Return this token as an APIAuthorization provider."""
        return self

    def merge(self, previous: Token) -> Token:
        """Return a new Token by merging this token with a previous one.

        New values take precedence, and missing optional fields fall back to the previous token.
        """
        merged_raw: dict[str, Any] = {}
        if previous.raw_fields:
            merged_raw.update(previous.raw_fields)
        if self.raw_fields:
            merged_raw.update(self.raw_fields)

        return Token(
            access_token=self.access_token,
            token_type=self.token_type,
            _expires_in=self._expires_in,
            _issued_at=self._issued_at if self._issued_at is not None else previous._issued_at,
            context=self.context,
            refresh_token=self.refresh_token if self.refresh_token is not None else previous.refresh_token,
            id_token=self.id_token if self.id_token is not None else previous.id_token,
            scope=self.scope if self.scope is not None else previous.scope,
            issued_token_type=(
                self.issued_token_type if self.issued_token_type is not None else previous.issued_token_type
            ),
            device_secret=self.device_secret if self.device_secret is not None else previous.device_secret,
            raw_fields=merged_raw or None,
        )

    @classmethod
    def from_response(
        cls,
        data: Mapping[str, Any],
        *,
        context: TokenContext,
        issued_at: float | None = None,
        jwks: JWKS | None = None,
        jwt_context: JWTUsageContext | None = None,
    ) -> Token:
        """Create a Token from an OAuth2 token response payload."""
        access_token = str(data.get("access_token", ""))
        token_type_raw = str(data.get("token_type", ""))
        token_type: Union[GrantedTokenType, str]
        try:
            token_type = GrantedTokenType(token_type_raw)
        except ValueError:
            token_type = token_type_raw
        expires_in_value = data.get("expires_in")
        if expires_in_value is None:
            raise ValueError("expires_in is required")
        expires_in = float(expires_in_value)
        scope_value = data.get("scope")
        scope = _parse_scope(scope_value)
        id_token_value = coerce_optional_str(data.get("id_token"))
        id_token = None
        if id_token_value:
            id_token = JWT(id_token_value, jwks=jwks, context=jwt_context)
        token = cls(
            access_token=access_token,
            token_type=token_type,
            _expires_in=expires_in,
            context=context,
            _issued_at=issued_at,
            refresh_token=coerce_optional_str(data.get("refresh_token")),
            id_token=id_token,
            scope=scope,
            issued_token_type=coerce_optional_str(data.get("issued_token_type")),
            device_secret=coerce_optional_str(data.get("device_secret")),
            raw_fields=dict(data),
        )
        if token.id_token:
            if token.access_token:
                get_access_token_validator().validate(token.access_token, token.id_token)
            if token.device_secret:
                get_device_secret_validator().validate(token.device_secret, token.id_token)
        return token


def _parse_scope(value: Any) -> list[str] | None:
    """Parse a scope value into a list of strings."""
    if value is None:
        return None
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        return [item for item in value.split(" ") if item]
    return None
