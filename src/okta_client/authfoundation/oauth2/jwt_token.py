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
from collections.abc import Mapping
from enum import Enum
from types import MappingProxyType
from typing import Any, Union

import jwt
from jwt import PyJWK

from okta_client.authfoundation.utils import coerce_float

from ..time_coordinator import get_time_coordinator
from .claims import HasClaims, IdTokenClaim
from .jwt_context import JWTUsageContext
from .models import JWKS


class JWTType(str, Enum):
    """Known JWT ``typ`` header values."""

    JWT = "JWT"
    DPOP = "dpop+jwt"
    ID_JAG = "id-jag+jwt"
    OAUTH_ID_JAG = "oauth-id-jag+jwt"


class JWT(HasClaims[IdTokenClaim]):
    """Parsed JWT with immutable header and payload claims."""

    def __init__(
        self,
        token: str,
        jwks: JWKS | None = None,
        context: JWTUsageContext | None = None,
    ) -> None:
        """Decode and optionally validate a JWT.

        Args:
            token: The raw encoded JWT string.
            jwks: A JWKS key set used to verify the token signature.
                When ``None``, the token is decoded **without** signature
                verification. Callers that need to trust the token's
                integrity should always supply a JWKS.
            context: Optional validation context that supplies expected
                audience, issuer, nonce, and max-age constraints.
        """
        self._token = token
        self._header = jwt.get_unverified_header(token)

        # Define basic decode arguments
        decode_kwargs: dict[str, Any] = {
            "options": {
                "require": ["exp", "iat"],
                "verify_sub": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_nbf": True,
                "verify_jti": True,
            },
        }

        # Detect the signing algorithm
        alg = self._header.get("alg")
        if alg:
            decode_kwargs["algorithms"] = [str(alg)]
        elif jwks is None:
            decode_kwargs["algorithms"] = []
        else:
            raise ValueError("Token algorithm is missing")

        # Select the appropriate jwks key
        if jwks is not None:
            decode_kwargs["options"]["verify_signature"] = True
            decode_kwargs["key"] = _select_key(jwks, self._header)
        else:
            decode_kwargs["options"]["verify_signature"] = False

        # Add validation steps if JWTUsageContext is supplied
        if context is not None:
            decode_kwargs["audience"] = context.audience
            decode_kwargs["options"]["verify_aud"] = True

            decode_kwargs["issuer"] = context.issuer
            decode_kwargs["options"]["verify_iss"] = True
            if context.leeway is not None:
                decode_kwargs["leeway"] = context.leeway

        # Decode the JWT
        claims = jwt.decode(token, **decode_kwargs)
        self._claims = dict(claims)

        # Verify the nonce
        if context is not None and context.nonce is not None:
            nonce = self._claims.get(IdTokenClaim.NONCE.key())
            if nonce != context.nonce:
                raise ValueError("Nonce mismatch")

        # Verify the max_age
        if context is not None and context.max_age is not None:
            auth_time = self._claims.get(IdTokenClaim.AUTH_TIME.key())
            if auth_time is None:
                raise ValueError("auth_time is required for max_age")
            now = get_time_coordinator().now()
            leeway = context.leeway or 0.0
            elapsed = now - float(auth_time)
            if elapsed < 0:
                raise ValueError("auth_time is in the future")
            if elapsed > context.max_age + leeway:
                raise ValueError("Token exceeds max_age")

    @property
    def raw(self) -> str:
        """Return the original encoded JWT string."""
        return self._token

    @property
    def type(self) -> Union[JWTType, str] | None:
        """Return the JWT ``typ`` header value, if present.

        Returns a :class:`JWTType` member when the value matches a known
        type, otherwise the raw string.
        """
        value = self._header.get("typ")
        if value is None:
            return None
        raw = str(value)
        try:
            return JWTType(raw)
        except ValueError:
            return raw

    @property
    def header(self) -> Mapping[str, Any]:
        """Return the parsed JWT header."""
        return MappingProxyType(dict(self._header))

    @property
    def claims(self) -> Mapping[str, Any]:
        """Return the parsed JWT claims/payload."""
        return MappingProxyType(dict(self._claims))

    def claim(self, claim: IdTokenClaim) -> Any:
        return self._claims.get(claim.key())

    def claim_key(self, key: str) -> Any:
        """Return a claim value by raw key."""
        return self._claims.get(key)

    @property
    def algorithm(self) -> str | None:
        value = self._header.get("alg")
        return str(value) if value is not None else None

    @property
    def issuer(self) -> str | None:
        value = self._claims.get(IdTokenClaim.ISSUER.key())
        return str(value) if value is not None else None

    @property
    def subject(self) -> str | None:
        value = self._claims.get(IdTokenClaim.SUBJECT.key())
        return str(value) if value is not None else None

    @property
    def audience(self) -> list[str]:
        value = self._claims.get(IdTokenClaim.AUDIENCE.key())
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item) for item in value]
        return [str(value)]

    @property
    def expiration_time(self) -> float | None:
        return coerce_float(self._claims.get(IdTokenClaim.EXPIRATION.key()))

    @property
    def issued_at(self) -> float | None:
        return coerce_float(self._claims.get(IdTokenClaim.ISSUED_AT.key()))

    @property
    def auth_time(self) -> float | None:
        return coerce_float(self._claims.get(IdTokenClaim.AUTH_TIME.key()))

    @property
    def nonce(self) -> str | None:
        value = self._claims.get(IdTokenClaim.NONCE.key())
        return str(value) if value is not None else None


def _select_key(jwks: JWKS, header: Mapping[str, Any]) -> Any:
    kid = header.get("kid")
    candidates: list[PyJWK] = []
    for jwk in jwks.keys:
        pyjwk = PyJWK.from_json(json.dumps(jwk.data))
        candidates.append(pyjwk)
        if kid and pyjwk.key_id == kid:
            return pyjwk.key
    if candidates:
        return candidates[0].key
    raise ValueError("No compatible JWK found")

