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
from typing import ClassVar

from ..time_coordinator import get_time_coordinator


@dataclass(frozen=True)
class JWTBearerClaims:
    """Claims required to build a JWT bearer assertion."""

    _reserved_claims: ClassVar[frozenset[str]] = frozenset(("iss", "sub", "aud", "iat", "exp", "jti"))

    issuer: str
    subject: str
    audience: str
    expires_in: float
    issued_at: float | None = None
    jwt_id: str | None = None
    additional_claims: Mapping[str, object] | None = None

    def to_claims(self) -> dict[str, object]:
        if not self.issuer:
            raise ValueError("issuer is required")
        if not self.subject:
            raise ValueError("subject is required")
        if not self.audience:
            raise ValueError("audience is required")
        if self.expires_in <= 0:
            raise ValueError("expires_in must be positive")
        issued_at = self.issued_at if self.issued_at is not None else get_time_coordinator().now()
        exp = issued_at + self.expires_in
        claims: dict[str, object] = {
            "iss": self.issuer,
            "sub": self.subject,
            "aud": self.audience,
            "iat": int(issued_at),
            "exp": int(exp),
        }
        if self.jwt_id:
            claims["jti"] = self.jwt_id
        if self.additional_claims:
            overlap = self._reserved_claims.intersection(self.additional_claims.keys())
            if overlap:
                raise ValueError("additional_claims must not override required claims")
            claims.update(self.additional_claims)
        return claims
