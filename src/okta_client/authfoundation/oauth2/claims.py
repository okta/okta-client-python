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

from enum import Enum
from typing import Any, Generic, Protocol, TypeVar, runtime_checkable

ClaimEnum = TypeVar("ClaimEnum", bound=Enum, contravariant=True)


@runtime_checkable
class HasClaims(Protocol, Generic[ClaimEnum]):
    """Protocol for objects exposing typed claim values."""

    def claim(self, claim: ClaimEnum) -> Any:
        ...


class IdTokenClaim(str, Enum):
    """Standard OpenID Connect ID token claims."""

    ISSUER = "iss"
    SUBJECT = "sub"
    AUDIENCE = "aud"
    EXPIRATION = "exp"
    ISSUED_AT = "iat"
    AUTH_TIME = "auth_time"
    NONCE = "nonce"
    AT_HASH = "at_hash"
    DS_HASH = "ds_hash"
    ACR = "acr"
    AMR = "amr"
    AZP = "azp"

    def key(self) -> str:
        return str(self.value)
