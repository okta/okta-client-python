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

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .requests import IDTokenValidatorContext


@runtime_checkable
class JWTUsageContext(Protocol):
    """Protocol describing expected JWT validation context."""

    issuer: str
    audience: str | None
    nonce: str | None
    max_age: float | None
    leeway: float | None


@dataclass(frozen=True)
class JWTValidationContext(JWTUsageContext):
    """Concrete JWT context used for validation checks."""

    issuer: str
    audience: str | None = None
    nonce: str | None = None
    max_age: float | None = None
    leeway: float | None = None

    @classmethod
    def from_contexts(
        cls,
        usage: JWTUsageContext,
        validator_context: IDTokenValidatorContext | None,
    ) -> JWTValidationContext:
        return cls(
            issuer=usage.issuer,
            audience=usage.audience,
            nonce=validator_context.nonce if validator_context else None,
            max_age=validator_context.max_age if validator_context else None,
            leeway=usage.leeway,
        )
