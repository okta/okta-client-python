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

from typing import Protocol, runtime_checkable

from .jwt_context import JWTUsageContext
from .jwt_token import JWT
from .models import JWKS


@runtime_checkable
class TokenHashValidator(Protocol):
    """Protocol for validating token hashes using ID tokens."""

    def validate(self, token: str, id_token: JWT) -> None:
        ...


@runtime_checkable
class TokenValidator(Protocol):
    """Protocol for validating and parsing JWTs with usage context."""

    def validate(self, token: str, jwks: JWKS | None, context: JWTUsageContext | None) -> JWT:
        ...
