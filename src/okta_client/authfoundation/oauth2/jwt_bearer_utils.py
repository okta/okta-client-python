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

from ..key_provider import KeyProvider, get_key_provider
from .jwt_bearer_claims import JWTBearerClaims


def resolve_jwt_bearer_assertion(
    *,
    assertion: str | None = None,
    assertion_claims: JWTBearerClaims | None = None,
    key_provider: KeyProvider | None = None,
) -> str:
    if assertion and assertion_claims:
        raise ValueError("Provide either assertion or assertion_claims, not both")
    if assertion:
        return assertion
    if assertion_claims is None:
        raise ValueError("assertion or assertion_claims is required")
    provider = key_provider or get_key_provider()
    return provider.sign_jwt(assertion_claims.to_claims())
