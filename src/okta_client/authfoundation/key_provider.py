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
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

import jwt
from jwt import algorithms as jwt_algorithms

_ALLOWED_ALGORITHMS = {
    "HS256",
    "HS384",
    "HS512",
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
    "PS256",
    "PS384",
    "PS512",
}


@runtime_checkable
class KeyProvider(Protocol):
    """Protocol for signing JWT assertions."""

    algorithm: str
    key_id: str | None

    def sign_jwt(self, claims: Mapping[str, object], headers: Mapping[str, object] | None = None) -> str:
        """Sign the given claims and return a compact JWT string."""
        ...


@dataclass(frozen=True)
class LocalKeyProvider(KeyProvider):
    """Key provider that signs JWTs using local key material."""

    key: str | bytes | Mapping[str, Any]
    algorithm: str = "RS256"
    key_id: str | None = None

    def __post_init__(self) -> None:
        if self.algorithm not in _ALLOWED_ALGORITHMS:
            raise ValueError(f"Unsupported JWT algorithm: {self.algorithm}")

    def sign_jwt(self, claims: Mapping[str, object], headers: Mapping[str, object] | None = None) -> str:
        if not claims:
            raise ValueError("claims must not be empty")
        encoded_headers = dict(headers or {})
        if self.key_id and "kid" not in encoded_headers:
            encoded_headers["kid"] = self.key_id
        key = _resolve_key_material(self.key, self.algorithm)
        token = jwt.encode(payload=dict(claims), key=key, algorithm=self.algorithm, headers=encoded_headers or None)
        return token.decode("utf-8") if isinstance(token, bytes) else token

    @classmethod
    def from_pem(
        cls,
        pem: str,
        *,
        algorithm: str = "RS256",
        key_id: str | None = None,
    ) -> LocalKeyProvider:
        return cls(pem, algorithm=algorithm, key_id=key_id)

    @classmethod
    def from_pem_file(
        cls,
        path: str,
        *,
        algorithm: str = "RS256",
        key_id: str | None = None,
        encoding: str = "utf-8",
    ) -> LocalKeyProvider:
        with open(path, encoding=encoding) as handle:
            return cls(handle.read(), algorithm=algorithm, key_id=key_id)


class DefaultKeyProvider(KeyProvider):
    """Default provider that requires explicit configuration."""

    algorithm: str = ""
    key_id: str | None = None

    def sign_jwt(self, claims: Mapping[str, object], headers: Mapping[str, object] | None = None) -> str:
        raise RuntimeError("KeyProvider is not configured. Use set_key_provider() to supply a signer.")


_default_key_provider: KeyProvider = DefaultKeyProvider()
_key_provider_lock = threading.Lock()


def get_key_provider() -> KeyProvider:
    """Get the global KeyProvider in a thread-safe manner."""
    with _key_provider_lock:
        return _default_key_provider


def set_key_provider(provider: KeyProvider) -> None:
    """Set the global KeyProvider in a thread-safe manner."""
    global _default_key_provider
    with _key_provider_lock:
        _default_key_provider = provider


def _resolve_key_material(key: str | bytes | Mapping[str, Any], algorithm: str) -> Any:
    if isinstance(key, (str, bytes)):
        return key
    if isinstance(key, Mapping):
        algorithms = jwt_algorithms.get_default_algorithms()
        if algorithm not in algorithms:
            raise ValueError(f"Unsupported JWT algorithm: {algorithm}")
        return algorithms[algorithm].from_jwk(json.dumps(dict(key)))
    raise TypeError("key must be a PEM string, bytes, or JWK mapping")
