# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

from pathlib import Path

import jwt

from okta_client.authfoundation import LocalKeyProvider, get_key_provider, set_key_provider
from okta_client.authfoundation.utils import base64url_encode


def test_default_key_provider_requires_configuration() -> None:
    provider = get_key_provider()
    try:
        provider.sign_jwt({"sub": "test"})
    except RuntimeError as exc:
        assert "KeyProvider is not configured" in str(exc)
        return
    raise AssertionError("Expected KeyProvider to raise when unconfigured")


def test_set_key_provider_signs_and_includes_kid() -> None:
    previous = get_key_provider()
    try:
        secret = b"really-super-secret-key-don't-tell-anyone!"
        provider = LocalKeyProvider(key=secret, algorithm="HS256", key_id="kid")
        set_key_provider(provider)
        token = get_key_provider().sign_jwt({"sub": "test"})
        decoded = jwt.decode(token, secret, algorithms=["HS256"], options={"verify_aud": False})
        assert decoded["sub"] == "test"
        header = jwt.get_unverified_header(token)
        assert header["kid"] == "kid"
    finally:
        set_key_provider(previous)


def test_local_key_provider_supports_jwk_oct_key() -> None:
    secret = b"really-super-secret-key-don't-tell-anyone!"
    jwk = {
        "kty": "oct",
        "k": base64url_encode(secret),
    }
    provider = LocalKeyProvider(key=jwk, algorithm="HS256")
    token = provider.sign_jwt({"sub": "user"})
    decoded = jwt.decode(token, secret, algorithms=["HS256"], options={"verify_aud": False})
    assert decoded["sub"] == "user"


def test_local_key_provider_from_pem() -> None:
    pem_path = Path(__file__).parent / "resources" / "test_key.pem"
    pem = pem_path.read_text(encoding="utf-8")

    provider = LocalKeyProvider.from_pem(pem, algorithm="RS256")
    token = provider.sign_jwt({"sub": "pem"})

    public_key_path = Path(__file__).parent / "resources" / "test_key.pub"
    public_key_pem = public_key_path.read_bytes()

    decoded = jwt.decode(token, public_key_pem, algorithms=["RS256"], options={"verify_aud": False})
    assert decoded["sub"] == "pem"


def test_local_key_provider_from_pem_file() -> None:
    pem_path = Path(__file__).parent / "resources" / "test_key.pem"

    provider = LocalKeyProvider.from_pem_file(str(pem_path), algorithm="RS256")
    token = provider.sign_jwt({"sub": "pem-file"})

    public_key_path = Path(__file__).parent / "resources" / "test_key.pub"
    public_key_pem = public_key_path.read_bytes()

    decoded = jwt.decode(token, public_key_pem, algorithms=["RS256"], options={"verify_aud": False})
    assert decoded["sub"] == "pem-file"


def test_local_key_provider_rejects_unknown_algorithm() -> None:
    try:
        LocalKeyProvider(key="secret", algorithm="none")
    except ValueError:
        return
    raise AssertionError("Expected ValueError for unsupported algorithm")


def test_local_key_provider_requires_claims() -> None:
    provider = LocalKeyProvider(key="secret", algorithm="HS256")
    try:
        provider.sign_jwt({})
    except ValueError:
        return
    raise AssertionError("Expected ValueError for empty claims")
