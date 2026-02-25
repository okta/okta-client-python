# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

import hashlib
import json
import time

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from okta_client.authfoundation.oauth2.claims import IdTokenClaim
from okta_client.authfoundation.oauth2.jwt_context import JWTValidationContext
from okta_client.authfoundation.oauth2.models import JWK, JWKS
from okta_client.authfoundation.oauth2.validators.token_hash import DefaultTokenHashValidator
from okta_client.authfoundation.oauth2.validators.token_validator import DefaultTokenValidator
from okta_client.authfoundation.time_coordinator import TimeCoordinator, get_time_coordinator, set_time_coordinator
from okta_client.authfoundation.utils import base64url_encode


def _make_keypair() -> tuple[rsa.RSAPrivateKey, JWKS]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk_json = RSAAlgorithm.to_jwk(key.public_key())
    jwk_data = json.loads(jwk_json)
    jwk_data["kid"] = "test-key"
    return key, JWKS(keys=[JWK(jwk_data)])


def _encode_token(payload: dict, key: rsa.RSAPrivateKey, alg: str = "RS256") -> str:
    header = {"alg": alg, "kid": "test-key"}
    token = jwt.encode(payload, key, algorithm=alg, headers=header)
    return str(token)


def _encode_raw_jwt(header: dict, payload: dict) -> str:
    header_b64 = base64url_encode(json.dumps(header).encode("utf-8"))
    payload_b64 = base64url_encode(json.dumps(payload).encode("utf-8"))
    return f"{header_b64}.{payload_b64}."


def test_default_id_token_validator_success() -> None:
    key, jwks = _make_keypair()
    now = time.time()
    payload = {
        "iss": "https://issuer.example.com",
        "aud": "client-id",
        "exp": now + 3600,
        "iat": now,
        "sub": "user",
        "auth_time": now - 10,
        "nonce": "nonce-123",
    }
    token = _encode_token(payload, key)
    context = JWTValidationContext(
        issuer=payload["iss"],
        audience=payload["aud"],
        nonce="nonce-123",
        max_age=60,
    )
    validator = DefaultTokenValidator()
    parsed = validator.validate(token, jwks=jwks, context=context)
    assert parsed.claim(IdTokenClaim.SUBJECT) == "user"


def test_id_token_invalid_issuer() -> None:
    key, jwks = _make_keypair()
    now = time.time()
    payload = {
        "iss": "https://issuer.example.com",
        "aud": "client-id",
        "exp": now + 3600,
        "iat": now,
        "sub": "user",
    }
    token = _encode_token(payload, key)
    validator = DefaultTokenValidator()
    try:
        validator.validate(
            token,
            jwks=jwks,
            context=JWTValidationContext(
                issuer="https://other.example.com",
                audience="client-id",
            ),
        )
    except jwt.InvalidIssuerError:
        return
    raise AssertionError("Expected InvalidIssuerError")


def test_id_token_invalid_audience() -> None:
    key, jwks = _make_keypair()
    now = time.time()
    payload = {
        "iss": "https://issuer.example.com",
        "aud": "client-id",
        "exp": now + 3600,
        "iat": now,
        "sub": "user",
    }
    token = _encode_token(payload, key)
    validator = DefaultTokenValidator()
    try:
        validator.validate(
            token,
            jwks=jwks,
            context=JWTValidationContext(
                issuer=payload["iss"],
                audience="other-client",
            ),
        )
    except jwt.InvalidAudienceError:
        return
    raise AssertionError("Expected InvalidAudienceError")


def test_id_token_expired() -> None:
    key, jwks = _make_keypair()
    now = time.time()
    payload = {
        "iss": "https://issuer.example.com",
        "aud": "client-id",
        "exp": now - 10,
        "iat": now,
        "sub": "user",
    }
    token = _encode_token(payload, key)
    validator = DefaultTokenValidator()
    try:
        validator.validate(
            token,
            jwks=jwks,
            context=JWTValidationContext(
                issuer=payload["iss"],
                audience="client-id",
            ),
        )
    except jwt.ExpiredSignatureError:
        return
    raise AssertionError("Expected ExpiredSignatureError")


def test_id_token_nonce_mismatch() -> None:
    key, jwks = _make_keypair()
    now = time.time()
    payload = {
        "iss": "https://issuer.example.com",
        "aud": "client-id",
        "exp": now + 3600,
        "iat": now,
        "sub": "user",
        "nonce": "expected",
    }
    token = _encode_token(payload, key)
    validator = DefaultTokenValidator()
    try:
        validator.validate(
            token,
            jwks=jwks,
            context=JWTValidationContext(
                issuer=payload["iss"],
                audience="client-id",
                nonce="other",
            ),
        )
    except ValueError as error:
        assert str(error) == "Nonce mismatch"
        return
    raise AssertionError("Expected nonce mismatch")


def test_id_token_issued_at_outside_grace() -> None:
    key, jwks = _make_keypair()
    now = time.time()
    payload = {
        "iss": "https://issuer.example.com",
        "aud": "client-id",
        "exp": now + 3600,
        "iat": now + 1000,
        "sub": "user",
    }
    token = _encode_token(payload, key)
    validator = DefaultTokenValidator()
    try:
        validator.validate(
            token,
            jwks=jwks,
            context=JWTValidationContext(
                issuer=payload["iss"],
                audience="client-id",
            ),
        )
    except (jwt.ImmatureSignatureError, jwt.InvalidIssuedAtError):
        return
    raise AssertionError("Expected issued-at error")


def test_id_token_max_age_exceeded() -> None:
    key, jwks = _make_keypair()
    now = time.time()
    payload = {
        "iss": "https://issuer.example.com",
        "aud": "client-id",
        "exp": now + 3600,
        "iat": now,
        "auth_time": now - 1000,
        "sub": "user",
    }
    token = _encode_token(payload, key)
    validator = DefaultTokenValidator()
    try:
        validator.validate(
            token,
            jwks=jwks,
            context=JWTValidationContext(
                issuer=payload["iss"],
                audience="client-id",
                max_age=10,
            ),
        )
    except ValueError as error:
        assert str(error) == "Token exceeds max_age"
        return
    raise AssertionError("Expected max_age error")


def test_id_token_missing_exp() -> None:
    key, jwks = _make_keypair()
    now = time.time()
    payload = {
        "iss": "https://issuer.example.com",
        "aud": "client-id",
        "iat": now,
        "sub": "user",
    }
    token = _encode_token(payload, key)
    try:
        DefaultTokenValidator().validate(
            token,
            jwks=jwks,
            context=JWTValidationContext(
                issuer=payload["iss"],
                audience="client-id",
            ),
        )
    except jwt.MissingRequiredClaimError:
        return
    raise AssertionError("Expected MissingRequiredClaimError for exp")


def test_id_token_missing_iat() -> None:
    key, jwks = _make_keypair()
    now = time.time()
    payload = {
        "iss": "https://issuer.example.com",
        "aud": "client-id",
        "exp": now + 3600,
        "sub": "user",
    }
    token = _encode_token(payload, key)
    try:
        DefaultTokenValidator().validate(
            token,
            jwks=jwks,
            context=JWTValidationContext(
                issuer=payload["iss"],
                audience="client-id",
            ),
        )
    except jwt.MissingRequiredClaimError:
        return
    raise AssertionError("Expected MissingRequiredClaimError for iat")


def test_id_token_not_yet_valid_nbf() -> None:
    key, jwks = _make_keypair()
    now = time.time()
    payload = {
        "iss": "https://issuer.example.com",
        "aud": "client-id",
        "exp": now + 3600,
        "iat": now,
        "nbf": now + 1000,
        "sub": "user",
    }
    token = _encode_token(payload, key)
    try:
        DefaultTokenValidator().validate(
            token,
            jwks=jwks,
            context=JWTValidationContext(
                issuer=payload["iss"],
                audience="client-id",
            ),
        )
    except jwt.ImmatureSignatureError:
        return
    raise AssertionError("Expected ImmatureSignatureError for nbf")


def test_id_token_missing_auth_time_with_max_age() -> None:
    key, jwks = _make_keypair()
    now = time.time()
    payload = {
        "iss": "https://issuer.example.com",
        "aud": "client-id",
        "exp": now + 3600,
        "iat": now,
        "sub": "user",
    }
    token = _encode_token(payload, key)
    try:
        DefaultTokenValidator().validate(
            token,
            jwks=jwks,
            context=JWTValidationContext(
                issuer=payload["iss"],
                audience="client-id",
                max_age=10,
            ),
        )
    except ValueError as error:
        assert str(error) == "auth_time is required for max_age"
        return
    raise AssertionError("Expected auth_time missing error")


def test_id_token_auth_time_in_future() -> None:
    key, jwks = _make_keypair()
    now = time.time()
    payload = {
        "iss": "https://issuer.example.com",
        "aud": "client-id",
        "exp": now + 3600,
        "iat": now,
        "auth_time": now + 1000,
        "sub": "user",
    }
    token = _encode_token(payload, key)
    try:
        DefaultTokenValidator().validate(
            token,
            jwks=jwks,
            context=JWTValidationContext(
                issuer=payload["iss"],
                audience="client-id",
                max_age=10,
            ),
        )
    except ValueError as error:
        assert str(error) == "auth_time is in the future"
        return
    raise AssertionError("Expected auth_time future error")


def test_id_token_max_age_allows_leeway() -> None:
    key, jwks = _make_keypair()
    fixed_now = time.time()
    payload = {
        "iss": "https://issuer.example.com",
        "aud": "client-id",
        "exp": fixed_now + 3600,
        "iat": fixed_now,
        "auth_time": fixed_now - 10,
        "sub": "user",
    }
    token = _encode_token(payload, key)

    class _FixedCoordinator(TimeCoordinator):
        def now(self) -> float:
            return fixed_now

        def observe_server_time(self, server_time: float) -> None:
            return None

    previous = get_time_coordinator()
    set_time_coordinator(_FixedCoordinator())
    try:
        DefaultTokenValidator().validate(
            token,
            jwks=jwks,
            context=JWTValidationContext(
                issuer=payload["iss"],
                audience="client-id",
                max_age=5,
                leeway=10,
            ),
        )
    finally:
        set_time_coordinator(previous)


def test_id_token_missing_algorithm_with_jwks() -> None:
    _key, jwks = _make_keypair()
    now = time.time()
    payload = {
        "iss": "https://issuer.example.com",
        "aud": "client-id",
        "exp": now + 3600,
        "iat": now,
        "sub": "user",
    }
    token = _encode_raw_jwt({"kid": "test-key"}, payload)
    try:
        DefaultTokenValidator().validate(
            token,
            jwks=jwks,
            context=JWTValidationContext(
                issuer=payload["iss"],
                audience="client-id",
            ),
        )
    except ValueError as error:
        assert str(error) == "Token algorithm is missing"
        return
    raise AssertionError("Expected missing algorithm error")


def test_id_token_no_matching_jwk() -> None:
    key, _jwks = _make_keypair()
    now = time.time()
    payload = {
        "iss": "https://issuer.example.com",
        "aud": "client-id",
        "exp": now + 3600,
        "iat": now,
        "sub": "user",
    }
    token = _encode_token(payload, key)
    try:
        DefaultTokenValidator().validate(
            token,
            jwks=JWKS(keys=[]),
            context=JWTValidationContext(
                issuer=payload["iss"],
                audience="client-id",
            ),
        )
    except ValueError as error:
        assert str(error) == "No compatible JWK found"
        return
    raise AssertionError("Expected missing JWK error")


def test_token_hash_mismatch() -> None:
    key, jwks = _make_keypair()
    now = time.time()
    payload = {
        "iss": "https://issuer.example.com",
        "aud": "client-id",
        "exp": now + 3600,
        "iat": now,
        "sub": "user",
    }
    token_value = "access-token"
    digest = hashlib.sha256(token_value.encode("ascii")).digest()
    left_half = digest[: len(digest) // 2]
    payload["at_hash"] = base64url_encode(left_half)
    token = _encode_token(payload, key)

    validator = DefaultTokenValidator()
    parsed = validator.validate(
        token,
        jwks=jwks,
        context=JWTValidationContext(
            issuer=payload["iss"],
            audience="client-id",
        ),
    )

    hash_validator = DefaultTokenHashValidator("at_hash")
    try:
        hash_validator.validate("different-token", parsed)
    except ValueError as error:
        assert str(error) == "Token hash mismatch"
        return
    raise AssertionError("Expected token hash mismatch")


def test_invalid_signature() -> None:
    key, _jwks = _make_keypair()
    _, wrong_jwks = _make_keypair()
    now = time.time()
    payload = {
        "iss": "https://issuer.example.com",
        "aud": "client-id",
        "exp": now + 3600,
        "iat": now,
        "sub": "user",
    }
    token = _encode_token(payload, key)
    try:
        DefaultTokenValidator().validate(
            token,
            jwks=wrong_jwks,
            context=JWTValidationContext(
                issuer=payload["iss"],
                audience="client-id",
            ),
        )
    except jwt.InvalidSignatureError:
        return
    raise AssertionError("Expected InvalidSignatureError")
