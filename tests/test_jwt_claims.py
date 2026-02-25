# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

import base64 as _b64
import json
import time

import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from jwt.algorithms import RSAAlgorithm

from okta_client.authfoundation.oauth2.claims import IdTokenClaim
from okta_client.authfoundation.oauth2.jwt_context import JWTValidationContext
from okta_client.authfoundation.oauth2.jwt_token import JWT, JWTType
from okta_client.authfoundation.oauth2.models import JWK, JWKS


def _make_keypair() -> tuple[rsa.RSAPrivateKey, JWKS]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk_json = RSAAlgorithm.to_jwk(key.public_key())
    jwk_data = json.loads(jwk_json)
    jwk_data["kid"] = "test-key"
    return key, JWKS(keys=[JWK(jwk_data)])


def _encode_token(
    payload: dict,
    key: rsa.RSAPrivateKey,
    alg: str = "RS256",
    extra_headers: dict | None = None,
) -> str:
    header: dict[str, str] = {"alg": alg, "kid": "test-key"}
    if extra_headers:
        header.update(extra_headers)
    token = jwt.encode(payload, key, algorithm=alg, headers=header)
    return str(token)


def test_jwt_claim_accessors() -> None:
    key, jwks = _make_keypair()
    now = time.time()
    payload = {
        "iss": "https://issuer.example.com",
        "aud": ["client-id", "other"],
        "exp": now + 3600,
        "iat": now,
        "sub": "user",
        "nonce": "nonce-1",
    }
    token = _encode_token(payload, key)
    jwt_token = JWT(
        token,
        jwks=jwks,
        context=JWTValidationContext(
            issuer=payload["iss"],
            audience="client-id",
        ),
    )

    assert jwt_token.claim(IdTokenClaim.SUBJECT) == "user"
    assert jwt_token.claim_key("nonce") == "nonce-1"
    assert jwt_token.issuer == payload["iss"]
    assert jwt_token.subject == "user"
    assert jwt_token.audience == ["client-id", "other"]
    assert jwt_token.nonce == "nonce-1"


def test_jwt_claim_key_missing() -> None:
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
    jwt_token = JWT(
        token,
        jwks=jwks,
        context=JWTValidationContext(
            issuer=payload["iss"],
            audience="client-id",
        ),
    )

    assert jwt_token.claim_key("missing") is None


def test_jwt_audience_string_coerces_to_list() -> None:
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
    jwt_token = JWT(
        token,
        jwks=jwks,
        context=JWTValidationContext(
            issuer=payload["iss"],
            audience="client-id",
        ),
    )

    assert jwt_token.audience == ["client-id"]


def test_jwt_claims_mapping_is_immutable() -> None:
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
    jwt_token = JWT(
        token,
        jwks=jwks,
        context=JWTValidationContext(
            issuer=payload["iss"],
            audience="client-id",
        ),
    )

    claims = jwt_token.claims
    try:
        claims["sub"] = "other"  # type: ignore[index]
    except TypeError:
        return
    raise AssertionError("Expected claims mapping to be immutable")


# ---------------------------------------------------------------------------
# JWT type (typ header) tests
# ---------------------------------------------------------------------------


def _make_jwt_with_type(typ: str | None = None) -> JWT:
    """Helper to create a JWT with a specific ``typ`` header value."""
    key, jwks = _make_keypair()
    now = time.time()
    payload = {
        "iss": "https://issuer.example.com",
        "aud": "client-id",
        "exp": now + 3600,
        "iat": now,
        "sub": "user",
    }
    extra_headers = {"typ": typ} if typ is not None else {}
    token = _encode_token(payload, key, extra_headers=extra_headers)
    return JWT(
        token,
        jwks=jwks,
        context=JWTValidationContext(
            issuer=payload["iss"],
            audience="client-id",
        ),
    )


def test_jwt_type_returns_enum_for_jwt() -> None:
    jwt_token = _make_jwt_with_type("JWT")
    assert jwt_token.type is JWTType.JWT
    assert jwt_token.type == "JWT"


def test_jwt_type_returns_enum_for_dpop() -> None:
    jwt_token = _make_jwt_with_type("dpop+jwt")
    assert jwt_token.type is JWTType.DPOP
    assert jwt_token.type == "dpop+jwt"


def test_jwt_type_returns_enum_for_id_jag() -> None:
    jwt_token = _make_jwt_with_type("id-jag+jwt")
    assert jwt_token.type is JWTType.ID_JAG
    assert jwt_token.type == "id-jag+jwt"


def test_jwt_type_returns_enum_for_oauth_id_jag() -> None:
    jwt_token = _make_jwt_with_type("oauth-id-jag+jwt")
    assert jwt_token.type is JWTType.OAUTH_ID_JAG
    assert jwt_token.type == "oauth-id-jag+jwt"


def test_jwt_type_returns_str_for_unknown() -> None:
    jwt_token = _make_jwt_with_type("custom+jwt")
    result = jwt_token.type
    assert result == "custom+jwt"
    assert not isinstance(result, JWTType)


def test_jwt_type_returns_none_when_missing() -> None:
    """A token whose header has no ``typ`` field returns None.

    We build a properly-signed JWT whose header is exactly
    ``{"alg":"RS256","kid":"test-key"}`` with no ``typ`` key.
    """

    key, jwks = _make_keypair()

    header_json = json.dumps({"alg": "RS256", "kid": "test-key"}, separators=(",", ":"))
    payload_json = json.dumps({
        "iss": "https://issuer.example.com",
        "aud": "client-id",
        "exp": time.time() + 3600,
        "iat": time.time(),
        "sub": "user",
    }, separators=(",", ":"))

    header_b64 = _b64.urlsafe_b64encode(header_json.encode()).rstrip(b"=")
    payload_b64 = _b64.urlsafe_b64encode(payload_json.encode()).rstrip(b"=")
    signing_input = header_b64 + b"." + payload_b64

    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = _b64.urlsafe_b64encode(signature).rstrip(b"=")

    token = f"{header_b64.decode()}.{payload_b64.decode()}.{sig_b64.decode()}"
    jwt_token = JWT(
        token,
        jwks=jwks,
        context=JWTValidationContext(
            issuer="https://issuer.example.com",
            audience="client-id",
        ),
    )
    assert jwt_token.type is None
