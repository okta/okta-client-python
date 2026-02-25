# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

from okta_client.authfoundation import JWTBearerClaims


def test_jwt_bearer_claims_requires_issuer() -> None:
    claims = JWTBearerClaims(
        issuer="",
        subject="client",
        audience="https://example.com/token",
        expires_in=300,
    )
    try:
        claims.to_claims()
    except ValueError:
        return
    raise AssertionError("Expected ValueError for missing issuer")


def test_jwt_bearer_claims_requires_subject() -> None:
    claims = JWTBearerClaims(
        issuer="client",
        subject="",
        audience="https://example.com/token",
        expires_in=300,
    )
    try:
        claims.to_claims()
    except ValueError:
        return
    raise AssertionError("Expected ValueError for missing subject")


def test_jwt_bearer_claims_requires_audience() -> None:
    claims = JWTBearerClaims(
        issuer="client",
        subject="client",
        audience="",
        expires_in=300,
    )
    try:
        claims.to_claims()
    except ValueError:
        return
    raise AssertionError("Expected ValueError for missing audience")


def test_jwt_bearer_claims_requires_positive_expiration() -> None:
    claims = JWTBearerClaims(
        issuer="client",
        subject="client",
        audience="https://example.com/token",
        expires_in=0,
    )
    try:
        claims.to_claims()
    except ValueError:
        return
    raise AssertionError("Expected ValueError for non-positive expires_in")


def test_jwt_bearer_claims_rejects_reserved_additional_claims() -> None:
    claims = JWTBearerClaims(
        issuer="client",
        subject="client",
        audience="https://example.com/token",
        expires_in=300,
        additional_claims={"iss": "override"},
    )
    try:
        claims.to_claims()
    except ValueError:
        return
    raise AssertionError("Expected ValueError for overlapping additional_claims")
