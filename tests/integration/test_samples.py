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

import re

import pytest

from .utils import generate_client_assertion, json_from_file, repo_root, run_sample

_ACCESS_TOKEN_PATTERN = re.compile(r"Access Token:\s*(\S+)")
_REFRESH_TOKEN_PATTERN = re.compile(r"Refresh Token:\s*(\S+)")

@pytest.fixture(scope="session")
def ro_tokens() -> dict[str, str]:
    repo_root_path = repo_root()
    okta_default = repo_root_path / "okta-default.json"
    okta_client_secret = repo_root_path / "okta-client-secret-api.json"
    test_config = repo_root_path / "test-configuration-1fa.json"

    if not (okta_default.exists() and okta_client_secret.exists() and test_config.exists()):
        pytest.skip("Integration config files are missing")

    resource_owner = run_sample(
        [
            "samples.resource_owner",
            "--config",
            okta_default.name,
            "--test-config",
            test_config.name,
        ],
        failure_message="Resource owner sample failed",
    )

    access_match = _ACCESS_TOKEN_PATTERN.search(resource_owner.stdout)
    if not access_match:
        pytest.fail("Access token not found in resource owner output", pytrace=False)
    refresh_match = _REFRESH_TOKEN_PATTERN.search(resource_owner.stdout)
    if not refresh_match:
        pytest.fail("Refresh token not found in resource owner output", pytrace=False)
    return {
        "access_token": access_match.group(1),
        "refresh_token": refresh_match.group(1),
    }


@pytest.mark.integration
def test_resource_owner(ro_tokens: dict[str, str]) -> None:
    assert ro_tokens["access_token"]
    assert ro_tokens["refresh_token"]


@pytest.mark.integration
def test_token_exchange(ro_tokens: dict[str, str]) -> None:
    repo_root_path = repo_root()
    okta_client_secret = repo_root_path / "okta-client-secret-api.json"
    if not okta_client_secret.exists():
        pytest.skip("Integration config files are missing")

    run_sample(
        [
            "samples.token_exchange",
            "--config",
            okta_client_secret.name,
            "--subject-type",
            "access_token",
            "--subject-token",
            ro_tokens["access_token"],
        ],
        failure_message="Token exchange sample failed",
    )


@pytest.mark.integration
def test_token_exchange_with_client_assertion(ro_tokens: dict[str, str]) -> None:
    repo_root_path = repo_root()
    okta_client_assertion = repo_root_path / "okta-client-assertion-api.json"
    key_file = repo_root_path / "okta-private-key.pem"
    public_key_file = repo_root_path / "okta-public-key.json"
    if not (okta_client_assertion.exists() and key_file.exists() and public_key_file.exists()):
        pytest.skip("Integration config files are missing")

    client_assertion_config = json_from_file(okta_client_assertion)
    issuer = client_assertion_config.get("issuer")
    client_id = client_assertion_config.get("client_id")
    if not issuer or not client_id:
        pytest.fail("Client assertion config is missing issuer or client_id", pytrace=False)

    token_endpoint = issuer.rstrip("/") + "/v1/token"

    key_id = json_from_file(public_key_file).get("kid")
    if not key_id:
        pytest.fail("Key ID (kid) not found in public key file", pytrace=False)

    assertion = generate_client_assertion(client_id, token_endpoint, key_file.name, key_id)

    run_sample(
        [
            "samples.token_exchange",
            "--config",
            okta_client_assertion.name,
            "--client_assertion",
            assertion,
            "--subject-type",
            "access_token",
            "--subject-token",
            ro_tokens["access_token"],
            "--verbose",
        ],
        failure_message="Token exchange (client assertion) failed",
    )


@pytest.mark.integration
def test_refresh_token_flow(ro_tokens: dict[str, str]) -> None:
    repo_root_path = repo_root()
    okta_default = repo_root_path / "okta-default.json"
    if not okta_default.exists():
        pytest.skip("Integration config files are missing")

    run_sample(
        [
            "samples.refresh_token",
            "--config",
            okta_default.name,
            "--refresh-token",
            ro_tokens["refresh_token"],
        ],
        failure_message="Refresh token sample failed",
    )
