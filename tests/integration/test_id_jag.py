 # The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

"""Integration tests for the ID-JAG Cross-App Authorization workflow.

End-to-end flow:
  1. Sign in a user via the Authorization Code (PKCE) web redirect flow (``web_signin_token`` fixture).
  2. Generate a client assertion for the API client.
  3. Exchange the web ID token for an ID-JAG via token exchange.
  4. Generate a fresh client assertion for the JWT bearer exchange.
  5. Exchange the ID-JAG for a usable access token via JWT bearer.
  6. Validate the resulting token contains the expected scope.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import pytest

from okta_client.authfoundation import Token

from .utils import generate_client_assertion, json_from_file, repo_root, run_sample

# ---------------------------------------------------------------------------
# Override the web sign-in configuration to use the org-level issuer
# (strip the path from the okta-web.json issuer).
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def web_signin_overrides() -> dict[str, str]:
    """Use the org-level issuer (no path) for the web sign-in flow."""
    repo = repo_root()
    okta_web = repo / "okta-web.json"
    if not okta_web.exists():
        pytest.skip("okta-web.json not found")
    config = json.loads(okta_web.read_text(encoding="utf-8"))
    issuer = config.get("issuer", "")
    parsed = urlparse(issuer)
    org_issuer = f"{parsed.scheme}://{parsed.netloc}"
    return {"issuer": org_issuer}


_ACCESS_TOKEN_PATTERN = re.compile(r"Access Token:\s*(\S+)")
_TOKEN_TYPE_PATTERN = re.compile(r"Token Type:\s*(\S+)")
_SCOPES_PATTERN = re.compile(r"Scopes:\s*(.+)")


# ---------------------------------------------------------------------------
# Shared config fixture
# ---------------------------------------------------------------------------


@dataclass
class IDJAGConfig:
    """Resolved configuration values for the ID-JAG test chain."""

    repo: Path
    audience: str
    config_file: Path
    key_file: Path
    agent_client_id: str
    client_id: str
    org_issuer: str
    org_token_endpoint: str
    token_endpoint: str
    key_id: str


@pytest.fixture(scope="module")
def id_jag_config() -> IDJAGConfig:
    """Load and validate configuration needed for the ID-JAG workflow."""
    repo = repo_root()
    aiagent_config = repo / "test-configuration-ai-agent.json"
    okta_client_assertion = repo / "okta-client-assertion-api.json"
    key_file = repo / "okta-private-key.pem"
    public_key_file = repo / "okta-public-key.json"

    if not (okta_client_assertion.exists() and key_file.exists() and public_key_file.exists()):
        pytest.skip("Client assertion config or key files are missing")

    agent_config = json_from_file(aiagent_config)
    if not agent_config.get("client_id"):
        pytest.skip("test-configuration-ai-agent.json missing required client_id")
    agent_client_id = agent_config.get("client_id")
    if not agent_client_id:
        pytest.fail("Agent client_id is missing in test-configuration-ai-agent.json", pytrace=False)

    config = json_from_file(okta_client_assertion)
    issuer = config.get("issuer")
    client_id = config.get("client_id")
    audience = config.get("issuer")
    if not issuer or not client_id or not audience:
        pytest.fail("okta-client-assertion-api.json missing issuer or client_id", pytrace=False)

    parsed_issuer = urlparse(issuer)
    org_issuer = f"{parsed_issuer.scheme}://{parsed_issuer.netloc}"

    key_id = json_from_file(public_key_file).get("kid")
    if not key_id:
        pytest.fail("Key ID (kid) not found in public key file", pytrace=False)

    return IDJAGConfig(
        repo=repo,
        config_file=okta_client_assertion,
        key_file=key_file,
        agent_client_id=agent_client_id,
        client_id=client_id,
        org_issuer=org_issuer,
        org_token_endpoint=org_issuer + "/oauth2/v1/token",
        token_endpoint=issuer.rstrip("/") + "/v1/token",
        audience=audience,
        key_id=key_id,
    )


# ---------------------------------------------------------------------------
# Step 1: Generate client assertion for the token exchange
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def id_jag_client_assertion(id_jag_config: IDJAGConfig) -> str:
    """Generate a client assertion JWT for the ID-JAG token exchange request."""
    return generate_client_assertion(
        id_jag_config.agent_client_id,
        id_jag_config.org_token_endpoint,
        id_jag_config.key_file.name,
        id_jag_config.key_id,
    )


@pytest.mark.integration
def test_client_assertion_generated(id_jag_client_assertion: str) -> None:
    """Step 1: Verify a client assertion JWT was generated for the token exchange."""
    assert id_jag_client_assertion, "Client assertion should be a non-empty JWT string"
    parts = id_jag_client_assertion.split(".")
    assert len(parts) == 3, f"Client assertion should be a 3-part JWT, got {len(parts)} parts"


# ---------------------------------------------------------------------------
# Step 2: Exchange the web ID token for an ID-JAG
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def id_jag_token(
    web_signin_token: Token,
    id_jag_config: IDJAGConfig,
    id_jag_client_assertion: str,
) -> str:
    """Exchange the web sign-in ID token for an ID-JAG via token exchange."""
    web_id_token = web_signin_token.id_token.raw if web_signin_token.id_token else None
    if not web_id_token:
        pytest.fail("Web sign-in token does not contain an ID token")

    result = run_sample(
        [
            "samples.token_exchange",
            "--config",
            id_jag_config.config_file.name,
            "--issuer",
            id_jag_config.org_issuer,
            "--client_assertion",
            id_jag_client_assertion,
            "--subject-type",
            "id_token",
            "--subject-token",
            web_id_token,
            "--audience",
            id_jag_config.audience,
            "--requested-token-type",
            "id_jag",
            "--verbose",
        ],
        failure_message="Token exchange for ID-JAG failed",
    )

    access_token_match = _ACCESS_TOKEN_PATTERN.search(result.stdout)
    if not access_token_match:
        pytest.fail("ID-JAG access_token not found in token exchange output", pytrace=False)

    token_type_match = _TOKEN_TYPE_PATTERN.search(result.stdout)
    assert token_type_match is not None, "Token Type not found in ID-JAG response"
    assert token_type_match.group(1) == "N_A", (
        f"Expected token_type N_A, got {token_type_match.group(1)}"
    )

    return access_token_match.group(1)


@pytest.mark.integration
def test_id_jag_exchange(id_jag_token: str) -> None:
    """Step 2: Verify the token exchange produced a valid ID-JAG token."""
    assert id_jag_token, "ID-JAG token should be a non-empty string"


# ---------------------------------------------------------------------------
# Step 3: Generate a fresh client assertion for the JWT bearer exchange
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def bearer_client_assertion(id_jag_config: IDJAGConfig) -> str:
    """Generate a fresh client assertion JWT for the JWT bearer request."""
    return generate_client_assertion(
        id_jag_config.agent_client_id,
        id_jag_config.token_endpoint,
        id_jag_config.key_file.name,
        id_jag_config.key_id,
    )


@pytest.mark.integration
def test_bearer_client_assertion_generated(bearer_client_assertion: str) -> None:
    """Step 3: Verify a fresh client assertion JWT was generated for the JWT bearer exchange."""
    assert bearer_client_assertion, "Bearer client assertion should be a non-empty JWT string"
    parts = bearer_client_assertion.split(".")
    assert len(parts) == 3, f"Bearer client assertion should be a 3-part JWT, got {len(parts)} parts"


# ---------------------------------------------------------------------------
# Step 4: Exchange the ID-JAG for an access token via JWT bearer
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_id_jag_token_exchange(
    id_jag_config: IDJAGConfig,
    id_jag_token: str,
    bearer_client_assertion: str,
) -> None:
    """Step 4: Exchange the ID-JAG for an access token via JWT bearer and validate scopes."""
    result = run_sample(
        [
            "samples.jwt_bearer",
            "--config",
            id_jag_config.config_file.name,
            "--client_assertion",
            bearer_client_assertion,
            "--assertion",
            id_jag_token,
            "--scope",
            "",
            "--verbose",
        ],
        failure_message="JWT bearer exchange of ID-JAG failed",
    )

    bearer_access_token = _ACCESS_TOKEN_PATTERN.search(result.stdout)
    assert bearer_access_token is not None, "Access token not found in JWT bearer output"

    scopes_match = _SCOPES_PATTERN.search(result.stdout)
    assert scopes_match is not None, "Scopes not found in JWT bearer output"
    scopes = scopes_match.group(1).strip().split()
    assert "custom_scope" in scopes, f"Expected 'custom_scope' in scopes, got: {scopes}"
