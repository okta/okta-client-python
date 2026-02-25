# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

"""Integration test for CrossAppAccessFlow (ID-JAG exchange).

End-to-end flow using the SDK's :class:`CrossAppAccessFlow`:
  1. Sign in a user via the Authorization Code (PKCE) web redirect flow
     (``web_signin_token`` fixture).
  2. Build an :class:`OAuth2Client` with org-level issuer and private-key
     client assertion authentication.
  3. Use :meth:`CrossAppAccessFlow.start` to exchange the web ID token
     for an ID-JAG via token exchange.
  4. Use :meth:`CrossAppAccessFlow.resume` to exchange the ID-JAG
     for a resource-server access token via JWT bearer.
  5. Validate the resulting token contains the expected scope.
"""

from __future__ import annotations

import asyncio
import json
from urllib.parse import urlparse

import pytest

from okta_client.authfoundation import (
    OAuth2Client,
    OAuth2ClientConfiguration,
    Token,
)
from okta_client.authfoundation.key_provider import LocalKeyProvider
from okta_client.authfoundation.oauth2.client_authorization import ClientAssertionAuthorization
from okta_client.authfoundation.oauth2.jwt_bearer_claims import JWTBearerClaims
from okta_client.oauth2auth.cross_app import (
    CrossAppAccessFlow,
    CrossAppAccessTarget,
)

from .utils import json_from_file, repo_root

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


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_cross_app_authorization_flow(web_signin_token: Token) -> None:
    """Exchange a web ID token for a resource access token via CrossAppAccessFlow."""
    repo = repo_root()
    agent_config_path = repo / "test-configuration-ai-agent.json"
    api_config_path = repo / "okta-client-assertion-api.json"
    key_file = repo / "okta-private-key.pem"
    public_key_file = repo / "okta-public-key.json"

    for path in (agent_config_path, api_config_path, key_file, public_key_file):
        if not path.exists():
            pytest.skip(f"Required config file not found: {path.name}")

    # Load configuration
    agent_client_id = json_from_file(agent_config_path).get("client_id")
    if not agent_client_id:
        pytest.fail("test-configuration-ai-agent.json missing required client_id", pytrace=False)

    resource_issuer = json_from_file(api_config_path).get("issuer")
    if not resource_issuer:
        pytest.fail("okta-client-assertion-api.json missing issuer", pytrace=False)

    parsed = urlparse(resource_issuer)
    org_issuer = f"{parsed.scheme}://{parsed.netloc}"

    key_id = json_from_file(public_key_file).get("kid")
    if not key_id:
        pytest.fail("Key ID (kid) not found in public key file", pytrace=False)

    key_provider = LocalKeyProvider.from_pem_file(
        str(key_file),
        algorithm="RS256",
        key_id=key_id,
    )

    # Extract the raw ID token from the web sign-in result
    id_token = web_signin_token.id_token.raw if web_signin_token.id_token else None
    if not id_token:
        pytest.fail("Web sign-in token does not contain an ID token")

    # Build the org-level client and the cross-app flow
    client = OAuth2Client(
        configuration=OAuth2ClientConfiguration(
            issuer=org_issuer,
            scope="custom_scope",
            client_authorization=ClientAssertionAuthorization(
                assertion_claims=JWTBearerClaims(
                    issuer=agent_client_id,
                    subject=agent_client_id,
                    audience=f"{org_issuer}/oauth2/v1/token",
                    expires_in=300,
                ),
                key_provider=key_provider,
            ),
        ),
    )
    flow = CrossAppAccessFlow(
        client=client,
        target=CrossAppAccessTarget(issuer=resource_issuer),
    )

    # Step 1: Exchange the web ID token for an ID-JAG
    exchange_result = asyncio.run(
        flow.start(
            token=id_token,
            audience=resource_issuer,
        )
    )

    assert exchange_result is not None, "start() should return a CrossAppExchangeResult"
    # Key-provider path → resume_assertion_claims should be None (auto-sign)
    assert exchange_result.resume_assertion_claims is None, (
        "Expected auto-sign path (resume_assertion_claims should be None)"
    )

    assert flow.context is not None, "Flow context should be set after start()"
    id_jag_token = flow.context.id_jag_token
    assert id_jag_token is not None, "ID-JAG token should be stored in context"
    assert id_jag_token.access_token, "ID-JAG token should have a non-empty access_token"
    assert id_jag_token.issued_token_type == "urn:ietf:params:oauth:token-type:id-jag"

    # Step 2: Exchange the ID-JAG for a resource-server access token
    access_token = asyncio.run(flow.resume())

    assert access_token is not None, "resume() should return an access token"
    assert access_token.access_token, "Access token should be non-empty"
    assert access_token.token_type == "Bearer"

    scopes = access_token.scope or []
    assert "custom_scope" in scopes, f"Expected 'custom_scope' in scopes, got: {scopes}"
