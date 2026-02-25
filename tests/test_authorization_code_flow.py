# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

"""Unit tests for the Authorization Code Flow (PKCE) with PAR support."""

import asyncio
import json
from urllib.parse import parse_qs, quote, urlencode, urlsplit

import pytest

from okta_client.authfoundation import (
    NetworkInterface,
    OAuth2Client,
    OAuth2ClientConfiguration,
    OAuth2Error,
    PKCEData,
    RawResponse,
    generate_pkce,
)
from okta_client.authfoundation.oauth2.client_authorization import ClientIdAuthorization
from okta_client.oauth2auth import (
    AuthorizationCodeContext,
    AuthorizationCodeFlow,
    Prompt,
    parse_redirect_uri,
)

# ---------------------------------------------------------------------------
# Fixtures / Helpers
# ---------------------------------------------------------------------------

_OPENID_CONFIG = {
    "issuer": "https://example.com",
    "authorization_endpoint": "https://example.com/authorize",
    "token_endpoint": "https://example.com/token",
    "jwks_uri": "https://example.com/keys",
    "grant_types_supported": ["authorization_code"],
}

_OPENID_CONFIG_WITH_PAR = {
    **_OPENID_CONFIG,
    "pushed_authorization_request_endpoint": "https://example.com/par",
}

_TOKEN_RESPONSE = {
    "access_token": "access_tok",
    "token_type": "Bearer",
    "expires_in": 3600,
    "id_token": None,
}


class DummyNetwork(NetworkInterface):
    """Test network that returns canned responses based on the URL path."""

    def __init__(
        self,
        openid_config: dict | None = None,
        token_body: dict | None = None,
        token_status: int = 200,
        par_body: dict | None = None,
        par_status: int = 200,
    ) -> None:
        self.openid_config = openid_config or _OPENID_CONFIG
        self.token_body = token_body or _TOKEN_RESPONSE
        self.token_status = token_status
        self.par_body = par_body
        self.par_status = par_status
        self.sent_requests: list[dict] = []

    def send(self, request) -> RawResponse:
        url = request.url
        path = urlsplit(url).path

        self.sent_requests.append({"url": url, "method": getattr(request, "http_method", None)})

        if path.endswith(".well-known/openid-configuration"):
            return RawResponse(
                status_code=200,
                headers={},
                body=json.dumps(self.openid_config).encode("utf-8"),
            )
        if path.endswith("/keys"):
            return RawResponse(status_code=200, headers={}, body=json.dumps({"keys": []}).encode("utf-8"))
        if path.endswith("/par"):
            body = self.par_body or {"request_uri": "urn:example:par:12345", "expires_in": 300}
            return RawResponse(
                status_code=self.par_status,
                headers={},
                body=json.dumps(body).encode("utf-8"),
            )
        if path.endswith("/token"):
            return RawResponse(
                status_code=self.token_status,
                headers={},
                body=json.dumps(self.token_body).encode("utf-8"),
            )
        return RawResponse(status_code=200, headers={}, body=b"{}")


def _build_client(
    network: NetworkInterface,
    redirect_uri: str = "https://example.com/callback",
) -> OAuth2Client:
    config = OAuth2ClientConfiguration(
        issuer="https://example.com",
        scope=["openid", "profile"],
        client_authorization=ClientIdAuthorization(id="test_client"),
        redirect_uri=redirect_uri,
    )
    return OAuth2Client(configuration=config, network=network)


def _make_redirect_uri(
    code: str = "authcode123",
    state: str = "some_state",
    base: str = "https://example.com/callback",
) -> str:
    params = {"code": code, "state": state}
    return f"{base}?{urlencode(params, quote_via=quote)}"


# ---------------------------------------------------------------------------
# generate_pkce() tests
# ---------------------------------------------------------------------------


class TestGeneratePKCE:
    def test_returns_pkce_data(self) -> None:
        pkce = generate_pkce()
        assert isinstance(pkce, PKCEData)
        assert pkce.code_challenge_method == "S256"

    def test_verifier_length(self) -> None:
        pkce = generate_pkce()
        # 32 random bytes → 43 base64url chars (no padding)
        assert len(pkce.code_verifier) == 43

    def test_challenge_is_deterministic_for_verifier(self) -> None:
        """Rehashing the same verifier yields the same challenge."""
        import hashlib

        from okta_client.authfoundation.utils import base64url_encode

        pkce = generate_pkce()
        expected = base64url_encode(hashlib.sha256(pkce.code_verifier.encode("ascii")).digest())
        assert pkce.code_challenge == expected

    def test_different_each_time(self) -> None:
        a = generate_pkce()
        b = generate_pkce()
        assert a.code_verifier != b.code_verifier


# ---------------------------------------------------------------------------
# parse_redirect_uri() tests
# ---------------------------------------------------------------------------


class TestParseRedirectUri:
    def test_happy_path(self) -> None:
        url = _make_redirect_uri(code="abc", state="xyz")
        code = parse_redirect_uri(url, expected_state="xyz", expected_redirect_uri="https://example.com/callback")
        assert code == "abc"

    def test_state_mismatch_raises(self) -> None:
        url = _make_redirect_uri(code="abc", state="wrong")
        with pytest.raises(OAuth2Error, match="state_mismatch"):
            parse_redirect_uri(url, expected_state="expected", expected_redirect_uri="https://example.com/callback")

    def test_error_in_redirect_raises(self) -> None:
        url = "https://example.com/callback?error=access_denied&error_description=User+cancelled"
        with pytest.raises(OAuth2Error, match="access_denied"):
            parse_redirect_uri(url, expected_state="s", expected_redirect_uri="https://example.com/callback")

    def test_missing_code_raises(self) -> None:
        url = "https://example.com/callback?state=s"
        with pytest.raises(OAuth2Error, match="missing_code"):
            parse_redirect_uri(url, expected_state="s", expected_redirect_uri="https://example.com/callback")

    def test_redirect_uri_mismatch_raises(self) -> None:
        url = _make_redirect_uri(code="abc", state="s", base="https://evil.com/callback")
        with pytest.raises(OAuth2Error, match="redirect_uri_mismatch"):
            parse_redirect_uri(url, expected_state="s", expected_redirect_uri="https://example.com/callback")

    def test_redirect_uri_port_mismatch_raises(self) -> None:
        url = "http://localhost:9999/callback?code=abc&state=s"
        with pytest.raises(OAuth2Error, match="redirect_uri_mismatch"):
            parse_redirect_uri(url, expected_state="s", expected_redirect_uri="http://localhost:8080/callback")

    def test_redirect_uri_port_matches(self) -> None:
        url = "http://localhost:8080/callback?code=abc&state=s"
        code = parse_redirect_uri(url, expected_state="s", expected_redirect_uri="http://localhost:8080/callback")
        assert code == "abc"

    def test_redirect_uri_default_port_normalization(self) -> None:
        """https://example.com and https://example.com:443 should be equivalent."""
        url = "https://example.com:443/callback?code=abc&state=s"
        code = parse_redirect_uri(url, expected_state="s", expected_redirect_uri="https://example.com/callback")
        assert code == "abc"


# ---------------------------------------------------------------------------
# Prompt enum tests
# ---------------------------------------------------------------------------


class TestPromptEnum:
    def test_values(self) -> None:
        assert Prompt.NONE.value == "none"
        assert Prompt.CONSENT.value == "consent"
        assert Prompt.LOGIN.value == "login"
        assert Prompt.LOGIN_AND_CONSENT.value == "login consent"

    def test_is_string(self) -> None:
        assert isinstance(Prompt.LOGIN, str)


# ---------------------------------------------------------------------------
# AuthorizationCodeContext tests
# ---------------------------------------------------------------------------


class TestAuthorizationCodeContext:
    def test_defaults_auto_generate(self) -> None:
        ctx = AuthorizationCodeContext()
        assert ctx.pkce is not None
        assert ctx.nonce is not None
        assert ctx.state is not None
        assert ctx.pushed_authorization_request_enabled is True
        assert ctx.authentication_url is None

    def test_custom_values_preserved(self) -> None:
        pkce = generate_pkce()
        ctx = AuthorizationCodeContext(
            pkce=pkce,
            nonce="custom_nonce",
            state="custom_state",
            max_age=300.0,
            login_hint="user@example.com",
            prompt=Prompt.LOGIN,
        )
        assert ctx.pkce is pkce
        assert ctx.nonce == "custom_nonce"
        assert ctx.state == "custom_state"
        assert ctx.max_age == 300.0
        assert ctx.login_hint == "user@example.com"
        assert ctx.prompt == Prompt.LOGIN

    def test_parameters_authorization(self) -> None:
        from okta_client.authfoundation import OAuth2APIRequestCategory

        ctx = AuthorizationCodeContext(
            state="mystate",
            nonce="mynonce",
            max_age=600.0,
            prompt=Prompt.CONSENT,
            login_hint="user@test.com",
        )
        params = ctx.parameters(OAuth2APIRequestCategory.AUTHORIZATION)
        assert params is not None
        assert params["response_type"] == "code"
        assert params["state"] == "mystate"
        assert params["nonce"] == "mynonce"
        assert params["max_age"] == "600"
        assert params["prompt"] == "consent"
        assert params["login_hint"] == "user@test.com"
        assert "code_challenge" in params
        assert "code_challenge_method" in params

    def test_parameters_token(self) -> None:
        from okta_client.authfoundation import OAuth2APIRequestCategory

        ctx = AuthorizationCodeContext()
        params = ctx.parameters(OAuth2APIRequestCategory.TOKEN)
        assert params is not None
        assert "code_verifier" in params

    def test_parameters_other_category_empty(self) -> None:
        from okta_client.authfoundation import OAuth2APIRequestCategory

        ctx = AuthorizationCodeContext()
        params = ctx.parameters(OAuth2APIRequestCategory.CONFIGURATION)
        assert params is None

    def test_is_frozen(self) -> None:
        ctx = AuthorizationCodeContext()
        with pytest.raises(AttributeError):
            ctx.state = "new_state"  # type: ignore[misc]

    def test_implements_id_token_validator_context(self) -> None:
        from okta_client.authfoundation.oauth2.request_protocols import IDTokenValidatorContext

        ctx = AuthorizationCodeContext(nonce="n", max_age=42.0)
        assert isinstance(ctx, IDTokenValidatorContext)
        assert ctx.nonce == "n"
        assert ctx.max_age == 42.0


# ---------------------------------------------------------------------------
# Codable (to_dict / from_dict) tests
# ---------------------------------------------------------------------------


class TestContextSerialization:
    def test_roundtrip_defaults(self) -> None:
        """A default context should survive to_dict → from_dict unchanged."""
        ctx = AuthorizationCodeContext()
        data = ctx.to_dict()
        restored = AuthorizationCodeContext.from_dict(data)

        assert restored.state == ctx.state
        assert restored.nonce == ctx.nonce
        assert restored.pkce is not None
        assert ctx.pkce is not None
        assert restored.pkce.code_verifier == ctx.pkce.code_verifier
        assert restored.pkce.code_challenge == ctx.pkce.code_challenge
        assert restored.pkce.code_challenge_method == ctx.pkce.code_challenge_method
        assert restored.max_age == ctx.max_age
        assert restored.pushed_authorization_request_enabled == ctx.pushed_authorization_request_enabled

    def test_roundtrip_with_all_fields(self) -> None:
        ctx = AuthorizationCodeContext(
            state="my_state",
            nonce="my_nonce",
            max_age=300.0,
            login_hint="user@example.com",
            id_token_hint="prev_id_token",
            display="page",
            prompt=Prompt.LOGIN_AND_CONSENT,
            acr_values=["urn:acr:1"],
            ui_locales=["en", "fr"],
            claims_locales=["en"],
            pushed_authorization_request_enabled=False,
        )
        data = ctx.to_dict()
        restored = AuthorizationCodeContext.from_dict(data)

        assert restored.state == "my_state"
        assert restored.nonce == "my_nonce"
        assert restored.max_age == 300.0
        assert restored.login_hint == "user@example.com"
        assert restored.id_token_hint == "prev_id_token"
        assert restored.display == "page"
        assert restored.prompt == Prompt.LOGIN_AND_CONSENT
        assert restored.acr_values == ["urn:acr:1"]
        assert restored.ui_locales == ["en", "fr"]
        assert restored.claims_locales == ["en"]
        assert restored.pushed_authorization_request_enabled is False

    def test_to_dict_enums_are_values(self) -> None:
        ctx = AuthorizationCodeContext(prompt=Prompt.LOGIN)
        data = ctx.to_dict()
        assert data["prompt"] == "login"
        assert isinstance(data["prompt"], str)

    def test_to_dict_nested_pkce_is_dict(self) -> None:
        ctx = AuthorizationCodeContext()
        data = ctx.to_dict()
        assert isinstance(data["pkce"], dict)
        assert "code_verifier" in data["pkce"]

    def test_json_roundtrip(self) -> None:
        """Verify the dict is JSON-serializable and survives a JSON roundtrip."""
        ctx = AuthorizationCodeContext(prompt=Prompt.CONSENT, max_age=120.0)
        json_str = json.dumps(ctx.to_dict())
        restored = AuthorizationCodeContext.from_dict(json.loads(json_str))
        assert restored.prompt == Prompt.CONSENT
        assert restored.max_age == 120.0
        assert restored.pkce is not None
        assert ctx.pkce is not None
        assert restored.pkce.code_verifier == ctx.pkce.code_verifier

    def test_from_dict_missing_pkce_auto_generates(self) -> None:
        data = {"state": "s", "nonce": "n"}
        restored = AuthorizationCodeContext.from_dict(data)
        assert restored.pkce is not None
        assert restored.pkce.code_verifier


# ---------------------------------------------------------------------------
# AuthorizationCodeFlow.__init__ tests
# ---------------------------------------------------------------------------


class TestFlowInit:
    def test_missing_redirect_uri_raises(self) -> None:
        config = OAuth2ClientConfiguration(
            issuer="https://example.com",
            scope=["openid"],
            client_authorization=ClientIdAuthorization(id="cid"),
            # no redirect_uri
        )
        client = OAuth2Client(configuration=config, network=DummyNetwork())
        with pytest.raises(OAuth2Error, match="redirect_uri"):
            AuthorizationCodeFlow(client=client)

    def test_valid_init(self) -> None:
        client = _build_client(DummyNetwork())
        flow = AuthorizationCodeFlow(client=client)
        assert flow.client is client
        assert flow.context is None


# ---------------------------------------------------------------------------
# AuthorizationCodeFlow.start() — non-PAR (happy path)
# ---------------------------------------------------------------------------


class TestFlowStartNonPAR:
    def test_returns_authorization_url(self) -> None:
        network = DummyNetwork()
        client = _build_client(network)
        flow = AuthorizationCodeFlow(client=client)

        url = asyncio.run(flow.start())

        assert url.startswith("https://example.com/authorize?")
        parts = urlsplit(url)
        qs = parse_qs(parts.query)
        assert qs["response_type"] == ["code"]
        assert qs["client_id"] == ["test_client"]
        assert "code_challenge" in qs
        assert "state" in qs
        assert "nonce" in qs
        assert qs["scope"] == ["openid profile"]

    def test_context_has_authentication_url(self) -> None:
        client = _build_client(DummyNetwork())
        flow = AuthorizationCodeFlow(client=client)

        url = asyncio.run(flow.start())

        assert flow.context is not None
        assert flow.context.authentication_url == url

    def test_custom_context_used(self) -> None:
        client = _build_client(DummyNetwork())
        flow = AuthorizationCodeFlow(client=client)
        ctx = AuthorizationCodeContext(
            state="custom_state",
            login_hint="me@example.com",
            prompt=Prompt.LOGIN,
        )

        url = asyncio.run(flow.start(context=ctx))
        qs = parse_qs(urlsplit(url).query)
        assert qs["state"] == ["custom_state"]
        assert qs["login_hint"] == ["me@example.com"]
        assert qs["prompt"] == ["login"]

    def test_unsupported_grant_raises(self) -> None:
        config = {**_OPENID_CONFIG, "grant_types_supported": ["password"]}
        client = _build_client(DummyNetwork(openid_config=config))
        flow = AuthorizationCodeFlow(client=client)

        with pytest.raises(ValueError, match="not supported"):
            asyncio.run(flow.start())


# ---------------------------------------------------------------------------
# AuthorizationCodeFlow.start() — PAR (happy path)
# ---------------------------------------------------------------------------


class TestFlowStartPAR:
    def test_par_minimal_url(self) -> None:
        network = DummyNetwork(openid_config=_OPENID_CONFIG_WITH_PAR)
        client = _build_client(network)
        flow = AuthorizationCodeFlow(client=client)

        url = asyncio.run(flow.start())

        qs = parse_qs(urlsplit(url).query)
        assert qs["client_id"] == ["test_client"]
        assert qs["request_uri"] == ["urn:example:par:12345"]
        # Full query parameters should NOT be in the PAR URL
        assert "code_challenge" not in qs

    def test_par_disabled_fallback(self) -> None:
        """When context disables PAR, fall back to full URL even if server supports PAR."""
        network = DummyNetwork(openid_config=_OPENID_CONFIG_WITH_PAR)
        client = _build_client(network)
        flow = AuthorizationCodeFlow(client=client)
        ctx = AuthorizationCodeContext(pushed_authorization_request_enabled=False)

        url = asyncio.run(flow.start(context=ctx))

        qs = parse_qs(urlsplit(url).query)
        # Should be a full authorize URL, not a PAR redirect
        assert "code_challenge" in qs
        assert "request_uri" not in qs

    def test_par_failure_falls_back(self) -> None:
        """If PAR endpoint returns an error, fall back to regular URL."""
        network = DummyNetwork(
            openid_config=_OPENID_CONFIG_WITH_PAR,
            par_body={"error": "invalid_request"},
            par_status=400,
        )
        client = _build_client(network)
        flow = AuthorizationCodeFlow(client=client)

        url = asyncio.run(flow.start())

        qs = parse_qs(urlsplit(url).query)
        # Should have full parameters (fallback)
        assert "code_challenge" in qs
        assert "request_uri" not in qs


# ---------------------------------------------------------------------------
# AuthorizationCodeFlow.resume() tests
# ---------------------------------------------------------------------------


class TestFlowResume:
    def test_happy_path(self) -> None:
        network = DummyNetwork(
            token_body={"access_token": "tok", "token_type": "Bearer", "expires_in": 3600},
        )
        client = _build_client(network)
        flow = AuthorizationCodeFlow(client=client)

        auth_url = asyncio.run(flow.start())
        assert auth_url.startswith("https://example.com/authorize?")
        assert flow.context is not None
        state = flow.context.state

        redirect = _make_redirect_uri(code="authcode", state=state)
        token = asyncio.run(flow.resume(redirect))

        assert token.access_token == "tok"

    def test_resume_without_start_raises(self) -> None:
        client = _build_client(DummyNetwork())
        flow = AuthorizationCodeFlow(client=client)

        with pytest.raises(OAuth2Error, match="invalid_context"):
            asyncio.run(flow.resume("https://example.com/callback?code=x&state=y"))

    def test_state_mismatch_on_resume(self) -> None:
        network = DummyNetwork()
        client = _build_client(network)
        flow = AuthorizationCodeFlow(client=client)

        asyncio.run(flow.start())
        redirect = _make_redirect_uri(code="authcode", state="wrong_state")

        with pytest.raises(OAuth2Error, match="state_mismatch"):
            asyncio.run(flow.resume(redirect))

    def test_error_in_redirect_on_resume(self) -> None:
        network = DummyNetwork()
        client = _build_client(network)
        flow = AuthorizationCodeFlow(client=client)

        asyncio.run(flow.start())
        assert flow.context is not None
        redirect = f"https://example.com/callback?error=access_denied&state={flow.context.state}"

        with pytest.raises(OAuth2Error, match="access_denied"):
            asyncio.run(flow.resume(redirect))

    def test_token_validator_receives_nonce(self) -> None:
        """The token request should propagate nonce and max_age from context."""
        from okta_client.oauth2auth.authorization_code import AuthorizationCodeTokenRequest

        ctx = AuthorizationCodeContext(nonce="test_nonce", max_age=120.0)
        from okta_client.authfoundation.oauth2.models import OpenIdConfiguration

        oidc = OpenIdConfiguration.from_json(_OPENID_CONFIG)
        config = OAuth2ClientConfiguration(
            issuer="https://example.com",
            scope=["openid"],
            client_authorization=ClientIdAuthorization(id="cid"),
            redirect_uri="https://example.com/callback",
        )
        request = AuthorizationCodeTokenRequest(
            _openid_configuration=oidc,
            _client_configuration=config,
            additional_parameters=None,
            context=ctx,
            authorization_code="code123",
        )
        assert request.token_validator_context.nonce == "test_nonce"
        assert request.token_validator_context.max_age == 120.0


# ---------------------------------------------------------------------------
# Listener tests
# ---------------------------------------------------------------------------


class TestFlowListeners:
    def test_customize_url_called(self) -> None:
        customized = {}

        class MyListener:
            def authentication_started(self, flow): pass
            def authentication_updated(self, flow, context): pass
            def authentication_completed(self, flow, result): pass
            def authentication_failed(self, flow, error): pass

            def authentication_customize_url(self, flow, url_parts):
                url_parts["custom_param"] = "custom_value"
                customized["called"] = True
                return url_parts

            def authentication_should_authenticate(self, flow, url):
                customized["url"] = url

        client = _build_client(DummyNetwork())
        flow = AuthorizationCodeFlow(client=client)
        flow.listeners.add(MyListener())

        url = asyncio.run(flow.start())

        assert customized.get("called") is True
        assert "custom_param=custom_value" in url
        assert customized.get("url") == url

    def test_standard_listener_not_called_for_extended_methods(self) -> None:
        """A plain AuthenticationListener should NOT receive customize_url or should_authenticate."""

        class PlainListener:
            def authentication_started(self, flow): pass
            def authentication_updated(self, flow, context): pass
            def authentication_completed(self, flow, result): pass
            def authentication_failed(self, flow, error): pass

        client = _build_client(DummyNetwork())
        flow = AuthorizationCodeFlow(client=client)
        flow.listeners.add(PlainListener())

        # Should not raise — plain listener just doesn't get the extended calls
        url = asyncio.run(flow.start())
        assert url.startswith("https://example.com/authorize?")


# ---------------------------------------------------------------------------
# AuthorizationCodeTokenRequest body_parameters merge order
# ---------------------------------------------------------------------------


class TestTokenRequestMergeOrder:
    def test_grant_type_always_wins(self) -> None:
        from okta_client.authfoundation.oauth2.models import OpenIdConfiguration
        from okta_client.oauth2auth.authorization_code import AuthorizationCodeTokenRequest

        oidc = OpenIdConfiguration.from_json(_OPENID_CONFIG)
        config = OAuth2ClientConfiguration(
            issuer="https://example.com",
            scope=["openid"],
            client_authorization=ClientIdAuthorization(id="cid"),
            redirect_uri="https://example.com/callback",
        )
        ctx = AuthorizationCodeContext(state="s")
        request = AuthorizationCodeTokenRequest(
            _openid_configuration=oidc,
            _client_configuration=config,
            additional_parameters={"grant_type": "password"},
            context=ctx,
            authorization_code="code123",
        )
        assert request.body_parameters["grant_type"] == "authorization_code"
        assert request.body_parameters["code"] == "code123"
        assert "code_verifier" in request.body_parameters

    def test_config_scope_included(self) -> None:
        from okta_client.authfoundation.oauth2.models import OpenIdConfiguration
        from okta_client.oauth2auth.authorization_code import AuthorizationCodeTokenRequest

        oidc = OpenIdConfiguration.from_json(_OPENID_CONFIG)
        config = OAuth2ClientConfiguration(
            issuer="https://example.com",
            scope=["openid", "profile"],
            client_authorization=ClientIdAuthorization(id="cid"),
            redirect_uri="https://example.com/callback",
        )
        ctx = AuthorizationCodeContext()
        request = AuthorizationCodeTokenRequest(
            _openid_configuration=oidc,
            _client_configuration=config,
            additional_parameters=None,
            context=ctx,
            authorization_code="code",
        )
        params = request.body_parameters
        assert params.get("scope") == "openid profile"
        assert params.get("redirect_uri") == "https://example.com/callback"


# ---------------------------------------------------------------------------
# Flow state lifecycle
# ---------------------------------------------------------------------------


class TestFlowLifecycle:
    def test_state_transitions(self) -> None:
        from okta_client.authfoundation import AuthenticationState

        network = DummyNetwork(
            token_body={"access_token": "t", "token_type": "Bearer", "expires_in": 3600},
        )
        client = _build_client(network)
        flow = AuthorizationCodeFlow(client=client)

        assert flow.state == AuthenticationState.IDLE

        auth_url = asyncio.run(flow.start())
        assert auth_url.startswith("https://example.com/authorize?")
        assert flow.state == AuthenticationState.AUTHENTICATING

        assert flow.context is not None
        redirect = _make_redirect_uri(code="c", state=flow.context.state)
        asyncio.run(flow.resume(redirect))
        assert flow.state == AuthenticationState.COMPLETED

    def test_reset(self) -> None:
        from okta_client.authfoundation import AuthenticationState

        client = _build_client(DummyNetwork())
        flow = AuthorizationCodeFlow(client=client)
        asyncio.run(flow.start())
        assert flow.context is not None

        flow.reset()
        assert flow.context is None
        assert flow.state == AuthenticationState.IDLE
