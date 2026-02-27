[<img src="https://www.okta.com/sites/default/files/Dev_Logo-01_Large-thumbnail.png" align="right" width="256px" alt="Okta Developer Logo"/>](https://devforum.okta.com/)

# Okta Client SDK for Python

[![PyPI](https://img.shields.io/pypi/v/okta-client-python)](https://pypi.org/project/okta-client-python/)
[![Python Versions](https://img.shields.io/pypi/pyversions/okta-client-python)](https://pypi.org/project/okta-client-python/)
[![License](https://img.shields.io/pypi/l/okta-client-python)](LICENSE)

The Okta Client SDK represents a collection of SDKs for different languages, each of which itself is a modular ecosystem of libraries that build upon one-another to enable client applications to:

* Authenticate clients with an Authorization Server (AS) using a variety of authentication flows.
<!-- * Flexibly store and manage the resulting tokens enabling a wide variety of use-cases. -->
* Transparently persist and manage the lifecycle of those tokens through authentication, refresh, and revocation.
* Secure applications and tokens, using best practices, by default.

This SDK emphasizes security, developer experience, and customization of the SDK's core capabilities. It is built as a platform, enabling you to choose the individual library components you need for your application.

**Table of Contents**

<!-- TOC depthFrom:2 depthTo:3 -->
<!-- /TOC -->

## Release status

This library uses semantic versioning and follows Okta's [Library Version Policy][okta-library-versioning].

| Version | Status                             |
| ------- | ---------------------------------- |
| 0.1.0   | Current release                    |

The latest release can always be found on the [releases page][github-releases].

### Dependencies

The SDK requires **Python 3.10+** or higher, and has the following runtime dependency:

* [PyJWT](https://pyjwt.readthedocs.io/)

## Need help?

If you run into problems using the SDK, you can:

* Ask questions on the [Okta Developer Forums][devforum]
* Post [issues][github-issues] here on GitHub (for code errors)

## Getting Started

To get started, you will need:

* An Okta account, called an _organization_ (sign up for a free [developer organization](https://developer.okta.com/signup) if you need one).
* An Okta Application. Use Okta's administrator console to create the application by following the wizard and using default properties.

For examples of how this SDK can be utilized, please refer to the [sample applications](samples) included within this repository.

### Quick Start

```python
import asyncio
from okta_client.authfoundation import OAuth2Client, OAuth2ClientConfiguration
from okta_client.oauth2auth import AuthorizationCodeFlow

# Load configuration from a JSON file (see Configuration section below)
config = OAuth2ClientConfiguration.from_file("okta.json")
client = OAuth2Client(configuration=config)

# Start an Authorization Code + PKCE flow
flow = AuthorizationCodeFlow(client=client)
authorize_url = asyncio.run(flow.start())
# → Redirect the user to authorize_url

# After the user is redirected back to your app:
token = asyncio.run(flow.resume("http://localhost:8080/callback?code=...&state=..."))
print("Access token:", token.access_token)
```

### Installation

Install via pip:

```bash
pip install okta-client-python
```

Or install from source:

```bash
git clone https://github.com/okta/okta-client-python.git
cd okta-client-python
pip install -e .
```

### Modules

This SDK consists of several different libraries/packages, each with detailed documentation.

* `okta_client.authfoundation` -- Common classes for managing tokens, validation and security, network handling, and common type definitions. Used as a foundation for all other libraries.
* `okta_client.oauth2auth` -- OAuth2 authentication capabilities for advanced use-cases.
* `okta_client.oktadirectauth` -- Authenticate using Okta's DirectAuth APIs. _(Coming Soon)_

This SDK enables you to build or support a myriad of different authentication flows and approaches.

## Usage Guide

All authentication flows require an `OAuth2Client`, which is constructed from
an `OAuth2ClientConfiguration` and performs the underlying HTTP requests. The
examples below assume you already have a configuration — see
[Configuration](#configuration) for how to create one.

```python
from okta_client.authfoundation import OAuth2Client, OAuth2ClientConfiguration

config = OAuth2ClientConfiguration.from_file("okta.json")
oauth_client = OAuth2Client(configuration=config)
```

### Configuration

`OAuth2ClientConfiguration` holds the issuer, client credentials, scopes, and
redirect URIs needed by every flow. There are several ways to create one:

**From a JSON or INI file:**

```python
from okta_client.authfoundation import OAuth2ClientConfiguration

config = OAuth2ClientConfiguration.from_file("okta.json")
```

A typical `okta.json` looks like:

```json
{
  "issuer": "https://example.okta.com/oauth2/default",
  "client_id": "0oa...",
  "scope": "openid profile offline_access",
  "redirect_uri": "http://localhost:8080/callback"
}
```

**From the default location** (`okta.json` or `okta.ini` in the current working
directory, overridden by `OKTA_CLIENT_CONFIG`):

```python
config = OAuth2ClientConfiguration.from_default()
```

**From a mapping (dictionary):**

```python
config = OAuth2ClientConfiguration.from_mapping({
    "issuer": "https://example.okta.com/oauth2/default",
    "client_id": "0oa...",
    "scope": ["openid", "profile"],
    "redirect_uri": "http://localhost:8080/callback",
})
```

**Directly, with keyword arguments:**

```python
from okta_client.authfoundation import (
    OAuth2ClientConfiguration,
    ClientSecretAuthorization,
)

config = OAuth2ClientConfiguration(
    issuer="https://example.okta.com/oauth2/default",
    scope=["openid", "profile", "offline_access"],
    redirect_uri="http://localhost:8080/callback",
    client_authorization=ClientSecretAuthorization(
        id="0oa...",
        secret="your-client-secret",
    ),
)
```

---


### Client Authorization Strategies

The `client_authorization` field controls how the client authenticates with the
authorization server:

| Strategy | When to use |
| --- | --- |
| `ClientIdAuthorization(id=...)` | Public clients (no secret). |
| `ClientSecretAuthorization(id=..., secret=...)` | Confidential clients with a shared secret. |
| `ClientAssertionAuthorization(assertion=...)` | Pre-built JWT assertion string. |
| `ClientAssertionAuthorization(assertion_claims=..., key_provider=...)` | SDK-managed assertion signing using a `KeyProvider`. |

When using `from_file` or `from_mapping`, the strategy is inferred automatically
from the presence of `client_id`, `client_secret`, or `client_assertion` keys.

## Authentication Flows

OAuth2 supports a variety of authentication flows, each with its own capabilities, configuration, and limitations. To ensure developers do not need to be experts in the variety of options available to you, these flows follow a common set of patterns that allows the peculiarities of each flow to be encapsulated.

In general, these authentication flows conform to a common `AuthenticationFlow` protocol, and feature a `start` function, and an optional `resume` function for "multi-step" flows.

### Web Redirect Authentication using OIDC

`AuthorizationCodeFlow` implements the Authorization Code + PKCE flow defined in
[RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636). It optionally uses
Pushed Authorization Requests (PAR) as defined in
[RFC 9126](https://datatracker.ietf.org/doc/html/rfc9126) when the server
supports them.

This is a two-step flow:

1. **`start()`** — generates a PKCE code verifier/challenge, builds the
   authorization URL (using PAR if available), and returns the URL string.
2. **`resume(redirect_uri)`** — parses the authorization code from the redirect,
   validates state, and exchanges the code for tokens.

<details>
<summary>
Show example
</summary>

```python
import asyncio
from okta_client.authfoundation import OAuth2Client, OAuth2ClientConfiguration
from okta_client.oauth2auth import (
    AuthorizationCodeFlow,
    AuthorizationCodeContext,
    Prompt,
)

config = OAuth2ClientConfiguration.from_file("okta.json")
oauth_client = OAuth2Client(configuration=config)
flow = AuthorizationCodeFlow(client=oauth_client)

# Step 1: Build the authorization URL
context = AuthorizationCodeContext(
    prompt=Prompt.LOGIN,          # force login screen
    login_hint="user@example.com",  # pre-populate username
)
authorize_url = asyncio.run(flow.start(context=context))
print("Open this URL in a browser:", authorize_url)

# ... user signs in and is redirected back ...

# Step 2: Exchange the authorization code for tokens
redirect_url = "http://localhost:8080/callback?code=abc&state=xyz"
token = asyncio.run(flow.resume(redirect_url))

print("Access token:", token.access_token)
print("ID token:",     token.id_token)
print("Refresh token:", token.refresh_token)
```

</details>

**Context options:**

| Field | Description |
| --- | --- |
| `prompt` | `Prompt.NONE`, `Prompt.LOGIN`, `Prompt.CONSENT`, `Prompt.LOGIN_AND_CONSENT` |
| `login_hint` | Pre-populate the username field on the login page. |
| `pushed_authorization_request_enabled` | Enable PAR (default `True`). |
| `max_age` | Maximum age (seconds) before re-authentication is required. |
| `state` | Custom state string (auto-generated UUID by default). |

---

### Username / Password Sign In

`ResourceOwnerFlow` implements the Resource Owner Password Credentials grant
([RFC 6749 §4.3](https://datatracker.ietf.org/doc/html/rfc6749#section-4.3)).

> **Warning:** This flow sends credentials directly to the authorization server
> and is not recommended for production applications. Prefer the
> Authorization Code flow or Okta's DirectAuth SDK instead (available in a
> future release of this SDK).

<details>
<summary>
Show example
</summary>

```python
import asyncio
from okta_client.authfoundation import OAuth2Client, OAuth2ClientConfiguration
from okta_client.oauth2auth import ResourceOwnerFlow

config = OAuth2ClientConfiguration.from_file("okta.json")
oauth_client = OAuth2Client(configuration=config)
flow = ResourceOwnerFlow(client=oauth_client)

token = asyncio.run(flow.start("jane@example.com", "super-secret-password"))

print("Access token:", token.access_token)
```

Additional parameters can be passed at construction time for flows or authorization
servers that require extra fields:

```python
flow = ResourceOwnerFlow(
    client=oauth_client,
    additional_parameters={"custom_value": "123456"},
)
```

</details>

---

### Exchanging Access or ID Tokens For New Tokens

`TokenExchangeFlow` implements the OAuth 2.0 Token Exchange standard
([RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693)). It exchanges a
subject token (and optional actor token) for a new token with a different type,
audience, or scope.

<details>
<summary>
Show example
</summary>

```python
import asyncio
from okta_client.authfoundation import OAuth2Client, OAuth2ClientConfiguration
from okta_client.oauth2auth import TokenExchangeFlow, TokenType

config = OAuth2ClientConfiguration.from_file("okta.json")
oauth_client = OAuth2Client(configuration=config)
flow = TokenExchangeFlow(client=oauth_client)

# Keyword form (recommended)
token = asyncio.run(flow.start(
    subject_token="eyJhbGci...",
    subject_token_type=TokenType.ID_TOKEN,
    audience="api://my-resource-server",
    requested_token_type=TokenType.ACCESS_TOKEN,
))

print("Exchanged access token:", token.access_token)
```

The `scope` parameter is optional and is used to **down-scope** the resulting
token — that is, request a subset of the scopes the subject token already
carries. When omitted, the authorization server issues the new token with the
full set of scopes associated with the subject token. Only include `scope` when
you want to restrict the exchanged token to narrower permissions than the
original:

```python
# Request only "openid" even though the subject token may carry more scopes
token = asyncio.run(flow.start(
    subject_token="eyJhbGci...",
    subject_token_type=TokenType.ACCESS_TOKEN,
    audience="api://my-resource-server",
    scope=["openid"],
))
```

You can also use the structured form with `TokenExchangeParameters`:

```python
from okta_client.oauth2auth import TokenExchangeParameters, TokenDescriptor

params = TokenExchangeParameters(
    subject=TokenDescriptor(
        token_type=TokenType.ACCESS_TOKEN,
        value="eyJhbGci...",
    ),
    audience="api://my-resource-server",
)
token = asyncio.run(flow.start(params))
```

**Supported token types:**

| `TokenType` | Description |
| --- | --- |
| `ID_TOKEN` | OpenID Connect ID token. |
| `ACCESS_TOKEN` | OAuth 2.0 access token. |
| `REFRESH_TOKEN` | Refresh token. |
| `DEVICE_SECRET` | Device secret. |
| `ID_JAG` | Identity Assertion Authorization Grant (used internally by `CrossAppAccessFlow`). |

</details>

### Authenticating Using Signed JWT Tokens

`JWTBearerFlow` exchanges a signed JWT assertion for an access
token using the JWT Bearer grant type
([RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523)). This allows a client to use a pre-registered private key to sign a JWT assertion which can be used to generate access tokens.

You have the choice of signing JWT assertions yourself, or the SDK can do the JWT token generation for you.

<details>
<summary>
Show example
</summary>

#### Option A: Using pre-built assertions

When you already have a signed JWT assertion, simply pass it to `start()`:

```python
import asyncio
from okta_client.authfoundation import OAuth2Client, OAuth2ClientConfiguration
from okta_client.oauth2auth import JWTBearerFlow

config = OAuth2ClientConfiguration.from_file("okta.json")
oauth_client = OAuth2Client(configuration=config)
flow = JWTBearerFlow(client=oauth_client)

signed_jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
token = asyncio.run(flow.start(assertion=signed_jwt))
```

#### Option B: Automatic assertion generation

When you want the SDK to handle JWT generation and signing, pass the claims and key provider:

```python
import asyncio
from okta_client.authfoundation import (
    OAuth2Client,
    OAuth2ClientConfiguration,
    LocalKeyProvider,
)
from okta_client.authfoundation.oauth2.jwt_bearer_claims import JWTBearerClaims
from okta_client.oauth2auth import JWTBearerFlow

config = OAuth2ClientConfiguration.from_file("okta.json")
oauth_client = OAuth2Client(configuration=config)
flow = JWTBearerFlow(client=oauth_client)

claims = JWTBearerClaims(
    issuer="0oa...",       # client ID or trusted issuer
    subject="user@example.com",
    audience="https://example.okta.com/oauth2/default/v1/token",
    expires_in=300,        # 5 minutes
)
key_provider = LocalKeyProvider.from_pem_file(
    "private_key.pem",
    algorithm="RS256",
    key_id="my-key-id",
)

token = asyncio.run(flow.start(
    assertion_claims=claims,
    key_provider=key_provider,
))
```

You can also generate the assertion separately using the static helper:

```python
signed_jwt = JWTBearerFlow.generate_assertion(claims, key_provider)
```

</details>

### Refreshing Tokens

`RefreshTokenFlow` uses an existing refresh token to obtain a fresh access token
without user interaction.

<details>
<summary>
Show example
</summary>

```python
import asyncio
from okta_client.authfoundation import OAuth2Client, OAuth2ClientConfiguration
from okta_client.authfoundation.oauth2.refresh_token import RefreshTokenFlow

config = OAuth2ClientConfiguration.from_file("okta.json")
oauth_client = OAuth2Client(configuration=config)
flow = RefreshTokenFlow(client=oauth_client)

refreshed = asyncio.run(flow.start("existing-refresh-token-value"))

print("New access token:", refreshed.access_token)
print("New refresh token:", refreshed.refresh_token)
```

The `scope` parameter is optional and is used to **down-scope** the refreshed
token. When omitted, the new access token retains the same scopes as the
original. Pass `scope` only when you want the refreshed token to carry fewer
permissions:

```python
# Refresh but drop down to only "openid" scope
refreshed = asyncio.run(flow.start(
    "existing-refresh-token-value",
    scope=["openid"],
))
```

</details>

### Cross App Access for AI Agents

`CrossAppAccessFlow` implements the Identity Assertion Authorization
Grant (ID-JAG) pattern for cross-application access. This is designed
for AI agent scenarios where one application needs to obtain access
tokens for a different resource server on behalf of its user.

The flow operates in two steps:

1. **`start()`** — exchanges the user's ID token (or access token) for an
   ID-JAG via [RFC 8693 token exchange](#exchanging-access-or-id-tokens-for-new-tokens).
2. **`resume()`** — exchanges the ID-JAG for a resource-server access token
   via the [RFC 7523 JWT bearer grant](#authenticating-using-signed-jwt-tokens).

<details>
<summary>
Show example
</summary>

#### `target` vs `audience`

The constructor's `target` (or `target_authorization_server_id`) and the
`audience` argument to `start()` serve different purposes:

* **`target`** configures the _resource_ authorization server that `resume()`
  will talk to. The flow uses the target's issuer to build the `OAuth2Client`
  for the JWT bearer exchange (Step 2), including discovering its token
  endpoint and rewriting the client assertion's `aud` claim.

* **`audience`** is the value sent in the token-exchange request (Step 1) to
  tell your _originating_ authorization server what audience the ID-JAG should
  carry. The originating AS embeds this value into the ID-JAG so the resource
  AS will accept it.

In the common case these are the same issuer URL — the resource server's
issuer — so the values match. They are kept separate because the token-exchange
audience is a logical parameter of the request, while the target is a
structural configuration that determines which server the second leg talks to.

#### Path 1 — Automatic (key-provider auth)

When the client uses `ClientAssertionAuthorization` with `assertion_claims` and
a `key_provider` (or a `ClientSecretAuthorization`), the flow handles both
steps automatically:

```python
import asyncio
from okta_client.authfoundation import (
    OAuth2Client,
    OAuth2ClientConfiguration,
    LocalKeyProvider,
)
from okta_client.authfoundation.oauth2.jwt_bearer_claims import JWTBearerClaims
from okta_client.authfoundation.oauth2.client_authorization import (
    ClientAssertionAuthorization,
)
from okta_client.oauth2auth import (
    CrossAppAccessFlow,
    CrossAppAccessTarget,
)

key_provider = LocalKeyProvider.from_pem_file("private_key.pem", algorithm="RS256")

config = OAuth2ClientConfiguration(
    issuer="https://example.okta.com/oauth2/default",
    client_authorization=ClientAssertionAuthorization(
        assertion_claims=JWTBearerClaims(
            issuer="0oa...",
            subject="0oa...",
            audience="https://example.okta.com/oauth2/default/v1/token",
            expires_in=300,
        ),
        key_provider=key_provider,
    ),
)

oauth_client = OAuth2Client(configuration=config)
target = CrossAppAccessTarget(
    issuer="https://example.okta.com/oauth2/my-resource-server",
)

flow = CrossAppAccessFlow(client=oauth_client, target=target)

# Step 1: exchange user token for ID-JAG
result = await flow.start(token="<user-id-token>")

# result.resume_assertion_claims is None → fully automatic
assert result.resume_assertion_claims is None

# Step 2: exchange ID-JAG for resource access token
access_token = await flow.resume()
print("Resource access token:", access_token.access_token)
```

#### Path 2 — Manual signing (pre-built assertion auth)

When the client uses a pre-built `assertion` string without a key provider,
`start()` returns a `CrossAppExchangeResult` with `resume_assertion_claims`
populated. You must sign those claims and pass the JWT back to `resume()`:

```python
result = await flow.start(token="<user-id-token>")

if result.resume_assertion_claims:
    # Sign the claims using your own signing mechanism
    signed_jwt = my_key_provider.sign_jwt(
        result.resume_assertion_claims.to_claims()
    )
    access_token = await flow.resume(client_assertion=signed_jwt)
```

Alternatively, pass a `key_provider` to `resume()` and let the flow sign for
you:

```python
    access_token = await flow.resume(key_provider=my_key_provider)
```

#### Target Configuration

Supply the target authorization server using either a
`CrossAppAccessTarget` or the shorthand
`target_authorization_server_id`:

```python
# Full target object
flow = CrossAppAccessFlow(
    client=oauth_client,
    target=CrossAppAccessTarget(
        issuer="https://example.okta.com/oauth2/my-resource-server",
    ),
)

# Shorthand — resolved relative to the client issuer
flow = CrossAppAccessFlow(
    client=oauth_client,
    target_authorization_server_id="my-resource-server",
)
```

</details>

## Listeners

A common pattern within this SDK is the use of "Listeners" which enable developers to observe key events within the SDK's lifecycle. This permits you to implement some protocol within your application, and add your class instance as a listener to the client or flow you would like to observe.

Listeners are managed through a `ListenerCollection` accessible via the `listeners` property on both flows and clients:

```python
# Adding a listener to a flow
flow.listeners.add(my_listener)

# Removing a listener from a flow
flow.listeners.remove(my_listener)

# Adding a listener to an OAuth2Client
oauth_client.listeners.add(my_listener)
```

You only need to implement the methods you care about — any method you omit will simply be a no-op.

### OAuth2Client Listener

All requests made by an `OAuth2Client` (including those made internally by flows) fire events that can be observed by implementing the `OAuth2ClientListener` protocol, which is an extension of a more generic `APIClientListener` protocol. You can add an instance of your listener to the client's `listeners` collection to start receiving events.

#### `APIClientListener`

The base network-level listener observes raw HTTP request/response lifecycle events on any `APIClient` (including `OAuth2Client`):

| Method | When it fires |
| --- | --- |
| `will_send(client, request)` | Before an HTTP request is sent. |
| `did_send(client, request, response)` | After a successful response is received. |
| `did_send_error(client, request, error)` | When a request fails with an exception. |
| `should_retry(client, request, rate_limit)` | To determine retry behavior (return an `APIRetry`). |

<details>
<summary>Show example</summary>

```python
from okta_client.authfoundation import APIClientListener, APIRetry, OAuth2Client

class RequestLogger(APIClientListener):
    def will_send(self, client, request):
        print(f"→ {request.method.value} {request.url}")

    def did_send(self, client, request, response):
        print(f"← {response.status_code}")

    def did_send_error(self, client, request, error):
        print(f"✗ {error}")

    def should_retry(self, client, request, rate_limit):
        return APIRetry.default()

oauth_client = OAuth2Client(configuration=config)
oauth_client.listeners.add(RequestLogger())
```

</details>

#### `OAuth2ClientListener`

Extends `APIClientListener` with token-refresh lifecycle events:

| Method | When it fires |
| --- | --- |
| `will_refresh_token(client, token)` | Before a token refresh begins. |
| `did_refresh_token(client, token, refreshed_token)` | After a token refresh completes (or fails — `refreshed_token` may be `None`). |

<details>
<summary>Show example</summary>

```python
from okta_client.authfoundation.oauth2.client import OAuth2ClientListener

class TokenRefreshLogger(OAuth2ClientListener):
    def will_refresh_token(self, client, token):
        print(f"Refreshing token (expires_at={token.expires_at})...")

    def did_refresh_token(self, client, token, refreshed_token):
        if refreshed_token:
            print(f"Token refreshed (new expires_at={refreshed_token.expires_at})")
        else:
            print("Token refresh failed")

    # Inherited from APIClientListener — implement as needed
    def will_send(self, client, request): ...
    def did_send(self, client, request, response): ...
    def did_send_error(self, client, request, error): ...
    def should_retry(self, client, request, rate_limit):
        return APIRetry.default()

oauth_client.listeners.add(TokenRefreshLogger())
```

</details>

### Authentication Flow Listeners

All [authentication flows](#authentication-flows) support listeners that conform to the `AuthenticationListener` protocol, while some extend this base protocol with flow-specific callbacks. This enables you to observe and customize the authentication process at key points, without needing to modify the flow's core logic.

Every authentication flow fires these four lifecycle events:

| Method | When it fires |
| --- | --- |
| `authentication_started(flow)` | When `start()` begins authenticating. |
| `authentication_updated(flow, context)` | When the flow updates its internal context. |
| `authentication_completed(flow, result)` | When the flow completes successfully. |
| `authentication_failed(flow, error)` | When the flow fails with an exception. |

This listener works with **all** flows — [Resource Owner](#username--password-sign-in), [Token Exchange](#exchanging-access-or-id-tokens-for-new-tokens), [JWT Bearer](#authenticating-using-signed-jwt-tokens), [Refresh Token](#refreshing-tokens), [Authorization Code](#web-redirect-authentication-using-oidc), and [Cross-App Access](#cross-app-access-for-ai-agents):

<details>
<summary>Show example</summary>

```python
from okta_client.authfoundation.authentication import AuthenticationListener

class FlowObserver(AuthenticationListener):
    def authentication_started(self, flow):
        print(f"Flow started: {flow.__class__.__name__}")

    def authentication_updated(self, flow, context):
        print(f"Context updated: {context}")

    def authentication_completed(self, flow, result):
        print(f"Flow completed with token: {result.access_token[:20]}...")

    def authentication_failed(self, flow, error):
        print(f"Flow failed: {error}")

# Works with any flow
flow = ResourceOwnerFlow(client=oauth_client)
flow.listeners.add(FlowObserver())
```

</details>

> **NOTE:** Some flows may fire additional callbacks specific to their implementation. For example, the `AuthorizationCodeFlow` has two extra callbacks related to the construction of the authorization URL. If you need to observe or customize those events, implement the flow-specific listener described below.

#### `AuthorizationCodeFlowListener`

Extends `AuthenticationListener` with two additional callbacks specific to the authorization URL construction:

| Method | When it fires |
| --- | --- |
| `authentication_customize_url(flow, url_parts)` | Before the authorize URL is finalized. Return the (possibly modified) dict of query parameters. |
| `authentication_should_authenticate(flow, url)` | After the URL is created. Use this to log, record, or present the URL. |

<details>
<summary>Show example
</summary>

```python
from okta_client.oauth2auth import AuthorizationCodeFlowListener

class AuthCodeObserver(AuthorizationCodeFlowListener):
    def authentication_customize_url(self, flow, url_parts):
        # Inject a custom parameter into the authorize URL
        url_parts["acr_values"] = "urn:okta:loa:2fa:any"
        return url_parts

    def authentication_should_authenticate(self, flow, url):
        print(f"Please open: {url}")

    # Inherited base lifecycle events
    def authentication_started(self, flow):
        print("Authorization code flow started")

    def authentication_completed(self, flow, result):
        print("Tokens received!")

flow = AuthorizationCodeFlow(client=oauth_client)
flow.listeners.add(AuthCodeObserver())
```

</details>

### Cross App Access Listener

`CrossAppAccessFlowListener` extends `AuthenticationListener` with four callbacks that track the two-step ID-JAG exchange:

| Method | When it fires |
| --- | --- |
| `will_exchange_token_for_id_jag(flow, subject_token_type)` | Before the token exchange request (Step 1) is sent. |
| `did_exchange_token_for_id_jag(flow, id_jag_token)` | After the ID-JAG token is received from the exchange. |
| `will_exchange_id_jag_for_access_token(flow, id_jag_token)` | Before the JWT bearer grant (Step 2) is sent. |
| `did_exchange_id_jag_for_access_token(flow, access_token)` | After the resource-server access token is received. |

<details>
<summary>Show example
</summary>

```python
from okta_client.oauth2auth import CrossAppAccessFlowListener

class MyListener(CrossAppAccessFlowListener):
    def will_exchange_token_for_id_jag(self, flow, subject_token_type):
        print(f"Exchanging {subject_token_type} for ID-JAG...")

    def did_exchange_token_for_id_jag(self, flow, id_jag_token):
        print("Got ID-JAG token")

    def will_exchange_id_jag_for_access_token(self, flow, id_jag_token):
        print("Exchanging ID-JAG for access token...")

    def did_exchange_id_jag_for_access_token(self, flow, access_token):
        print("Got resource access token")

flow = CrossAppAccessFlow(client=oauth_client, target=target)
flow.listeners.add(MyListener())
```

</details>

## Development

Development dependencies may be installed using the `make deps` test target. As you implement features, ensure lint formatting checks are valid (using the `make lint` convenience if necessary), and that [unit tests pass](#running-tests).

### Project Feedback

This SDK is being actively developed, with plans for future expansion.

We are always seeking feedback from the developer community to evaluate:

* The overall SDK and its components
* The APIs and overall developer experience
* Use-cases or features that may be missed or do not align with your application’s needs
* Suggestions for future development
* Any other comments or feedback

### Running Tests

Unit tests may be run from the command line using the Makefile `test` target:

```bash
make test
```

End-to-end integration tests are also available, but requires additional setup and configuration.

```bash
make integration
```

> *NOTE:* The test environment and configuration files required for running integration tests are not documented at this time.

### Known issues

* Integration test configuration and org setup is not yet documented.

### Contributing

We are happy to accept contributions and PRs! Please see the [contribution guide](.github/CONTRIBUTING.md) to understand how to structure a contribution.

[okta-library-versioning]: https://developer.okta.com/code/library-versions
[github-issues]: https://github.com/okta/okta-client-python/issues
[github-releases]: https://github.com/okta/okta-client-python/releases
[devforum]: https://devforum.okta.com/
