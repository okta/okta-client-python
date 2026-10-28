# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## 0.3.1

### Security

- `ClientSecretAuthorization` and `ClientAssertionAuthorization` no longer contribute `client_secret`, `client_assertion`, or `client_assertion_type` to `AUTHORIZATION`-category parameters. Previously, `AuthorizationCodeFlow.start()` embedded the client secret (or assertion) as a query parameter in the browser-visible authorize URL whenever Pushed Authorization Requests were unavailable, disabled, or failed, exposing it to browser history, server logs, and `Referer` headers (RFC 6749 §2.3.1). Credentials are still sent on the back channel: in the token request and in the PAR request body (RFC 9126 §2).
- `AuthorizationCodeFlow` additionally strips `client_secret`, `client_assertion`, and `client_assertion_type` from the authorize URL query string regardless of which parameter source supplied them.
- The `authorization_code` sample now writes its saved flow context file with owner-only (`0600`) permissions, since it contains the PKCE code verifier.

### Changed

- `AuthorizationCodeFlow` logs a warning on the `okta_client.oauth2auth.authorization_code` logger when a Pushed Authorization Request fails and the flow falls back to a standard authorize URL, instead of falling back silently.

## 0.3.0

### Added

- `AuthenticationContext` base protocol now includes optional `nonce`, `max_age`, `audience`, and `resource` properties, available across all authentication flows.
- `StandardAuthenticationContext` concrete implementation for non-redirect flows (`ResourceOwnerFlow`, `JWTBearerFlow`, `RefreshTokenFlow`).
- `AuthorizationCodeContext` gains `audience` (`str | None`) and `resource` (`str | Sequence[str] | None`) fields, contributed to the token request per RFC 8707.
- `TokenExchangeContext` gains `nonce`, `max_age`, `audience`, and `resource` fields from the base context.
- `CrossAppAccessFlow.start()` now accepts an optional `resource` parameter (RFC 8707), forwarded to the token exchange alongside `audience` and `scope`.

### Changed

- `IDTokenValidatorContext` is deprecated; `AuthenticationContext` now subsumes its role for ID token validation.
- `OAuth2Error` now exposes an `additional_fields` mapping containing any non-standard keys returned in the error response body, so server-specific remediation hints are no longer discarded.
- `OAuth2Error.from_response()` classmethod builds an error from a parsed OAuth2 error response body, mapping standard RFC 6749 fields to their attributes and collecting the rest into `additional_fields`.

## 0.2.0

### Added

- Class-level `default_network` on `OAuth2Client` (`get_default_network` / `set_default_network`) to set a global default `NetworkInterface` for all new client instances, with thread-safe access.
- `DefaultNetworkInterface` now accepts an optional `proxy` parameter to route outgoing requests through an HTTP/HTTPS proxy.

## 0.1.0

### Added

- Initial SDK release with core networking, OAuth 2.0 / OpenID Connect support.
- Authentication flows: Resource Owner, Authorization Code (with PKCE & PAR), JWT Bearer, Token Exchange, Device Authorization, Refresh Token.
- Cross-App Authorization flow for AI agent use cases.
- Browser-based sign-in integration via `browser_signin` module.
- Token lifecycle management with credential storage.
- JWT creation, parsing, and validation (JWK / JWKS).
- OpenID Connect discovery and configuration caching.
- Listener-based extensibility for API clients, OAuth2 clients, and authentication flows.
- `pyproject.toml`-based packaging with PEP 561 `py.typed` marker.
