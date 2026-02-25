# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
