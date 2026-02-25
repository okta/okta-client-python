# Samples

This directory contains runnable examples and shared helpers.

## Resource Owner Password Flow (CLI)

> **Warning**: The Resource Owner Password flow is not recommended for production use.
> It bypasses modern MFA protections. Prefer DirectAuth when available.

### Usage

1. Create an okta.json or okta.ini configuration file in the repo root (or set `OKTA_CLIENT_CONFIG`).

Example okta.json:

```json
{
  "issuer": "https://example.com",
  "client_id": "client-id",
  "scope": "openid profile"
}
```

2. Run the sample:

```bash
python -m samples.resource_owner --config okta.ini
```

Add `--verbose` to log raw requests and responses:

```bash
python -m samples.resource_owner --config okta.ini --verbose

To supply test credentials from JSON (for CI), use `--test-config`:

```bash
python -m samples.resource_owner --config okta.json --test-config test-configuration.json
```

You will be prompted for a username and password. The sample will exchange credentials for a token and print the token details.

## Token Exchange Flow (CLI)

### Usage

1. Create an okta.json or okta.ini configuration file in the repo root (or set `OKTA_CLIENT_CONFIG`).
2. Run the sample with a subject token:

```bash
python -m samples.token_exchange \
  --config okta.json \
  --subject-token "$SUBJECT_TOKEN" \
  --subject-type access_token
```

Optional actor token:

```bash
python -m samples.token_exchange \
  --config okta.json \
  --subject-token "$SUBJECT_TOKEN" \
  --subject-type access_token \
  --actor-token "$ACTOR_TOKEN" \
  --actor-type id_token
```

Optional parameters (audience/resource/scope/requested token type):

```bash
python -m samples.token_exchange \
  --config okta.json \
  --subject-token "$SUBJECT_TOKEN" \
  --subject-type access_token \
  --audience api://default \
  --resource https://resource.example.com \
  --scope "openid profile" \
  --requested-token-type access_token
```

Add `--verbose` to log raw requests and responses. Use `--test-config` to supply token values from JSON in CI.

## Refresh Token Flow (CLI)

### Usage

1. Create an okta.json or okta.ini configuration file in the repo root (or set `OKTA_CLIENT_CONFIG`).
2. Run the sample with a refresh token:

```bash
python -m samples.refresh_token \
  --config okta.json \
  --refresh-token "$REFRESH_TOKEN"
```

Optional scope and additional parameters:

```bash
python -m samples.refresh_token \
  --config okta.json \
  --refresh-token "$REFRESH_TOKEN" \
  --scope "openid profile" \
  --param device_secret=my-device-secret
```

Add `--verbose` to log raw requests and responses. Use `--test-config` to supply the refresh token from JSON in CI.

## JWT Bearer Flow (CLI)

### Usage

1. Create an okta.json or okta.ini configuration file in the repo root (or set `OKTA_CLIENT_CONFIG`).
2. Run the sample with a pre-built assertion:

```bash
python -m samples.jwt_bearer \
  --config okta.json \
  --assertion "$JWT_ASSERTION"
```

Or generate an assertion using local key material:

```bash
python -m samples.jwt_bearer \
  --config okta.json \
  --jwt-issuer client-id \
  --jwt-subject client-id \
  --jwt-audience https://example.com/token \
  --jwt-expires-in 300 \
  --jwt-key-file ./private.pem \
  --jwt-algorithm RS256
```

Add `--param` for additional token request parameters. Add `--verbose` to log raw requests and responses.

## JWT Assertion Generator (CLI)

### Usage

Generate an assertion from a JSON claims payload and a PEM key file:

```bash
python -m samples.jwt_assertion \
  --claims-file ./claims.json \
  --key-file ./private.pem \
  --algorithm RS256
```

Or pass the claims as JSON:

```bash
python -m samples.jwt_assertion \
  --claims-json '{"iss":"client","sub":"client","aud":"https://example.com/token","exp":1234567890}' \
  --key "my-shared-secret" \
  --algorithm HS256
```

## Shared helpers

- Logging listener: [samples/common/logging_listener.py](samples/common/logging_listener.py)

## Security notes

- Avoid using real production credentials.
- Do not commit secrets or credentials.
