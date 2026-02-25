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

import argparse
import asyncio
import sys
from collections.abc import Mapping
from dataclasses import replace

from okta_client.authfoundation import (
    ConfigurationFileNotFoundError,
    InvalidConfigurationError,
    LocalKeyProvider,
    OAuth2Error,
)
from okta_client.authfoundation.oauth2.client_authorization import ClientAssertionAuthorization
from okta_client.authfoundation.oauth2.jwt_bearer_claims import JWTBearerClaims
from okta_client.oauth2auth import JWTBearerFlow
from samples.common.cli_inputs import TestConfiguration
from samples.common.sample_setup import build_oauth_client, load_configuration
from samples.common.token_output import print_token_details


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="JWT Bearer flow sample (RFC 7523).")
    parser.add_argument("--config", help="Path to okta.json or okta.ini")
    parser.add_argument("--issuer", help="Issuer URL")
    parser.add_argument("--client_id", help="Client ID")
    parser.add_argument("--scope", help="Scopes (space-separated)")
    parser.add_argument("--client_secret", help="Client secret")
    parser.add_argument("--client_assertion", help="Client assertion JWT value")
    parser.add_argument("--assertion", help="Pre-built JWT assertion (optional)")
    parser.add_argument("--jwt-issuer", help="JWT issuer (iss)")
    parser.add_argument("--jwt-subject", help="JWT subject (sub)")
    parser.add_argument("--jwt-audience", help="JWT audience (aud)")
    parser.add_argument("--jwt-expires-in", type=int, help="JWT expiration in seconds (exp = now + value)")
    parser.add_argument("--jwt-key", help="JWT signing key (shared secret, PEM, or JWK JSON)")
    parser.add_argument("--jwt-key-file", help="Path to PEM file for signing")
    parser.add_argument("--jwt-key-id", help="Key ID (kid) header")
    parser.add_argument("--jwt-algorithm", help="JWT algorithm (e.g., RS256, HS256)")
    parser.add_argument("--param", action="append", help="Additional parameter (key=value). Repeatable.")
    parser.add_argument("--test-config", dest="test_config", help="Path to test-configuration.json")
    parser.add_argument("--verbose", action="store_true", help="Log raw requests and responses")
    return parser


def _resolve_assertion_or_claims(
    args: argparse.Namespace,
    test_config: TestConfiguration,
    config_parameters: Mapping[str, str] | None,
) -> tuple[str | None, JWTBearerClaims | None, LocalKeyProvider | None]:
    assertion = args.assertion or test_config.values.get("assertion")
    if assertion:
        return assertion, None, None

    config_parameters = config_parameters or {}

    issuer = args.jwt_issuer or config_parameters.get("jwt_issuer") or test_config.get("jwt_issuer", "JWT issuer (iss)")
    subject = args.jwt_subject or config_parameters.get("jwt_subject") or test_config.get("jwt_subject", "JWT subject (sub)")
    audience = args.jwt_audience or config_parameters.get("jwt_audience") or test_config.get("jwt_audience", "JWT audience (aud)")
    expires_in_value = (
        args.jwt_expires_in
        or config_parameters.get("jwt_expires_in")
        or test_config.get("jwt_expires_in", "JWT expires in (seconds)")
    )
    try:
        expires_in_int = int(expires_in_value)
    except (TypeError, ValueError):
        raise ValueError("--jwt-expires-in must be an integer") from None

    key_file = (
        args.jwt_key_file
        or config_parameters.get("jwt_key_file")
        or test_config.get("jwt_key_file", "JWT key file (optional)")
    )
    key_value = None
    if not key_file:
        key_value = (
            args.jwt_key
            or config_parameters.get("jwt_key")
            or test_config.get_secret("jwt_key", "JWT signing key")
        )
    key_id = (
        args.jwt_key_id
        or config_parameters.get("jwt_key_id")
        or test_config.get("jwt_key_id", "JWT key id (optional)")
    )
    algorithm = (
        args.jwt_algorithm
        or config_parameters.get("jwt_algorithm")
        or test_config.get("jwt_algorithm", "JWT algorithm (default RS256)")
        or "RS256"
    )

    if key_file:
        provider = LocalKeyProvider.from_pem_file(key_file, algorithm=algorithm, key_id=key_id or None)
    else:
        provider = LocalKeyProvider(key=str(key_value), algorithm=algorithm, key_id=key_id)

    claims = JWTBearerClaims(
        issuer=str(issuer),
        subject=str(subject),
        audience=str(audience),
        expires_in=expires_in_int,
    )
    return None, claims, provider


def main() -> None:
    parser = _build_parser()
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        return

    args = parser.parse_args()
    if not args.config and args.test_config:
        args.config = args.test_config
    try:
        config = load_configuration(args)
        test_config = TestConfiguration(args.test_config, param_values=list(args.param or []))
    except (ConfigurationFileNotFoundError, InvalidConfigurationError) as error:
        print(f"Configuration error: {error}", file=sys.stderr)
        parser.print_help(sys.stderr)
        sys.exit(1)
    except (FileNotFoundError, ValueError) as error:
        print(f"Test configuration error: {error}", file=sys.stderr)
        sys.exit(1)

    client_assertion = args.client_assertion or test_config.values.get("client_assertion")
    if client_assertion:
        additional_parameters = dict(config.additional_parameters or {})
        additional_parameters.pop("client_assertion", None)
        config = replace(
            config,
            client_authorization=ClientAssertionAuthorization(assertion=client_assertion),
            additional_parameters=additional_parameters or None,
        )

    jwt_reserved_keys = {
        "assertion",
        "jwt_issuer",
        "jwt_subject",
        "jwt_audience",
        "jwt_expires_in",
        "jwt_key",
        "jwt_key_file",
        "jwt_key_id",
        "jwt_algorithm",
    }

    if config.additional_parameters:
        filtered_config_params = {
            key: value
            for key, value in config.additional_parameters.items()
            if key not in jwt_reserved_keys
        }
        config = replace(config, additional_parameters=filtered_config_params or None)

    oauth_client = build_oauth_client(config, verbose=args.verbose)
    additional_parameters = test_config.additional_parameters()
    filtered_parameters = {
        key: value for key, value in additional_parameters.items() if key not in jwt_reserved_keys
    }
    flow = JWTBearerFlow(
        client=oauth_client,
        additional_parameters=filtered_parameters or None,
    )

    try:
        assertion, claims, provider = _resolve_assertion_or_claims(
            args,
            test_config,
            config.additional_parameters or None,
        )
    except ValueError as error:
        print(str(error), file=sys.stderr)
        parser.print_help(sys.stderr)
        sys.exit(1)

    try:
        token = asyncio.run(
            flow.start(
                assertion=assertion,
                assertion_claims=claims,
                key_provider=provider,
            )
        )
    except OAuth2Error as error:
        print(f"JWT bearer flow failed: {error}")
        sys.exit(1)
    except Exception as error:
        print(f"Unexpected error: {error}")
        sys.exit(1)

    print()
    print_token_details(token)


if __name__ == "__main__":
    main()
