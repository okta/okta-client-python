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
from dataclasses import replace

from okta_client.authfoundation import (
    ConfigurationFileNotFoundError,
    InvalidConfigurationError,
    OAuth2Error,
)
from okta_client.authfoundation.oauth2.client_authorization import ClientAssertionAuthorization
from okta_client.oauth2auth import TokenExchangeContext, TokenExchangeFlow, TokenType
from samples.common.cli_inputs import TestConfiguration
from samples.common.sample_setup import build_oauth_client, load_configuration
from samples.common.token_output import print_token_details


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Token Exchange flow sample (RFC 8693).")
    parser.add_argument("--config", help="Path to okta.json or okta.ini")
    parser.add_argument("--issuer", help="Issuer URL")
    parser.add_argument("--client_id", help="Client ID")
    parser.add_argument("--scope", help="Scopes (space-separated)")
    parser.add_argument("--client_secret", help="Client secret")
    parser.add_argument("--client_assertion", help="Client assertion JWT value")
    parser.add_argument("--subject-token", help="Subject token value")
    parser.add_argument("--subject-type", help="Subject token type (access_token, id_token, refresh_token, device_secret, or URN)")
    parser.add_argument("--actor-token", help="Actor token value (optional)")
    parser.add_argument("--actor-type", help="Actor token type (access_token, id_token, refresh_token, device_secret, or URN)")
    parser.add_argument("--audience", help="Audience value (optional)")
    parser.add_argument("--resource", action="append", help="Resource value (repeatable)")
    parser.add_argument("--requested-token-type", help="Requested token type (access_token, id_token, refresh_token, device_secret, id_jag, or URN)")
    parser.add_argument("--param", action="append", help="Additional parameter (key=value). Repeatable.")
    parser.add_argument("--test-config", dest="test_config", help="Path to test-configuration.json (subject_token, subject_type, actor_token, actor_type)")
    parser.add_argument("--verbose", action="store_true", help="Log raw requests and responses")
    return parser


def _parse_token_type(value: str | None) -> str | TokenType:
    if not value:
        raise ValueError("Token type is required")
    normalized = value.strip().lower()
    if normalized.startswith("urn:"):
        return value.strip()
    normalized = normalized.replace("-", "_")
    mapping = {
        "id_token": TokenType.ID_TOKEN,
        "access_token": TokenType.ACCESS_TOKEN,
        "device_secret": TokenType.DEVICE_SECRET,
        "refresh_token": TokenType.REFRESH_TOKEN,
        "id_jag": TokenType.ID_JAG,
    }
    return mapping.get(normalized, value.strip())


def _parse_resources(values: list[str] | None) -> list[str] | None:
    if not values:
        return None
    resources: list[str] = []
    for item in values:
        if not item:
            continue
        parts = [part.strip() for part in item.split(",") if part.strip()]
        resources.extend(parts or [item.strip()])
    return resources or None


def _parse_token_entry(
    prefix: str,
    args: argparse.Namespace,
    test_config: TestConfiguration,
    *,
    required: bool = False,
) -> dict[str, object] | None:
    token_value = getattr(args, f"{prefix}_token") or test_config.values.get(f"{prefix}_token")
    type_value = getattr(args, f"{prefix}_type") or test_config.values.get(f"{prefix}_type")
    if not token_value or not type_value:
        if required:
            missing = []
            if not token_value:
                missing.append(f"--{prefix}-token")
            if not type_value:
                missing.append(f"--{prefix}-type")
            raise ValueError(f"Missing required input(s): {', '.join(missing)}")
        return None
    return {"type": _parse_token_type(type_value), "value": token_value}


def main() -> None:
    parser = _build_parser()
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        return

    args = parser.parse_args()
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

    oauth_client = build_oauth_client(config, verbose=args.verbose)
    flow = TokenExchangeFlow(client=oauth_client)

    try:
        subject_entry = _parse_token_entry("subject", args, test_config, required=True)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        parser.print_help(sys.stderr)
        sys.exit(1)

    parameters: dict[str, object] = {
        "subject": subject_entry,
    }

    actor_entry = _parse_token_entry("actor", args, test_config)
    if actor_entry:
        parameters["actor"] = actor_entry

    audience = args.audience or test_config.values.get("audience")
    if audience:
        parameters["audience"] = audience

    resource_values = args.resource or test_config.values.get("resource")
    if resource_values and not isinstance(resource_values, list):
        resource_values = [resource_values]
    resources = _parse_resources(resource_values) if resource_values else None
    if resources:
        parameters["resource"] = resources

    scope_value = args.scope or test_config.values.get("scope")
    scope = [item for item in (scope_value or "").split() if item] or None

    requested_token_type_value = args.requested_token_type or test_config.values.get("requested_token_type")
    requested_token_type = (
        _parse_token_type(requested_token_type_value) if requested_token_type_value else None
    )

    additional_parameters = test_config.additional_parameters()

    context = TokenExchangeContext(
        scope=scope,
        requested_token_type=requested_token_type,
        _additional_parameters=additional_parameters or None,
    )

    try:
        token = asyncio.run(flow.start(parameters, context=context))
    except OAuth2Error as error:
        print(f"Token exchange failed: {error}")
        sys.exit(1)
    except Exception as error:
        print(f"Unexpected error: {error}")
        sys.exit(1)

    print()
    print_token_details(token)


if __name__ == "__main__":
    main()
