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

from okta_client.authfoundation import (
    ConfigurationFileNotFoundError,
    InvalidConfigurationError,
    OAuth2Error,
)
from okta_client.authfoundation.authentication import StandardAuthenticationContext
from okta_client.authfoundation.oauth2.refresh_token import RefreshTokenFlow
from samples.common.cli_inputs import TestConfiguration
from samples.common.sample_setup import build_oauth_client, load_configuration
from samples.common.token_output import print_token_details


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Refresh Token flow sample.")
    parser.add_argument("--config", help="Path to okta.json or okta.ini")
    parser.add_argument("--issuer", help="Issuer URL")
    parser.add_argument("--client_id", help="Client ID")
    parser.add_argument("--scope", help="Scopes (space-separated)")
    parser.add_argument("--client_secret", help="Client secret")
    parser.add_argument("--refresh-token", help="Refresh token value")
    parser.add_argument("--param", action="append", help="Additional parameter (key=value). Repeatable.")
    parser.add_argument(
        "--test-config",
        dest="test_config",
        help="Path to test-configuration.json (refresh_token, scope)",
    )
    parser.add_argument("--verbose", action="store_true", help="Log raw requests and responses")
    return parser


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

    refresh_token = args.refresh_token or test_config.get_secret("refresh_token", "Refresh Token")
    if not refresh_token:
        print("Missing required input: --refresh-token", file=sys.stderr)
        parser.print_help(sys.stderr)
        sys.exit(1)

    scope_value = args.scope or test_config.values.get("scope")
    scope = [item for item in (scope_value or "").split() if item] or None

    oauth_client = build_oauth_client(config, verbose=args.verbose)
    additional_parameters = test_config.additional_parameters()
    flow = RefreshTokenFlow(client=oauth_client, additional_parameters=additional_parameters or None)

    try:
        refreshed = asyncio.run(
            flow.start(refresh_token, scope=scope, context=StandardAuthenticationContext())
        )
    except OAuth2Error as error:
        print(f"Refresh failed: {error}", file=sys.stderr)
        sys.exit(1)
    except Exception as error:
        print(f"Unexpected error: {error}", file=sys.stderr)
        sys.exit(1)

    print()
    print_token_details(refreshed)


if __name__ == "__main__":
    main()
