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
import json
import sys
import time
import uuid
from typing import Any

from okta_client.authfoundation import LocalKeyProvider
from okta_client.authfoundation.time_coordinator import get_time_coordinator
from samples.common.cli_inputs import TestConfiguration


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="JWT assertion generator (RFC 7523).")
    parser.add_argument("--claims-json", help="JWT claims as JSON string")
    parser.add_argument("--claims-file", help="Path to JSON file with JWT claims")
    parser.add_argument("--expires-in", type=int, help="Seconds from now to set exp claim")
    parser.add_argument("--key", help="JWT signing key (shared secret, PEM, or JWK JSON)")
    parser.add_argument("--key-file", help="Path to PEM file for signing")
    parser.add_argument("--key-id", help="Key ID (kid) header")
    parser.add_argument("--token-id", help="JWT token ID (jti) claim")
    parser.add_argument("--algorithm", help="JWT algorithm (e.g., RS256, HS256)")
    parser.add_argument("--test-config", dest="test_config", help="Path to test-configuration.json")
    return parser


def _load_claims(args: argparse.Namespace, test_config: TestConfiguration) -> dict[str, Any]:
    claims_file = args.claims_file or test_config.values.get("claims_file")
    claims_json = None
    if not claims_file:
        claims_json = args.claims_json or test_config.get("claims_json", "JWT claims JSON")
    if claims_file:
        with open(claims_file, encoding="utf-8") as handle:
            data = json.load(handle)
    else:
        if not claims_json:
            raise ValueError("claims_json is required when claims_file is not provided")
        data = json.loads(claims_json)
    if not isinstance(data, dict):
        raise ValueError("JWT claims must be a JSON object")
    expires_in = args.expires_in or test_config.get("expires_in", "JWT expires in (seconds)")
    if expires_in is not None:
        try:
            exp_value = int(expires_in)
        except (TypeError, ValueError):
            raise ValueError("--expires-in must be an integer") from None
        data["exp"] = int(time.time()) + exp_value
    data["jti"] = args.token_id or test_config.values.get("token_id") or str(uuid.uuid4())

    return data


def _load_key(args: argparse.Namespace, test_config: TestConfiguration) -> tuple[Any, str, str | None]:
    key_file = args.key_file or test_config.get("key_file", "JWT key file (optional)")
    key_value = None
    if not key_file:
        key_value = args.key or test_config.get_secret("key", "JWT signing key")
    key_id = args.key_id or test_config.get("key_id", "JWT key id (optional)")
    algorithm = args.algorithm or test_config.values.get("algorithm") or "RS256"
    if key_file:
        provider = LocalKeyProvider.from_pem_file(key_file, algorithm=algorithm, key_id=key_id or None)
        return provider.key, provider.algorithm, provider.key_id

    key_str = str(key_value)
    if key_str.strip().startswith("{"):
        try:
            key_data = json.loads(key_str)
        except json.JSONDecodeError:
            key_data = key_str
    else:
        key_data = key_str
    return key_data, algorithm, key_id


def main() -> None:
    parser = _build_parser()
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        return

    args = parser.parse_args()
    try:
        test_config = TestConfiguration(args.test_config)
        claims = _load_claims(args, test_config)
        key, algorithm, key_id = _load_key(args, test_config)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as error:
        print(f"Configuration error: {error}", file=sys.stderr)
        sys.exit(1)

    claims["iat"] = int(get_time_coordinator().now())

    provider = LocalKeyProvider(key=key, algorithm=algorithm, key_id=key_id)
    assertion = provider.sign_jwt(claims)
    print(assertion)


if __name__ == "__main__":
    main()
