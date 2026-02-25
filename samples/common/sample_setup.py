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
from dataclasses import replace

from okta_client.authfoundation import OAuth2Client, OAuth2ClientConfiguration
from samples.common.logging_listener import ConsoleLoggingAPIClientListener

_CONFIG_KEYS: tuple[str, ...] = (
    "issuer",
    "client_id",
    "scope",
    "redirect_uri",
    "logout_redirect_uri",
    "client_secret",
    "client_assertion",
)


def load_configuration(args: argparse.Namespace) -> OAuth2ClientConfiguration:
    if getattr(args, "config", None):
        config = OAuth2ClientConfiguration.from_file(args.config)
    else:
        data: dict[str, str] = {}
        for key in _CONFIG_KEYS:
            if not hasattr(args, key):
                continue
            value = getattr(args, key)
            if value is not None:
                data[key] = value

        config = OAuth2ClientConfiguration.from_mapping(data) if data else OAuth2ClientConfiguration.from_default()

    # Apply any CLI overrides on top of the loaded configuration.
    overrides: dict[str, object] = {}
    for key in _CONFIG_KEYS:
        value = getattr(args, key, None)
        if value is not None and hasattr(config, key) and getattr(config, key, None) != value:
            overrides[key] = value
    if overrides:
        config = replace(config, **overrides)

    # Remove any keys whose values are an empty string
    config_dict = {key: value for key, value in config.__dict__.items() if value != ""}

    return OAuth2ClientConfiguration(**config_dict)

def build_oauth_client(
    config: OAuth2ClientConfiguration,
    *,
    verbose: bool = False,
    user_agent: str = "okta-client-python-sample",
) -> OAuth2Client:
    if config.user_agent != user_agent or config.base_url != config.issuer:
        config = replace(config, user_agent=user_agent, base_url=config.issuer)
    client = OAuth2Client(configuration=config)

    if verbose:
        client.listeners.add(ConsoleLoggingAPIClientListener())

    return client
