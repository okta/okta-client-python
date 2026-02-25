# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

import os
from pathlib import Path

from okta_client.authfoundation import (
    ClientSecretAuthorization,
    ConfigurationFileNotFoundError,
    InvalidConfigurationError,
    OAuth2ClientConfiguration,
)
from okta_client.authfoundation.oauth2.client_authorization import ClientAssertionAuthorization, ClientIdAuthorization


def test_configuration_loads_json() -> None:
    path = Path(__file__).parent / "resources" / "configs" / "okta.json"
    config = OAuth2ClientConfiguration.from_file(path)

    assert isinstance(config.client_authorization, ClientSecretAuthorization)
    assert config.client_authorization.id == "client"
    assert config.client_authorization.secret == "secret"
    assert config.issuer == "https://example.com"
    assert config.scope == ["openid", "profile"]
    assert config.redirect_uri == "com.example:/callback"
    assert config.additional_parameters == {"custom_param": "value"}


def test_configuration_loads_ini() -> None:
    path = Path(__file__).parent / "resources" / "configs" / "okta.ini"
    config = OAuth2ClientConfiguration.from_file(path)

    assert isinstance(config.client_authorization, ClientIdAuthorization)
    assert config.client_authorization.id == "client"
    assert config.scope == ["openid", "profile"]
    assert config.logout_redirect_uri == "com.example:/logout"
    assert config.additional_parameters == {"extra": "foo"}


def test_configuration_loads_client_assertion() -> None:
    path = Path(__file__).parent / "resources" / "configs" / "okta-client-assertion.json"
    config = OAuth2ClientConfiguration.from_file(path)

    assert isinstance(config.client_authorization, ClientAssertionAuthorization)
    assert config.client_authorization.assertion == "assertion-jwt"
    assert config.issuer == "https://example.com"
    assert config.scope == ["openid", "profile"]
    assert config.additional_parameters == {"custom_param": "value"}


def test_configuration_default_path_and_env_override() -> None:
    cwd = Path.cwd()
    resources_dir = Path(__file__).parent / "resources" / "configs"
    try:
        os.chdir(resources_dir)
        config = OAuth2ClientConfiguration.from_default()
        assert isinstance(config.client_authorization, ClientSecretAuthorization)
        assert config.client_authorization.id == "client"
        assert config.client_authorization.secret == "secret"
        assert config.scope == ["openid", "profile"]

        override = resources_dir / "custom.json"
        os.environ["OKTA_CLIENT_CONFIG"] = str(override)
        config = OAuth2ClientConfiguration.from_default()
        assert isinstance(config.client_authorization, ClientIdAuthorization)
        assert config.client_authorization.id == "override"
    finally:
        os.environ.pop("OKTA_CLIENT_CONFIG", None)
        os.chdir(cwd)


def test_configuration_missing_required_fields() -> None:
    try:
        OAuth2ClientConfiguration.from_mapping({"issuer": "https://example.com"})
    except InvalidConfigurationError:
        return
    raise AssertionError("Expected InvalidConfigurationError for missing fields")


def test_configuration_default_missing_file() -> None:
    cwd = Path.cwd()
    empty_dir = Path(__file__).parent / "resources"
    try:
        os.chdir(empty_dir)
        try:
            OAuth2ClientConfiguration.from_default()
        except ConfigurationFileNotFoundError:
            return
        raise AssertionError("Expected ConfigurationFileNotFoundError")
    finally:
        os.chdir(cwd)
