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

import configparser
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..networking import APIClientConfiguration, RequestValue
from .client_authorization import (
    ClientAssertionAuthorization,
    ClientAuthorization,
    ClientIdAuthorization,
    ClientSecretAuthorization,
)
from .parameters import OAuth2APIRequestCategory, ProvidesOAuth2Parameters


@dataclass(frozen=True, init=False)
class OAuth2ClientConfiguration(APIClientConfiguration, ProvidesOAuth2Parameters):
    """Configuration values required for OAuth2/OIDC client operations.

    Usage examples:
        OAuth2ClientConfiguration.from_default()
        OAuth2ClientConfiguration.from_file("./okta.json")
        OAuth2ClientConfiguration.from_mapping({"issuer": "https://example.com", "client_id": "abc", "scope": ["openid"]})
    """
    issuer: str
    scope: list[str] | None | str | None = None
    redirect_uri: str | None = None
    logout_redirect_uri: str | None = None
    client_authorization: ClientAuthorization | None = None
    additional_parameters: Mapping[str, str] | None = None
    metadata_cache_ttl: float | None = 3600.0

    @property
    def client_id(self) -> str | None:
        if self.client_authorization:
            return self.client_authorization.client_id
        return None

    def __init__(
        self,
        *,
        issuer: str,
        scope: list[str] | None | str | None = None,
        client_authorization: ClientAuthorization | None = None,
        redirect_uri: str | None = None,
        logout_redirect_uri: str | None = None,
        additional_parameters: Mapping[str, str] | None = None,
        metadata_cache_ttl: float | None = 3600.0,
        base_url: str | None = None,
        user_agent: str | None = None,
        additional_http_headers: Mapping[str, str] | None = None,
        request_id_header: str | None = None,
        timeout: float | None = None,
    ) -> None:
        resolved_base_url = base_url or issuer
        super().__init__(
            base_url=resolved_base_url,
            user_agent=user_agent or "",
            additional_http_headers=additional_http_headers,
            request_id_header=request_id_header,
            timeout=timeout,
        )
        if isinstance(scope, str):
            scope = [item for item in scope.split(" ") if item]

        object.__setattr__(self, "issuer", issuer)
        object.__setattr__(self, "scope", scope)
        object.__setattr__(self, "client_authorization", client_authorization)
        object.__setattr__(self, "redirect_uri", redirect_uri)
        object.__setattr__(self, "logout_redirect_uri", logout_redirect_uri)
        object.__setattr__(self, "additional_parameters", additional_parameters)
        object.__setattr__(self, "metadata_cache_ttl", metadata_cache_ttl)

    def parameters(self, category: OAuth2APIRequestCategory) -> Mapping[str, RequestValue] | None:
        """Return OAuth2 parameters for the given request category."""
        result: dict[str, RequestValue] = {}
        if self.additional_parameters:
            result.update({key: value for key, value in self.additional_parameters.items()})

        if category in (OAuth2APIRequestCategory.AUTHORIZATION, OAuth2APIRequestCategory.TOKEN):
            if self.scope:
                result["scope"] = " ".join(self.scope)
            if self.redirect_uri:
                result["redirect_uri"] = self.redirect_uri
        if self.client_authorization:
            auth_params = self.client_authorization.parameters(category)
            if auth_params:
                result.update(auth_params)

        return result or None

    @classmethod
    def from_default(cls) -> OAuth2ClientConfiguration:
        """Load configuration from the default file or OKTA_CLIENT_CONFIG override.

        Searches for `okta.json` or `okta.ini` in the current working directory unless
        `OKTA_CLIENT_CONFIG` is set to an explicit file path.
        """
        override = os.environ.get("OKTA_CLIENT_CONFIG")
        if override:
            return cls.from_file(override)
        for candidate in ("okta.json", "okta.ini"):
            path = Path.cwd() / candidate
            if path.exists():
                return cls.from_file(path)
        raise ConfigurationFileNotFoundError("No default configuration file found")

    @classmethod
    def from_file(cls, path: str | Path) -> OAuth2ClientConfiguration:
        """Load configuration from a JSON or INI file path."""
        file_path = Path(path)
        if not file_path.exists():
            raise ConfigurationFileNotFoundError(f"Configuration file not found: {file_path}")
        if file_path.suffix.lower() == ".json":
            data = _load_json(file_path)
        elif file_path.suffix.lower() in {".ini", ".cfg"}:
            data = _load_ini(file_path)
        else:
            try:
                data = _load_json(file_path)
            except ConfigurationParseError:
                data = _load_ini(file_path)
        return cls.from_mapping(data)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> OAuth2ClientConfiguration:
        """Validate and build configuration from a mapping of values."""
        issuer = _require_string(data, "issuer")
        scope = _parse_scope(data.get("scope"))
        if not scope:
            raise InvalidConfigurationError("scope is required")

        _validate_url("issuer", issuer)
        redirect_uri = _optional_string(data.get("redirect_uri"))
        logout_redirect_uri = _optional_string(data.get("logout_redirect_uri"))
        client_id = _require_string(data, "client_id")
        client_secret = _optional_string(data.get("client_secret"))
        client_assertion = _optional_string(data.get("client_assertion"))
        base_url = _optional_string(data.get("base_url"))
        user_agent = _optional_string(data.get("user_agent"))
        request_id_header = _optional_string(data.get("request_id_header"))
        timeout = _optional_float(data.get("timeout"))
        metadata_cache_ttl = _optional_float(data.get("metadata_cache_ttl"))
        additional_http_headers = _optional_mapping(data.get("additional_http_headers"))
        client_authorization: ClientAuthorization | None = None
        if client_assertion:
            client_authorization = ClientAssertionAuthorization(assertion=client_assertion)
        elif client_id:
            if client_secret is not None and client_secret != "":
                client_authorization = ClientSecretAuthorization(id=client_id, secret=client_secret)
            else:
                client_authorization = ClientIdAuthorization(id=client_id)

        additional_parameters = _additional_parameters(data)

        return cls(
            issuer=issuer,
            scope=scope,
            client_authorization=client_authorization,
            redirect_uri=redirect_uri,
            logout_redirect_uri=logout_redirect_uri,
            additional_parameters=additional_parameters or None,
            metadata_cache_ttl=metadata_cache_ttl if metadata_cache_ttl is not None else 3600.0,
            base_url=base_url,
            user_agent=user_agent,
            additional_http_headers=additional_http_headers,
            request_id_header=request_id_header,
            timeout=timeout,
        )


class ConfigurationError(ValueError):
    """Base configuration error."""


class ConfigurationFileNotFoundError(ConfigurationError):
    """Raised when a configuration file cannot be located."""


class ConfigurationParseError(ConfigurationError):
    """Raised when a configuration file cannot be parsed."""


class InvalidConfigurationError(ConfigurationError):
    """Raised when required configuration values are missing or invalid."""


def _load_json(path: Path) -> Mapping[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except Exception as exc:
        raise ConfigurationParseError(f"Unable to parse JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigurationParseError("JSON configuration must be an object")
    return data


def _load_ini(path: Path) -> Mapping[str, Any]:
    parser = configparser.ConfigParser()
    try:
        with path.open("r", encoding="utf-8") as handle:
            parser.read_file(handle)
    except Exception as exc:
        raise ConfigurationParseError(f"Unable to parse INI: {exc}") from exc
    section = parser["okta"] if "okta" in parser else parser[parser.default_section]
    return dict(section)


def _parse_scope(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if isinstance(value, str):
        return [item for item in value.split() if item]
    return []


def _require_string(data: Mapping[str, Any], key: str) -> str:
    value = _optional_string(data.get(key))
    if not value:
        raise InvalidConfigurationError(f"{key} is required")
    return value


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    string_value = str(value).strip()
    return string_value or None


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _optional_mapping(value: Any) -> Mapping[str, str] | None:
    if isinstance(value, Mapping):
        return {str(key): str(val) for key, val in value.items()}
    return None


def _validate_url(name: str, value: str) -> None:
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        raise InvalidConfigurationError(f"{name} must be a valid URL")


def _additional_parameters(data: Mapping[str, Any]) -> dict[str, str]:
    known = {
        "base_url",
        "user_agent",
        "additional_http_headers",
        "request_id_header",
        "timeout",
        "metadata_cache_ttl",
        "issuer",
        "client_id",
        "scope",
        "redirect_uri",
        "logout_redirect_uri",
        "client_secret",
        "client_assertion",
        "client_assertion_type",
    }
    extras: dict[str, str] = {}
    for key, value in data.items():
        if key in known:
            continue
        if isinstance(value, str):
            extras[key] = value
    return extras


