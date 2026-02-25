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

import getpass
import json
import sys
from collections.abc import Callable, Mapping
from pathlib import Path


class TestConfiguration:
    """Lazy-access configuration that prompts for missing values."""

    def __init__(
        self,
        path: str | None,
        input_func: Callable[[str], str] = input,
        secret_func: Callable[[str], str] = getpass.getpass,
        param_values: list[str] | None = None,
    ) -> None:
        self._path = path
        self._input_func = input_func
        self._secret_func = secret_func
        self._param_values = [value for value in (param_values or []) if value]
        self._values = self._load_values(path)
        self._merge_param_values()

    @property
    def values(self) -> Mapping[str, str]:
        """Return the loaded key/value pairs."""
        return dict(self._values)

    def additional_parameters(self) -> Mapping[str, str]:
        """Return merged additional parameters parsed from CLI/config values."""
        return self._parse_additional_params(self._param_values)

    def get(self, key: str, label: str) -> str | None:
        """Return a value or prompt if missing."""
        value = self._values.get(key)
        if value:
            return value
        if not sys.stdin.isatty():
            return None
        response = self._input_func(f"{label}: ").strip()
        return response or None

    def get_secret(self, key: str, label: str) -> str | None:
        """Return a secret value or prompt if missing."""
        value = self._values.get(key)
        if value:
            return value
        if not sys.stdin.isatty():
            return None
        response = self._secret_func(f"{label}: ")
        return response.strip() or None

    @staticmethod
    def _load_values(path: str | None) -> dict[str, str]:
        if not path:
            return {}
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"Test configuration file not found: {file_path}")
        with file_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            raise ValueError("Test configuration must be a JSON object")
        values: dict[str, str] = {}
        for key, value in data.items():
            if isinstance(value, str) and value.strip():
                values[str(key)] = value.strip()
            elif isinstance(value, (int, float)):
                values[str(key)] = str(value)
        return values

    def _merge_param_values(self) -> None:
        config_param = self._values.get("param")
        if not config_param:
            return
        self._param_values.extend([value.strip() for value in config_param.split(",") if value.strip()])

    def _parse_additional_params(self, values: list[str] | None) -> Mapping[str, str]:
        if not values:
            return {}
        params: dict[str, str] = {}
        for item in values:
            if not item:
                continue
            if "=" not in item:
                raise ValueError(f"Invalid --param value: {item}. Expected key=value.")
            key, value = item.split("=", 1)
            key = key.strip()
            value = value.strip()
            if key:
                params[key] = value
        return params
