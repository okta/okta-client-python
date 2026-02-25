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

import threading

from .validation_protocols import TokenHashValidator, TokenValidator
from .validators.token_hash import DefaultTokenHashValidator
from .validators.token_validator import DefaultTokenValidator

_lock = threading.Lock()
_token_validator: TokenValidator = DefaultTokenValidator()
_access_token_validator: TokenHashValidator = DefaultTokenHashValidator("at_hash")
_device_secret_validator: TokenHashValidator = DefaultTokenHashValidator("ds_hash")


def get_token_validator() -> TokenValidator:
    """Return the current token validator instance."""
    with _lock:
        return _token_validator


def set_token_validator(validator: TokenValidator) -> None:
    """Override the default token validator.

    Call this during application initialization to change validation behavior.
    """
    with _lock:
        global _token_validator
        _token_validator = validator


def get_access_token_validator() -> TokenHashValidator:
    """Return the current access token hash validator."""
    with _lock:
        return _access_token_validator


def set_access_token_validator(validator: TokenHashValidator) -> None:
    """Override the default access token hash validator."""
    with _lock:
        global _access_token_validator
        _access_token_validator = validator


def get_device_secret_validator() -> TokenHashValidator:
    """Return the current device secret hash validator."""
    with _lock:
        return _device_secret_validator


def set_device_secret_validator(validator: TokenHashValidator) -> None:
    """Override the default device secret hash validator."""
    with _lock:
        global _device_secret_validator
        _device_secret_validator = validator
