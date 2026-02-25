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

import base64
from collections.abc import Mapping, Sequence
from typing import Any

from okta_client.authfoundation.networking.types import RequestValue, RequestValueConvertible


def coerce_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None

def coerce_optional_str(value: Any) -> str | None:
    """Convert a value to a string if it is not None."""
    if value is None:
        return None
    return str(value)

def coerce_optional_sequence(value: Any) -> Sequence[str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        return [item for item in value.split() if item]
    if isinstance(value, Sequence):
        return [str(item) for item in value]
    return [str(value)]

def serialize_parameters(parameters: Mapping[str, RequestValue]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in parameters.items():
        serialized = serialize_request_value(value)
        if serialized is None:
            continue
        result[key] = serialized
    return result

def serialize_request_value(value: RequestValue) -> str | None:
    if value is None:
        return None
    if isinstance(value, RequestValueConvertible):
        return str(value.to_request_value())
    if isinstance(value, (list, tuple, set)):
        return " ".join(str(item) for item in value if item is not None)
    return str(value)

def base64url_encode(value: bytes) -> str:
    encoded = base64.urlsafe_b64encode(value).decode("ascii")
    return encoded.rstrip("=")
