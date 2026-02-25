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

from collections.abc import Mapping
from enum import Enum
from typing import Protocol, runtime_checkable

from ..networking import RequestValue


class OAuth2APIRequestCategory(str, Enum):
    """Request category used to determine which parameters apply."""

    CONFIGURATION = "configuration"
    AUTHORIZATION = "authorization"
    TOKEN = "token"
    RESOURCE = "resource"
    OTHER = "other"


@runtime_checkable
class ProvidesOAuth2Parameters(Protocol):
    """Protocol for objects that supply OAuth2 parameters for requests."""

    def parameters(self, category: OAuth2APIRequestCategory) -> Mapping[str, RequestValue] | None:
        """Return parameters to include for the given request category."""
        ...
