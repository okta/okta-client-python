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

from typing import Protocol, runtime_checkable

from .time_coordinator import get_time_coordinator


@runtime_checkable
class Expires(Protocol):
    """Protocol for objects that can expire based on issued time."""
    @property
    def expires_in(self) -> float:
        """Return the lifetime in seconds."""
        ...

    @property
    def issued_at(self) -> float | None:
        """Return the issue time in seconds since epoch, if known."""
        ...

    @property
    def expires_at(self) -> float | None:
        """Return the calculated expiration time, if possible."""
        if self.issued_at is None:
            return None
        return float(self.issued_at) + float(self.expires_in)

    @property
    def is_expired(self) -> bool:
        """Return True when the object is expired."""
        expires_at = self.expires_at
        if expires_at is None:
            return False
        return get_time_coordinator().now() >= expires_at

    @property
    def is_valid(self) -> bool:
        """Return True when the object is not expired."""
        return not self.is_expired
