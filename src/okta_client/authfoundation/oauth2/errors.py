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

from dataclasses import dataclass


@dataclass
class OAuth2Error(Exception):
    """Structured OAuth2 protocol error with optional metadata."""
    error: str
    error_description: str | None = None
    error_uri: str | None = None
    status_code: int | None = None
    request_id: str | None = None

    def __str__(self) -> str:
        """Return a readable error string."""
        details = [self.error]
        if self.error_description:
            details.append(self.error_description)
        if self.error_uri:
            details.append(self.error_uri)
        return ": ".join(details)
