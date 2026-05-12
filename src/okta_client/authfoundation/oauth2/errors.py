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
from dataclasses import dataclass, field
from typing import Any

_STANDARD_FIELDS = frozenset({"error", "error_description", "error_uri"})


def _coerce_optional_str(value: Any) -> str | None:
    return None if value is None else str(value)


@dataclass
class OAuth2Error(Exception):
    """Structured OAuth2 protocol error with optional metadata."""
    error: str
    error_description: str | None = None
    error_uri: str | None = None
    status_code: int | None = None
    request_id: str | None = None
    additional_fields: Mapping[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        """Return a readable error string."""
        details = [self.error]
        if self.error_description:
            details.append(self.error_description)
        if self.error_uri:
            details.append(self.error_uri)
        return ": ".join(details)

    @classmethod
    def from_response(
        cls,
        data: Mapping[str, Any],
        *,
        status_code: int | None = None,
        request_id: str | None = None,
    ) -> OAuth2Error:
        """Build an :class:`OAuth2Error` from a parsed OAuth2 error response body.

        Standard RFC 6749 keys (``error``, ``error_description``, ``error_uri``)
        are mapped to their dedicated attributes; any other keys are kept
        verbatim on :attr:`additional_fields` so callers can inspect
        server-specific remediation hints.

        ``error`` defaults to ``"oauth2_error"`` when the response body omits it
        (e.g., a 5xx with no JSON ``error`` key).
        """
        return cls(
            error=str(data.get("error", "oauth2_error")),
            error_description=_coerce_optional_str(data.get("error_description")),
            error_uri=_coerce_optional_str(data.get("error_uri")),
            status_code=status_code,
            request_id=request_id,
            additional_fields={k: v for k, v in data.items() if k not in _STANDARD_FIELDS},
        )
