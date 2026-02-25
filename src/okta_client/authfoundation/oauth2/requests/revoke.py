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

from okta_client.authfoundation.networking import APIContentType, APIRequestMethod, RequestValue
from okta_client.authfoundation.networking.body import APIRequestBodyMixin

from ..request_protocols import JSONRequest


class RevokeRequest(JSONRequest, APIRequestBodyMixin):
    """Request to revoke a token."""

    def __init__(self, url: str, token: str, token_type_hint: str | None, client_id: str | None) -> None:
        self._url = url
        self.token = token
        self.token_type_hint = token_type_hint
        self.client_id = client_id

    @property
    def url(self) -> str:
        """Return the revocation endpoint URL."""
        return self._url

    @property
    def http_method(self) -> APIRequestMethod:
        """Return POST for revocation."""
        return APIRequestMethod.POST

    @property
    def content_type(self) -> APIContentType | None:
        """Revocation requests are form-url-encoded."""
        return APIContentType.FORM_URLENCODED

    @property
    def body_parameters(self) -> Mapping[str, RequestValue]:
        """Return revocation body parameters."""
        params: dict[str, RequestValue] = {
            "token": self.token,
            "client_id": self.client_id,
        }
        if self.token_type_hint:
            params["token_type_hint"] = self.token_type_hint
        return params
