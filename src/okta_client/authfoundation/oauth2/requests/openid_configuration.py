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
from dataclasses import dataclass
from urllib.parse import urljoin

from okta_client.authfoundation.networking.types import APIRequestMethod, RequestValue

from ..request_protocols import JSONRequest


@dataclass
class OpenIDConfigurationRequest(JSONRequest):
    """Request for OpenID discovery configuration."""

    issuer: str
    client_id: str | None = None

    def __init__(self, issuer: str, client_id: str | None = None) -> None:
        self.issuer = issuer
        self.client_id = client_id

    @property
    def http_method(self) -> APIRequestMethod:
        """Return GET for discovery."""
        return APIRequestMethod.GET

    @property
    def url(self) -> str:
        """Return the discovery endpoint URL."""
        return urljoin(self.issuer.rstrip("/") + "/", ".well-known/openid-configuration")

    @property
    def query(self) -> Mapping[str, RequestValue] | None:
        if self.client_id:
            return {"client_id": self.client_id}
        return None
