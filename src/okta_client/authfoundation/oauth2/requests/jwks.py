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

from okta_client.authfoundation.networking.types import APIRequestMethod, RequestValue

from ..models import OAuthAuthorizationServer, OpenIdConfiguration
from ..request_protocols import JSONRequest


@dataclass
class JWKSRequest(JSONRequest):
    """Request for JWKS key set."""

    discovery_configuration: OpenIdConfiguration | OAuthAuthorizationServer
    client_id: str | None = None

    @property
    def http_method(self) -> APIRequestMethod:
        """Return GET for JWKS."""
        return APIRequestMethod.GET

    @property
    def url(self) -> str:
        """Return the JWKS endpoint URL."""
        return self.discovery_configuration.jwks_uri

    @property
    def query(self) -> Mapping[str, RequestValue] | None:
        """Optional client_id query parameter."""
        if not self.client_id:
            return None
        return {"client_id": self.client_id}
