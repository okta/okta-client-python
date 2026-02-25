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

import json
from typing import Any
from urllib.parse import parse_qs, urlencode

from okta_client.authfoundation.utils import serialize_parameters

from .types import APIContentType, APIParsingContext, APIRequestBody, RawResponse


class APIRequestBodyMixin(APIRequestBody):
    """Mixin that serializes body parameters based on content type."""

    @property
    def content_type(self) -> APIContentType | None:
        raise NotImplementedError

    @property
    def accepts_type(self) -> APIContentType | None:
        raise NotImplementedError

    def body(self) -> bytes | None:
        params = serialize_parameters(self.body_parameters)
        if self.content_type == APIContentType.JSON:
            return json.dumps(params).encode("utf-8")
        return urlencode(params).encode("utf-8")

    def parse_response(self, response: RawResponse, parsing_context: APIParsingContext | None = None) -> Any:
        if not response.body:
            return {}
        if self.accepts_type == APIContentType.JSON:
            return json.loads(response.body.decode("utf-8"))
        if self.accepts_type == APIContentType.FORM_URLENCODED:
            return parse_qs(response.body.decode("utf-8"))
        return response.body.decode("utf-8")
