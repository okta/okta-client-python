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
from typing import Any

from okta_client.authfoundation import (
    APIClient,
    APIClientListener,
    APIRateLimit,
    APIResponse,
    APIRetry,
    HTTPRequest,
)


class ConsoleLoggingAPIClientListener(APIClientListener):
    """Log APIClient requests and responses to the console."""

    def will_send(self, client: APIClient, request: HTTPRequest) -> None:
        pass  # Deferred to did_send to keep request/response pairs together.

    def did_send(self, client: APIClient, request: HTTPRequest, response: APIResponse[Any]) -> None:
        print(f"\n=== {request.method.value} {request.url} ===")
        print("Request Headers:")
        self._print_headers(request.headers)
        self._print_body(request.body, label="Request Body")
        print(f"Response Status: {response.status_code}")
        self._print_headers(response.headers, label="Response Headers")
        self._print_body(response.result, label="Response Body")

    def did_send_error(self, client: APIClient, request: HTTPRequest, error: Exception) -> None:
        print(f"\n=== {request.method.value} {request.url} ===")
        print("Request Headers:")
        self._print_headers(request.headers)
        self._print_body(request.body, label="Request Body")
        print(f"Error: {error.__class__.__name__}: {error}")

    def should_retry(
        self,
        client: APIClient,
        request: HTTPRequest,
        rate_limit: APIRateLimit | None,
    ) -> APIRetry:
        return APIRetry.default()

    @staticmethod
    def _print_headers(headers: Mapping[str, str], label: str = "Headers") -> None:
        if not headers:
            print(f"({label}: none)")
            return
        print(f"{label}:")
        for key, value in headers.items():
            print(f"  {key}: {value}")

    @staticmethod
    def _print_body(body: Any, label: str = "Body") -> None:
        if body is None:
            print(f"({label}: none)")
            return
        if isinstance(body, (bytes, bytearray)):
            text = body.decode("utf-8", errors="replace")
            print(f"{label}:")
            print(text)
            return
        print(f"{label}:")
        print(body)
