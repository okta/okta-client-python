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
import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Any, TypeVar
from urllib.parse import urlencode, urlsplit, urlunsplit

from okta_client.authfoundation.utils import serialize_parameters, serialize_request_value

from .types import (
    APIClientConfiguration,
    APIClientListener,
    APIContentType,
    APIParsingContext,
    APIRateLimit,
    APIRequest,
    APIRequestBody,
    APIResponse,
    APIRetry,
    HTTPRequest,
    ListenerCollection,
    NetworkInterface,
    RawResponse,
    RequestValue,
)

T = TypeVar("T")


class APIClient:
    """Network client that executes APIRequest objects and parses responses."""
    def __init__(
        self,
        base_url: str | None = None,
        user_agent: str | None = None,
        additional_http_headers: Mapping[str, str] | None = None,
        request_id_header: str | None = None,
        configuration: APIClientConfiguration | None = None,
        network: NetworkInterface | None = None,
    ) -> None:
        """Create a client with configuration and network transport."""
        if configuration is None:
            if base_url is None or user_agent is None:
                raise ValueError("base_url and user_agent are required when configuration is not provided")
            configuration = APIClientConfiguration(
                base_url=base_url,
                user_agent=user_agent,
                additional_http_headers=additional_http_headers or {},
                request_id_header=request_id_header,
            )
        self.configuration = configuration
        self.base_url = configuration.base_url
        self.user_agent = configuration.user_agent
        self.network = network or DefaultNetworkInterface()
        self.additional_http_headers = dict(configuration.additional_http_headers or {})
        self.request_id_header = configuration.request_id_header
        self._listeners: ListenerCollection[APIClientListener] = ListenerCollection()

    @property
    def listeners(self) -> ListenerCollection[APIClientListener]:
        """Registered listeners for request lifecycle events."""
        return self._listeners

    def send(self, request: APIRequest[T], parsing_context: APIParsingContext | None = None) -> APIResponse[T]:
        """Send an APIRequest and return a typed APIResponse."""
        http_request = self.build_http_request(request)
        self.will_send(http_request)
        try:
            raw_response = self._send_once(request, http_request=http_request)
            result = request.parse_response(raw_response, parsing_context=parsing_context)
            response = APIResponse(
                result=result,
                status_code=raw_response.status_code,
                headers=raw_response.headers,
                request_id=self._extract_request_id(raw_response.headers),
                rate_limit=None,
                links=None,
            )
            self.did_send(http_request, response)
            return response
        except Exception as error:
            self.did_send_error(http_request, error)
            raise

    def will_send(self, request: HTTPRequest) -> None:
        """Notify listeners before a request is sent."""
        for listener in self._listeners:
            listener.will_send(self, request)

    def did_send(self, request: HTTPRequest, response: APIResponse[Any]) -> None:
        """Notify listeners after a successful response."""
        for listener in self._listeners:
            listener.did_send(self, request, response)

    def did_send_error(self, request: HTTPRequest, error: Exception) -> None:
        """Notify listeners after a failed request."""
        for listener in self._listeners:
            listener.did_send_error(self, request, error)

    def should_retry(self, request: HTTPRequest, rate_limit: APIRateLimit | None = None) -> APIRetry:
        """Ask listeners for a retry policy for a request."""
        for listener in self._listeners:
            retry = listener.should_retry(self, request, rate_limit)
            if retry.kind != "default":
                return retry
        return APIRetry.default()

    def _send_once(self, request: APIRequest[T], http_request: HTTPRequest | None = None) -> RawResponse:
        """Send a request once using the configured network interface."""
        if not self.network:
            raise RuntimeError("APIClient.network is not configured")
        built_request = http_request or self.build_http_request(request)
        return self.network.send(built_request)

    def build_http_request(self, request: APIRequest[Any]) -> HTTPRequest:
        """Build a platform HTTP request from an APIRequest."""
        headers = dict(self._build_headers(request))
        url = self._build_url(request.url, request.query)
        body = self._build_body(request)
        timeout = request.timeout if request.timeout is not None else self.configuration.timeout
        http_request = HTTPRequest(method=request.http_method, url=url, headers=headers, body=body, timeout=timeout)
        if request.authorization:
            http_request = request.authorization.authorize(http_request)
        return http_request

    def _build_headers(self, request: APIRequest[Any]) -> Mapping[str, str]:
        """Build request headers from defaults and request data."""
        headers: dict[str, str] = {}
        headers.update(self.additional_http_headers)
        headers["User-Agent"] = self.user_agent
        if request.headers:
            for key, value in request.headers.items():
                serialized = serialize_request_value(value)
                if serialized is not None:
                    headers[key] = serialized
        if request.accepts_type:
            headers["Accept"] = request.accepts_type.value
        if request.content_type:
            headers["Content-Type"] = request.content_type.value
        return headers

    def _build_url(self, url: str, query: Mapping[str, RequestValue] | None) -> str:
        """Build a URL with merged query parameters."""
        if not query:
            return url
        query_string = urlencode(serialize_parameters(query))
        split = urlsplit(url)
        merged_query = "&".join(filter(None, [split.query, query_string]))
        return urlunsplit((split.scheme, split.netloc, split.path, merged_query, split.fragment))

    def _build_body(self, request: APIRequest[Any]) -> bytes | None:
        """Serialize the request body based on content type."""
        if isinstance(request, APIRequestBody):
            params = serialize_parameters(request.body_parameters)
            if request.content_type == APIContentType.JSON:
                return json.dumps(params).encode("utf-8")
            return urlencode(params).encode("utf-8")
        return request.body()

    def _extract_request_id(self, headers: Mapping[str, str]) -> str | None:
        """Extract a request ID from response headers, if configured."""
        if not self.request_id_header:
            return None
        for key, value in headers.items():
            if key.lower() == self.request_id_header.lower():
                return value
        return None


class DefaultNetworkInterface(NetworkInterface):
    """Default network interface using urllib.request.

    Args:
        proxy: Optional proxy URL (e.g. ``"http://proxy.example.com:8080"``).
            When provided, all outgoing requests are routed through this proxy.
            Supports ``http`` and ``https`` schemes.  When ``None`` (the
            default), no proxy is used and requests go directly to the host.
    """

    def __init__(self, proxy: str | None = None) -> None:
        self.proxy = proxy
        if proxy is not None:
            proxy_handler = urllib.request.ProxyHandler(
                {"http": proxy, "https": proxy}
            )
            self._opener = urllib.request.build_opener(proxy_handler)
        else:
            self._opener = None

    def send(self, request: HTTPRequest) -> RawResponse:
        req = urllib.request.Request(
            request.url,
            data=request.body,
            headers=request.headers,
            method=request.method.value,
        )
        open_fn = self._opener.open if self._opener is not None else urllib.request.urlopen
        try:
            with open_fn(req, timeout=request.timeout) as response:
                body = response.read() or b""
                headers = {k: v for k, v in response.headers.items()}
                return RawResponse(status_code=response.status, headers=headers, body=body)
        except urllib.error.HTTPError as error:
            body = error.read() or b""
            headers = {k: v for k, v in error.headers.items()}
            return RawResponse(status_code=error.code, headers=headers, body=body)
