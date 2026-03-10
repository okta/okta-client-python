# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

from collections.abc import Mapping
from dataclasses import dataclass

from okta_client.authfoundation import (
    APIClient,
    APIClientConfiguration,
    APIClientListener,
    APIContentType,
    APIRequestBody,
    APIRequestMethod,
    APIResponse,
    APIRetry,
    DefaultNetworkInterface,
    HTTPRequest,
    NetworkInterface,
    RawResponse,
    RequestValue,
)


class StringArg:
    def __init__(self, value: str) -> None:
        self._value = value

    def to_request_value(self) -> str:
        return self._value


@dataclass
class DummyRequest:
    http_method: APIRequestMethod
    url: str
    query: Mapping[str, RequestValue] | None = None
    headers: Mapping[str, RequestValue] | None = None
    accepts_type: APIContentType | None = None
    content_type: APIContentType | None = None
    authorization = None
    timeout: float | None = None

    def body(self) -> bytes | None:
        return None

    def parse_response(self, response: RawResponse, parsing_context=None) -> str:
        return response.body.decode("utf-8")

    def build_http_request(self, client: APIClient) -> HTTPRequest:
        return client.build_http_request(self)

    def send(self, client: APIClient, parsing_context=None) -> APIResponse[str]:
        return client.send(self, parsing_context=parsing_context)


class DummyNetwork(NetworkInterface):
    def __init__(self) -> None:
        self.last_headers = None
        self.last_request = None

    def send(self, request: HTTPRequest) -> RawResponse:
        self.last_request = request
        self.last_headers = request.headers
        return RawResponse(status_code=200, headers={"X-Request-Id": "abc123"}, body=b"ok")


def test_api_client_send_parses_response() -> None:
    network = DummyNetwork()
    client = APIClient(
        base_url="https://example.com",
        user_agent="okta-client-python",
        request_id_header="X-Request-Id",
        network=network,
    )
    request = DummyRequest(http_method=APIRequestMethod.GET, url="https://example.com/test")

    response = request.send(client)

    assert response.result == "ok"
    assert response.status_code == 200
    assert response.request_id == "abc123"
    assert network.last_headers is not None
    assert network.last_headers["User-Agent"] == "okta-client-python"


class FormBodyRequest(DummyRequest, APIRequestBody):
    @property
    def body_parameters(self) -> Mapping[str, RequestValue]:
        return {"foo": StringArg("bar"), "baz": "qux"}


def test_api_client_builds_http_request_with_query_and_body() -> None:
    network = DummyNetwork()
    client = APIClient(
        base_url="https://example.com",
        user_agent="okta-client-python",
        network=network,
    )
    request = FormBodyRequest(
        http_method=APIRequestMethod.POST,
        url="https://example.com/token",
        query={"q": "1"},
        content_type=APIContentType.FORM_URLENCODED,
    )

    request.send(client)

    assert network.last_request is not None
    assert "q=1" in network.last_request.url
    assert network.last_request.headers["Content-Type"] == APIContentType.FORM_URLENCODED.value
    assert network.last_request.body == b"foo=bar&baz=qux"


def test_api_client_configuration_defaults_and_overrides() -> None:
    network = DummyNetwork()
    config = APIClientConfiguration(
        base_url="https://example.com",
        user_agent="default-agent",
        additional_http_headers={"X-Default": "1"},
        timeout=10.0,
    )
    client = APIClient(configuration=config, network=network)
    request = DummyRequest(
        http_method=APIRequestMethod.GET,
        url="https://example.com/test",
        headers={"X-Default": "override", "User-Agent": "custom-agent"},
        timeout=1.0,
    )

    request.send(client)

    assert network.last_headers is not None
    assert network.last_headers["X-Default"] == "override"
    assert network.last_headers["User-Agent"] == "custom-agent"
    assert network.last_request is not None
    assert network.last_request.timeout == 1.0


class RecordingListener(APIClientListener):
    def __init__(self) -> None:
        self.events: list[str] = []

    def will_send(self, client: APIClient, request: HTTPRequest) -> None:
        request.headers["X-Delegate"] = "1"
        self.events.append("will_send")

    def did_send(self, client: APIClient, request: HTTPRequest, response: APIResponse[str]) -> None:
        self.events.append("did_send")

    def did_send_error(self, client: APIClient, request: HTTPRequest, error: Exception) -> None:
        self.events.append("did_send_error")

    def should_retry(self, client: APIClient, request: HTTPRequest, rate_limit=None):
        return APIRetry.default()


def test_api_client_delegates_can_mutate_request() -> None:
    network = DummyNetwork()
    client = APIClient(
        base_url="https://example.com",
        user_agent="okta-client-python",
        network=network,
    )
    listener = RecordingListener()
    client.listeners.add(listener)

    request = DummyRequest(http_method=APIRequestMethod.GET, url="https://example.com/test")
    request.send(client)

    assert network.last_headers is not None
    assert "X-Delegate" in network.last_headers
    assert listener.events == ["will_send", "did_send"]


# ---------------------------------------------------------------------------
# DefaultNetworkInterface tests
# ---------------------------------------------------------------------------

import urllib.request


def test_default_network_interface_no_proxy() -> None:
    """When no proxy is provided, no custom opener is created."""
    net = DefaultNetworkInterface()
    assert net.proxy is None
    assert net._opener is None


def test_default_network_interface_with_proxy() -> None:
    """When a proxy is provided, a custom opener with ProxyHandler is created."""
    proxy_url = "http://proxy.example.com:8080"
    net = DefaultNetworkInterface(proxy=proxy_url)
    assert net.proxy == proxy_url
    assert net._opener is not None

    # Verify the opener contains a ProxyHandler with the expected proxies.
    handler_types = [type(h) for h in net._opener.handlers]
    assert urllib.request.ProxyHandler in handler_types

    proxy_handler = next(h for h in net._opener.handlers if isinstance(h, urllib.request.ProxyHandler))
    assert proxy_handler.proxies.get("http") == proxy_url
    assert proxy_handler.proxies.get("https") == proxy_url


def test_default_network_interface_proxy_none_explicit() -> None:
    """Explicitly passing proxy=None behaves the same as omitting it."""
    net = DefaultNetworkInterface(proxy=None)
    assert net.proxy is None
    assert net._opener is None
