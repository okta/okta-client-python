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

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import (
    TYPE_CHECKING,
    Any,
    Generic,
    Protocol,
    TypeVar,
    cast,
    runtime_checkable,
)

if TYPE_CHECKING:
    from .client import APIClient

T = TypeVar("T")
ListenerT = TypeVar("ListenerT")


class APIContentType(str, Enum):
    """Common content types for request and response bodies."""
    JSON = "application/json"
    FORM_URLENCODED = "application/x-www-form-urlencoded"
    TEXT = "text/plain"


class APIRequestMethod(str, Enum):
    """HTTP request methods."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


@runtime_checkable
class RequestValueConvertible(Protocol):
    """Protocol for values that can serialize themselves to a string."""

    def to_request_value(self) -> str:
        """Return a string representation for request serialization."""
        ...


RequestValue = str | int | float | bool | Sequence[str] | RequestValueConvertible | None


@runtime_checkable
class APIRequestBody(Protocol):
    """Protocol for requests that supply body parameters."""
    @property
    def body_parameters(self) -> Mapping[str, RequestValue]:
        """Body parameters to serialize based on content type."""
        ...


@runtime_checkable
class APIAuthorization(Protocol):
    """Protocol for objects that authorize an outgoing HTTP request."""
    def authorize(self, request: HTTPRequest) -> HTTPRequest:
        """Apply authorization to the request and return it."""
        ...


class APIParsingContext(Protocol):
    """Marker protocol for parsing hints."""


@dataclass(frozen=True)
class APIRateLimit:
    """Rate-limit metadata extracted from responses."""
    limit: int
    remaining: int
    reset: datetime


class BackoffStrategy(Protocol):
    """Protocol for retry backoff strategies."""
    def delay_for_attempt(self, attempt: int) -> float:
        """Return a delay in seconds for the given attempt."""
        ...


@dataclass(frozen=True)
class APIRetry:
    """Retry policy returned by listeners or defaults."""
    kind: str
    maximum_count: int | None = None
    backoff_strategy: BackoffStrategy | None = None

    @classmethod
    def do_not_retry(cls) -> APIRetry:
        """Return a policy that disables retries."""
        return cls(kind="do_not_retry")

    @classmethod
    def retry(cls, maximum_count: int, backoff_strategy: BackoffStrategy | None = None) -> APIRetry:
        """Return a policy that retries up to a maximum count."""
        return cls(kind="retry", maximum_count=maximum_count, backoff_strategy=backoff_strategy)

    @classmethod
    def default(cls) -> APIRetry:
        """Return the SDK default retry policy."""
        return cls(kind="default")


@dataclass(frozen=True)
class RawResponse:
    """Raw response data returned by the network interface."""
    status_code: int
    headers: Mapping[str, str]
    body: bytes


@dataclass
class HTTPRequest:
    """HTTP request envelope used by the network interface."""
    method: APIRequestMethod
    url: str
    headers: dict[str, str]
    body: bytes | None
    timeout: float | None


@dataclass(frozen=True)
class APIResponse(Generic[T]):
    """Parsed response payload plus response metadata."""
    result: T
    status_code: int
    headers: Mapping[str, str]
    request_id: str | None = None
    rate_limit: APIRateLimit | None = None
    links: Mapping[str, str] | None = None


class APIRequest(Generic[T], Protocol):
    """Protocol describing a transport-agnostic API request."""
    @property
    def http_method(self) -> APIRequestMethod:
        ...

    @property
    def url(self) -> str:
        ...

    @property
    def query(self) -> Mapping[str, RequestValue] | None:
        ...

    @property
    def headers(self) -> Mapping[str, RequestValue] | None:
        ...

    @property
    def accepts_type(self) -> APIContentType | None:
        ...

    @property
    def content_type(self) -> APIContentType | None:
        ...

    @property
    def authorization(self) -> APIAuthorization | None:
        ...

    @property
    def timeout(self) -> float | None:
        ...

    def body(self) -> bytes | None:
        """Return the serialized request body, if any."""
        ...

    def parse_response(self, response: RawResponse, parsing_context: APIParsingContext | None = None) -> T:
        """Parse the raw response into a typed result."""
        ...

    def build_http_request(self, client: APIClient) -> HTTPRequest:
        """Build a platform HTTP request using the provided client."""
        return client.build_http_request(cast("APIRequest[Any]", self))

    def send(self, client: APIClient, parsing_context: APIParsingContext | None = None) -> APIResponse[T]:
        """Send the request using the provided client."""
        return client.send(cast("APIRequest[T]", self), parsing_context=parsing_context)

class BaseAPIRequest(Generic[T]):
    """Base request with standard optional defaults."""

    @property
    def query(self) -> Mapping[str, RequestValue] | None:
        return None

    @property
    def headers(self) -> Mapping[str, RequestValue] | None:
        return None

    @property
    def accepts_type(self) -> APIContentType | None:
        return None

    @property
    def content_type(self) -> APIContentType | None:
        return None

    @property
    def authorization(self) -> APIAuthorization | None:
        return None

    @property
    def timeout(self) -> float | None:
        return None

    def body(self) -> bytes | None:
        return None

    def build_http_request(self, client: APIClient) -> HTTPRequest:
        """Build a platform HTTP request using the provided client."""
        return client.build_http_request(cast("APIRequest[Any]", self))

    def send(self, client: APIClient, parsing_context: APIParsingContext | None = None) -> APIResponse[T]:
        """Send the request using the provided client."""
        return client.send(cast("APIRequest[T]", self), parsing_context=parsing_context)


class NetworkInterface(Protocol):
    """Protocol for transport implementations used by APIClient."""
    def send(self, request: HTTPRequest) -> RawResponse:
        """Send an HTTP request and return the raw response."""
        ...


@runtime_checkable
class APIClientListener(Protocol):
    """Listener for request lifecycle events."""
    def will_send(self, client: APIClient, request: HTTPRequest) -> None:
        """Called before a request is sent."""
        ...

    def did_send(self, client: APIClient, request: HTTPRequest, response: APIResponse[Any]) -> None:
        """Called when a response is received successfully."""
        ...

    def did_send_error(self, client: APIClient, request: HTTPRequest, error: Exception) -> None:
        """Called when a request fails with an error."""
        ...

    def should_retry(self, client: APIClient, request: HTTPRequest, rate_limit: APIRateLimit | None) -> APIRetry:
        """Return a retry policy for the given request."""
        ...


class ListenerCollection(Generic[ListenerT]):
    """Thread-unsafe collection of listeners with add/remove semantics."""
    def __init__(self) -> None:
        self._listeners: list[ListenerT] = []

    def add(self, listener: ListenerT) -> None:
        """Add a listener if it is not already registered."""
        if listener not in self._listeners:
            self._listeners.append(listener)

    def remove(self, listener: ListenerT) -> None:
        """Remove a listener if present."""
        if listener in self._listeners:
            self._listeners.remove(listener)

    def __iter__(self) -> Iterator[ListenerT]:
        """Iterate over registered listeners."""
        return iter(self._listeners)


@dataclass(frozen=True)
class APIClientConfiguration:
    """Immutable configuration for APIClient defaults."""
    base_url: str
    user_agent: str
    additional_http_headers: Mapping[str, str] | None = None
    request_id_header: str | None = None
    timeout: float | None = None
