# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

import asyncio
from collections.abc import Mapping

from okta_client.authfoundation import (
    AuthenticationContext,
    AuthenticationListener,
    AuthenticationState,
    BaseAuthenticationFlow,
    RequestValue,
)
from okta_client.authfoundation.oauth2.parameters import OAuth2APIRequestCategory


class _TestContext(AuthenticationContext):
    def __init__(
        self,
        *,
        acr_values: list[str] | None = None,
        persist_values: Mapping[str, str] | None = None,
        additional_parameters: Mapping[str, RequestValue] | None = None,
    ) -> None:
        self._acr_values = acr_values
        self._persist_values = persist_values
        self._additional_parameters = additional_parameters

    @property
    def acr_values(self) -> list[str] | None:
        return self._acr_values

    @property
    def persist_values(self) -> Mapping[str, str] | None:
        return self._persist_values

    @property
    def additional_parameters(self) -> Mapping[str, RequestValue] | None:
        return self._additional_parameters

    def parameters(self, category: OAuth2APIRequestCategory) -> Mapping[str, RequestValue] | None:
        return self._additional_parameters


class FlowListener(AuthenticationListener):
    def __init__(self) -> None:
        self.events: list[str] = []
        self.last_context: AuthenticationContext | None = None
        self.last_result: str | None = None
        self.last_error: Exception | None = None

    def authentication_started(self, flow) -> None:
        self.events.append("started")

    def authentication_updated(self, flow, context: AuthenticationContext) -> None:
        self.events.append("updated")
        self.last_context = context

    def authentication_completed(self, flow, result: str) -> None:
        self.events.append("completed")
        self.last_result = result

    def authentication_failed(self, flow, error: Exception) -> None:
        self.events.append("failed")
        self.last_error = error


class _TestFlow(BaseAuthenticationFlow[_TestContext]):
    async def start(self, *, context: _TestContext | None = None) -> str:
        await self._begin(context)
        if context is None:
            context = _TestContext()
        self._update_context(context)
        result = "token"
        self._complete(result)
        return result

    async def resume(self, *, context: _TestContext) -> str:
        await self._begin(context)
        self._update_context(context)
        result = "resumed"
        self._complete(result)
        return result


def test_authentication_flow_lifecycle() -> None:
    flow = _TestFlow()
    listener = FlowListener()
    flow.listeners.add(listener)

    result = asyncio.run(flow.start(context=_TestContext(acr_values=["phr"])))

    assert result == "token"
    assert flow.state == AuthenticationState.COMPLETED
    assert flow.is_authenticating is False
    assert listener.events == ["started", "updated", "updated", "completed"]
    assert listener.last_context is not None
    assert listener.last_context.acr_values == ["phr"]

    flow.reset()
    assert flow.state == AuthenticationState.IDLE


def test_authentication_flow_single_active_session() -> None:
    flow = _TestFlow()

    async def start_and_start() -> None:
        await flow._begin(None)
        await flow._begin(None)

    try:
        asyncio.run(start_and_start())
    except RuntimeError:
        return
    raise AssertionError("Expected RuntimeError when starting an active session")
