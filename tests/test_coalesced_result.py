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

from okta_client.authfoundation import CoalescedResult


def test_coalesced_result_coalesces_concurrent_calls() -> None:
    async def runner() -> None:
        coalesced: CoalescedResult[str] = CoalescedResult()
        started = asyncio.Event()
        release = asyncio.Event()
        calls = 0

        async def operation() -> str:
            nonlocal calls
            calls += 1
            started.set()
            await release.wait()
            return "ok"

        async def caller() -> str:
            return await coalesced.perform(operation)

        task1 = asyncio.create_task(caller())
        await started.wait()
        task2 = asyncio.create_task(caller())
        release.set()

        results = await asyncio.gather(task1, task2)
        assert results == ["ok", "ok"]
        assert calls == 1

    asyncio.run(runner())


def test_coalesced_result_returns_cached_value() -> None:
    async def runner() -> None:
        coalesced: CoalescedResult[str] = CoalescedResult()
        calls = 0

        async def operation() -> str:
            nonlocal calls
            calls += 1
            return "cached"

        first = await coalesced.perform(operation)
        second = await coalesced.perform(operation)

        assert first == "cached"
        assert second == "cached"
        assert calls == 1

    asyncio.run(runner())


def test_coalesced_result_reset_forces_refresh() -> None:
    async def runner() -> None:
        coalesced: CoalescedResult[str] = CoalescedResult()
        calls = 0

        async def operation() -> str:
            nonlocal calls
            calls += 1
            return f"value-{calls}"

        first = await coalesced.perform(operation)
        second = await coalesced.perform(operation, reset=True)

        assert first == "value-1"
        assert second == "value-2"
        assert calls == 2

    asyncio.run(runner())


def test_coalesced_result_propagates_errors() -> None:
    async def runner() -> None:
        coalesced: CoalescedResult[str] = CoalescedResult()
        started = asyncio.Event()
        release = asyncio.Event()
        calls = 0

        async def operation() -> str:
            nonlocal calls
            calls += 1
            started.set()
            await release.wait()
            raise ValueError("boom")

        async def caller() -> None:
            try:
                await coalesced.perform(operation)
            except ValueError:
                return
            raise AssertionError("Expected ValueError")

        task1 = asyncio.create_task(caller())
        await started.wait()
        task2 = asyncio.create_task(caller())
        release.set()
        await asyncio.gather(task1, task2)

        assert calls == 1
        assert coalesced.value is None

    asyncio.run(runner())


def test_coalesced_result_ttl_expires_cache() -> None:
    async def runner() -> None:
        current_time = [100.0]

        def time_provider() -> float:
            return current_time[0]

        coalesced: CoalescedResult[str] = CoalescedResult(ttl=10.0, time_provider=time_provider)
        calls = 0

        async def operation() -> str:
            nonlocal calls
            calls += 1
            return f"value-{calls}"

        first = await coalesced.perform(operation)
        second = await coalesced.perform(operation)
        assert first == "value-1"
        assert second == "value-1"
        assert calls == 1

        current_time[0] += 11.0
        third = await coalesced.perform(operation)
        assert third == "value-2"
        assert calls == 2

    asyncio.run(runner())
