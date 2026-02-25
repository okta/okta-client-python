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

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import Generic, TypeVar

T = TypeVar("T")


class CoalescedResult(Generic[T]):
    """Coalesce concurrent async operations so only one in-flight task runs.

    - Caches the last successful result.
    - Errors are propagated to all awaiting callers and are not cached.
    """

    def __init__(self, *, ttl: float | None = None, time_provider: Callable[[], float] | None = None) -> None:
        self._lock = asyncio.Lock()
        self._active = False
        self._value: T | None = None
        self._fetched_at: float | None = None
        self._ttl = ttl
        self._time_provider = time_provider or time.time
        self._waiters: list[asyncio.Future[T]] = []

    @property
    def is_active(self) -> bool:
        return self._active

    @property
    def value(self) -> T | None:
        return self._value

    async def perform(
        self,
        operation: Callable[[], Awaitable[T]],
        *,
        reset: bool = False,
    ) -> T:
        """Perform the operation or await the in-flight result.

        Args:
            operation: Async callable that produces the result.
            reset: If True, clears the cached value before proceeding.
        """
        future: asyncio.Future[T] | None = None
        async with self._lock:
            if reset:
                self._value = None
                self._fetched_at = None
            if self._active:
                loop = asyncio.get_running_loop()
                future = loop.create_future()
                self._waiters.append(future)
            else:
                if self._is_cache_valid():
                    return self._value  # type: ignore[return-value]
                self._active = True

        if future is not None:
            return await future

        try:
            result = await operation()
        except Exception as exc:
            await self._finish(error=exc)
            raise
        else:
            await self._finish(result=result)
            return result

    async def _finish(self, result: T | None = None, error: Exception | None = None) -> None:
        async with self._lock:
            if error is None:
                if self._ttl is not None and self._ttl <= 0:
                    self._value = None
                    self._fetched_at = None
                else:
                    self._value = result
                    self._fetched_at = self._time_provider()
            self._active = False
            waiters = self._waiters
            self._waiters = []

        for waiter in waiters:
            if waiter.done():
                continue
            if error is None:
                waiter.set_result(result)  # type: ignore[arg-type]
            else:
                waiter.set_exception(error)

    def _is_cache_valid(self) -> bool:
        if self._value is None:
            return False
        if self._ttl is None:
            return True
        if self._ttl <= 0:
            return False
        if self._fetched_at is None:
            return False
        return (self._time_provider() - self._fetched_at) < self._ttl
