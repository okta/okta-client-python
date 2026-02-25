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

import threading
import time
from typing import Protocol, runtime_checkable


@runtime_checkable
class TimeCoordinator(Protocol):
    """Protocol for coordinated time sources used in expiry checks."""

    def now(self) -> float:
        """Return the current coordinated time (seconds since epoch)."""
        ...

    def observe_server_time(self, server_time: float) -> None:
        """Observe server time for skew adjustment (optional)."""
        ...


class DefaultTimeCoordinator:
    """Default time coordinator with no skew adjustment."""

    def now(self) -> float:
        """Return system time."""
        return time.time()

    def observe_server_time(self, server_time: float) -> None:
        """No-op for the default coordinator."""
        return None


_default_time_coordinator: TimeCoordinator = DefaultTimeCoordinator()
_time_coordinator_lock = threading.Lock()


def get_time_coordinator() -> TimeCoordinator:
    """Get the global time coordinator in a thread-safe manner."""
    with _time_coordinator_lock:
        return _default_time_coordinator


def set_time_coordinator(coordinator: TimeCoordinator) -> None:
    """Set the global time coordinator in a thread-safe manner."""
    global _default_time_coordinator
    with _time_coordinator_lock:
        _default_time_coordinator = coordinator
