# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

from okta_client.authfoundation import (
    DefaultTimeCoordinator,
    TimeCoordinator,
    get_time_coordinator,
    set_time_coordinator,
)


class FixedTimeCoordinator(TimeCoordinator):
    def __init__(self, now_value: float) -> None:
        self._now_value = now_value

    def now(self) -> float:
        return self._now_value

    def observe_server_time(self, server_time: float) -> None:
        return None


def test_time_coordinator_set_and_get() -> None:
    original = get_time_coordinator()
    try:
        fixed = FixedTimeCoordinator(now_value=1234.0)
        set_time_coordinator(fixed)
        assert get_time_coordinator().now() == 1234.0
    finally:
        if isinstance(original, DefaultTimeCoordinator):
            set_time_coordinator(DefaultTimeCoordinator())
        else:
            set_time_coordinator(original)
