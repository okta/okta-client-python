# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

from dataclasses import dataclass

from okta_client.authfoundation import Expires
from okta_client.authfoundation.time_coordinator import (
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


@dataclass(frozen=True)
class MockExpires(Expires):
    _expires_in: float
    _issued_at: float | None

    @property
    def expires_in(self) -> float:
        return self._expires_in

    @property
    def issued_at(self) -> float | None:
        return self._issued_at


def test_expires_defaults_with_time_coordinator() -> None:
    original = get_time_coordinator()
    try:
        set_time_coordinator(FixedTimeCoordinator(now_value=1000.0))
        expires = MockExpires(_expires_in=60.0, _issued_at=950.0)

        assert expires.expires_at == 1010.0
        assert expires.is_expired is False
        assert expires.is_valid is True

        set_time_coordinator(FixedTimeCoordinator(now_value=1010.0))
        assert expires.is_expired is True
        assert expires.is_valid is False
    finally:
        if isinstance(original, DefaultTimeCoordinator):
            set_time_coordinator(DefaultTimeCoordinator())
        else:
            set_time_coordinator(original)
