# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

from enum import Enum
from typing import Any

from okta_client.authfoundation.oauth2.claims import HasClaims


class ExampleClaim(str, Enum):
    FOO = "foo"
    BAR = "bar"

    def key(self) -> str:
        return str(self.value)


class ExampleClaims:
    def __init__(self, values: dict[str, Any]) -> None:
        self._values = values

    def claim(self, claim: ExampleClaim) -> Any | None:
        return self._values.get(claim.key())

    def claim_key(self, key: str) -> Any | None:
        return self._values.get(key)


class NotClaims:
    pass


def test_hasclaims_protocol_isinstance() -> None:
    assert isinstance(ExampleClaims({}), HasClaims)
    assert not isinstance(NotClaims(), HasClaims)


def test_hasclaims_returns_value() -> None:
    claims = ExampleClaims({"foo": "value", "bar": 123})
    assert claims.claim(ExampleClaim.FOO) == "value"
    assert claims.claim(ExampleClaim.BAR) == 123


def test_hasclaims_missing_returns_none() -> None:
    claims = ExampleClaims({"foo": "value"})
    assert claims.claim(ExampleClaim.BAR) is None


def test_claim_key_returns_value() -> None:
    claims = ExampleClaims({"foo": "value", "extra": "other"})
    assert claims.claim_key("foo") == "value"
    assert claims.claim_key("extra") == "other"


def test_claim_key_missing_returns_none() -> None:
    claims = ExampleClaims({"foo": "value"})
    assert claims.claim_key("missing") is None
