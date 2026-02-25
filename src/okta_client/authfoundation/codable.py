# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

"""Serialization mixin for frozen dataclasses.

Provides a lightweight ``Codable`` protocol (inspired by Swift's ``Codable``)
that any :func:`~dataclasses.dataclass` can adopt to gain ``to_dict()`` /
``from_dict()`` round-trip serialization without third-party dependencies.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from enum import Enum
from typing import Any


class Codable:
    """Mixin for frozen dataclasses that need dictionary (de)serialization.

    Provides :meth:`to_dict` for serialization using :func:`dataclasses.asdict`
    (with automatic :class:`~enum.Enum` → value conversion) and a
    :meth:`from_dict` classmethod that subclasses override to reconstruct
    nested types.

    Usage::

        @dataclass(frozen=True)
        class MyModel(Codable):
            name: str
            kind: SomeEnum

            @classmethod
            def from_dict(cls, data: Mapping[str, Any]) -> "MyModel":
                return cls(
                    name=data["name"],
                    kind=SomeEnum(data["kind"]),
                )
    """

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict suitable for JSON encoding.

        Nested dataclasses are recursively converted to dicts.
        :class:`~enum.Enum` members are reduced to their ``.value``.
        """
        return dataclasses.asdict(self, dict_factory=_enum_aware_dict_factory)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Codable:
        """Reconstruct an instance from a plain dict.

        Subclasses **must** override this to handle nested dataclass and enum
        fields that require type-aware reconstruction.
        """
        raise NotImplementedError(f"{cls.__name__} must implement from_dict()")


def _enum_aware_dict_factory(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Dict factory for :func:`dataclasses.asdict` that converts enum values."""
    return {
        key: value.value if isinstance(value, Enum) else value
        for key, value in pairs
    }
