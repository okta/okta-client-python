# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

"""Okta Client SDK (Python)."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__: str = version("okta-client-python")
except PackageNotFoundError:  # pragma: no cover - not installed
    __version__ = "0.0.0-dev"

__all__ = ["__version__", "authfoundation", "browser_signin", "directauth", "oauth2auth"]
