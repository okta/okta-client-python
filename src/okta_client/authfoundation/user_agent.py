# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

"""Build a user-agent string reporting SDK sub-packages, runtime, and platform.

The format mirrors other Okta Client SDKs (Swift, Kotlin)::

    MyApp/1.0 okta-authfoundation-python/0.1.0 python/3.12.0 macOS/14.2.1
"""

from __future__ import annotations

import platform
import sys

from okta_client import __version__

# Mapping of sub-package module name -> user-agent component name.
# Order matters: authfoundation is always first (it's the base layer).
_SDK_COMPONENTS: list[tuple[str, str]] = [
    ("okta_client.authfoundation", "okta-authfoundation-python"),
    ("okta_client.oauth2auth", "okta-oauth2-python"),
    ("okta_client.browser_signin", "okta-browser-signin-python"),
    ("okta_client.directauth", "okta-directauth-python"),
]


def _sdk_components() -> list[str]:
    """Return user-agent tokens for each imported SDK sub-package."""
    parts: list[str] = []
    for module_name, agent_name in _SDK_COMPONENTS:
        if module_name in sys.modules:
            parts.append(f"{agent_name}/{__version__}")
    return parts if parts else [f"okta-client-python/{__version__}"]


def _runtime_component() -> str:
    """Return a token describing the Python runtime, e.g. ``python/3.12.0``."""
    return f"python/{platform.python_version()}"


def _platform_component() -> str:
    """Return an OS/platform token, e.g. ``macOS/14.2.1`` or ``Linux/Ubuntu-22.04``."""
    system = platform.system()
    if system == "Darwin":
        version = platform.mac_ver()[0] or platform.release()
        return f"macOS/{version}"
    if system == "Linux":
        try:
            import distro  # type: ignore[import-untyped]  # optional dependency

            name = distro.id().capitalize()
            ver = distro.version()
            return f"Linux/{name}-{ver}" if ver else f"Linux/{name}"
        except ModuleNotFoundError:
            return f"Linux/{platform.release()}"
    if system == "Windows":
        return f"Windows/{platform.version()}"
    return f"{system}/{platform.release()}"


def sdk_user_agent() -> str:
    """Return the SDK portion of the user-agent string.

    Includes imported SDK sub-packages, Python runtime, and platform::

        okta-authfoundation-python/0.1.0 python/3.12.0 macOS/14.2.1
    """
    tokens: list[str] = []
    tokens.extend(_sdk_components())
    tokens.append(_runtime_component())
    tokens.append(_platform_component())
    return " ".join(tokens)
