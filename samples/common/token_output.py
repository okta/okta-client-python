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

import os
import sys
from typing import TextIO

from okta_client.authfoundation import Token


def print_token_details(token: Token, stream: TextIO | None = None) -> None:
    """Print human-readable token details with optional ANSI colors."""
    output = stream or sys.stdout
    color = _colorizer(output)

    def line(label: str, value: str) -> None:
        output.write(f"{color(label, '1')}: {value}\n")

    output.write(f"{color('Token Details', '1;36')}\n")
    line("Access Token", color(token.access_token, "32"))
    line("Token Type", color(token.token_type, "32"))
    line("Expires In", color(str(token.expires_in), "33"))
    line("Expires At", color(str(token.expires_at), "33"))

    if token.scope:
        line("Scopes", color(" ".join(token.scope), "32"))
    line("ID Token", color(token.id_token.raw if token.id_token else "N/A", "32"))
    line("Refresh Token", color(token.refresh_token if token.refresh_token else "N/A", "32"))


def _colorizer(stream: TextIO):
    def color(text: str, code: str) -> str:
        if not _supports_color(stream):
            return text
        return f"\033[{code}m{text}\033[0m"

    return color


def _supports_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if not hasattr(stream, "isatty") or not stream.isatty():
        return False
    term = os.environ.get("TERM", "")
    return term.lower() != "dumb"
