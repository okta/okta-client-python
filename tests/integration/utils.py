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

import json
import os
import re
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path

import pytest

_ANY_TOKEN_PATTERN = re.compile(r"(\w+) Token:\s*(\S+)")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def json_from_file(path: Path) -> dict:
    """Load and return the contents of a JSON file."""
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def run_sample(
    args: Iterable[str],
    *,
    timeout: int = 300,
    failure_message: str,
) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, "-m", *args]
    result = subprocess.run(
        command,
        cwd=repo_root(),
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=timeout,
        check=False,
    )
    if os.environ.get("INTEGRATION_VERBOSE"):
        if result.stdout:
            sys.stdout.write(result.stdout)
        if result.stderr:
            sys.stderr.write(result.stderr)
    if result.returncode != 0:
        pytest.fail(
            f"{failure_message}\nCommand: {' '.join(command)}\n{format_output(result)}",
            pytrace=False,
        )
    return result


def format_output(result: subprocess.CompletedProcess[str]) -> str:
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    if stdout:
        stdout = _ANY_TOKEN_PATTERN.sub(lambda match: f"{match.group(1)} Token: [REDACTED]", stdout)
    if stderr:
        stderr = _ANY_TOKEN_PATTERN.sub(lambda match: f"{match.group(1)} Token: [REDACTED]", stderr)
    if not stdout and not stderr:
        return "(no output)"
    return f"stdout:\n{stdout}\n\nstderr:\n{stderr}"


def generate_client_assertion(
    client_id: str,
    token_endpoint: str,
    key_file: str,
    key_id: str,
) -> str:
    """Generate a client assertion JWT for the given client and endpoint."""
    claims_json = json.dumps({
        "iss": client_id,
        "sub": client_id,
        "aud": token_endpoint,
    })
    result = run_sample(
        [
            "samples.jwt_assertion",
            "--claims-json",
            claims_json,
            "--key-file",
            key_file,
            "--key-id",
            key_id,
            "--expires-in",
            "600",
        ],
        failure_message="JWT assertion generation failed",
    )
    assertion = (result.stdout or "").strip()
    if not assertion:
        pytest.fail("JWT assertion output was empty", pytrace=False)
    return assertion
