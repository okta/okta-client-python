# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

from pathlib import Path

import jwt as pyjwt

from okta_client.authfoundation.key_provider import KeyProvider

_RESOURCES = Path(__file__).parent / "resources"
_PRIVATE_KEY = (_RESOURCES / "test_key.pem").read_text()


class KeyProviderStub(KeyProvider):
    algorithm = "RS256"
    key_id = None

    def sign_jwt(self, claims, headers=None):
        return pyjwt.encode(dict(claims), _PRIVATE_KEY, algorithm="RS256", headers=dict(headers or {}))
