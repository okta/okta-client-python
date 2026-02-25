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

import hashlib
from dataclasses import dataclass

from ....authfoundation.utils import base64url_encode
from ..jwt_token import JWT
from ..validation_protocols import TokenHashValidator


@dataclass
class DefaultTokenHashValidator(TokenHashValidator):
    """Validate at_hash or ds_hash values using RS256."""

    hash_key: str

    def validate(self, token: str, id_token: JWT) -> None:
        expected_hash = id_token.claim_key(self.hash_key)
        if expected_hash is None:
            return
        if id_token.algorithm != "RS256":
            raise ValueError(f"Unsupported algorithm: {id_token.algorithm}")
        digest = hashlib.sha256(token.encode("ascii")).digest()
        left_half = digest[: len(digest) // 2]
        encoded = base64url_encode(left_half)
        if encoded != str(expected_hash):
            raise ValueError("Token hash mismatch")
