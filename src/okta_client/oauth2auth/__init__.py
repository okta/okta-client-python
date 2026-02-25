# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

"""OAuth2/OIDC authentication flows."""

from okta_client.authfoundation.authentication import StandardAuthenticationContext, generate_pkce
from okta_client.authfoundation.oauth2.jwt_bearer_claims import JWTBearerClaims

from .authorization_code import (
    AuthorizationCodeContext,
    AuthorizationCodeFlow,
    AuthorizationCodeFlowListener,
    Prompt,
)
from .cross_app import (
    CrossAppAccessContext,
    CrossAppAccessFlow,
    CrossAppAccessFlowListener,
    CrossAppAccessTarget,
    CrossAppExchangeResult,
)
from .jwt_bearer import (
    JWTBearerFlow,
)
from .resource_owner import ResourceOwnerFlow
from .token_exchange import (
    TokenDescriptor,
    TokenExchangeContext,
    TokenExchangeFlow,
    TokenExchangeParameters,
    TokenType,
)
from .utils import parse_redirect_uri

__all__ = [
    "AuthorizationCodeContext",
    "AuthorizationCodeFlow",
    "AuthorizationCodeFlowListener",
    "CrossAppAccessContext",
    "CrossAppAccessFlow",
    "CrossAppAccessFlowListener",
    "CrossAppAccessTarget",
    "CrossAppExchangeResult",
    "JWTBearerClaims",
    "JWTBearerFlow",
    "Prompt",
    "ResourceOwnerFlow",
    "StandardAuthenticationContext",
    "TokenDescriptor",
    "TokenExchangeContext",
    "TokenExchangeFlow",
    "TokenExchangeParameters",
    "TokenType",
    "generate_pkce",
    "parse_redirect_uri",
]
