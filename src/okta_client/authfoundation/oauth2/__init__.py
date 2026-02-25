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

from .claims import HasClaims, IdTokenClaim
from .client_authorization import (
    ClientAssertionAuthorization,
    ClientAuthorization,
    ClientIdAuthorization,
    ClientSecretAuthorization,
)
from .config import (
    ConfigurationError,
    ConfigurationFileNotFoundError,
    ConfigurationParseError,
    InvalidConfigurationError,
    OAuth2ClientConfiguration,
)
from .errors import OAuth2Error
from .jwt_bearer_claims import JWTBearerClaims
from .jwt_context import JWTUsageContext, JWTValidationContext
from .jwt_token import JWT, JWTType
from .models import JWK, JWKS, OpenIdConfiguration, TokenInfo, UserInfo
from .parameters import OAuth2APIRequestCategory, ProvidesOAuth2Parameters
from .request_protocols import (
    IDTokenValidatorContext,
    OAuth2APIRequest,
    OAuth2TokenRequest,
    OAuth2TokenRequestDefaults,
)
from .requests import (
    IntrospectRequest,
    JWKSRequest,
    OpenIDConfigurationRequest,
    RevokeRequest,
    UserInfoRequest,
)
from .utils import NullIDTokenValidatorContext
from .validation_protocols import TokenHashValidator, TokenValidator
from .validator_registry import (
    get_access_token_validator,
    get_device_secret_validator,
    get_token_validator,
    set_access_token_validator,
    set_device_secret_validator,
    set_token_validator,
)
from .validators.token_hash import DefaultTokenHashValidator
from .validators.token_validator import DefaultTokenValidator

__all__ = [
    "JWK",
    "JWKS",
    "JWT",
    "ClientAssertionAuthorization",
    "ClientAuthorization",
    "ClientIdAuthorization",
    "ClientSecretAuthorization",
    "ConfigurationError",
    "ConfigurationFileNotFoundError",
    "ConfigurationParseError",
    "DefaultTokenHashValidator",
    "DefaultTokenValidator",
    "HasClaims",
    "IDTokenValidatorContext",
    "IdTokenClaim",
    "IntrospectRequest",
    "InvalidConfigurationError",
    "JWKSRequest",
    "JWTBearerClaims",
    "JWTType",
    "JWTUsageContext",
    "JWTValidationContext",
    "NullIDTokenValidatorContext",
    "OAuth2APIRequest",
    "OAuth2APIRequestCategory",
    "OAuth2ClientConfiguration",
    "OAuth2Error",
    "OAuth2TokenRequest",
    "OAuth2TokenRequestDefaults",
    "OpenIDConfigurationRequest",
    "OpenIdConfiguration",
    "ProvidesOAuth2Parameters",
    "RevokeRequest",
    "TokenHashValidator",
    "TokenInfo",
    "TokenValidator",
    "UserInfo",
    "UserInfoRequest",
    "get_access_token_validator",
    "get_device_secret_validator",
    "get_token_validator",
    "set_access_token_validator",
    "set_device_secret_validator",
    "set_token_validator",
]
