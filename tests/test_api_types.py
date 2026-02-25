# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

from datetime import UTC, datetime, timedelta

from okta_client.authfoundation import APIClientConfiguration, APIRateLimit, APIRetry


def test_api_retry_factories() -> None:
    assert APIRetry.do_not_retry().kind == "do_not_retry"
    assert APIRetry.default().kind == "default"
    retry = APIRetry.retry(maximum_count=2)
    assert retry.kind == "retry"
    assert retry.maximum_count == 2


def test_api_rate_limit_model() -> None:
    now = datetime.now(UTC)
    rl = APIRateLimit(limit=100, remaining=50, reset=now + timedelta(seconds=30))
    assert rl.remaining == 50


def test_api_client_configuration_defaults() -> None:
    config = APIClientConfiguration(
        base_url="https://example.com",
        user_agent="okta-client-python",
        additional_http_headers={"X-Test": "1"},
        request_id_header="X-Request-Id",
    )
    assert config.base_url == "https://example.com"
    assert config.additional_http_headers["X-Test"] == "1"
