"""Tests for okta_client.authfoundation.user_agent."""

from __future__ import annotations

import platform
import re
import sys
from unittest.mock import patch

from okta_client import __version__
from okta_client.authfoundation.user_agent import (
    _platform_component,
    _runtime_component,
    _sdk_components,
    sdk_user_agent,
)

# ---------------------------------------------------------------------------
# _sdk_components
# ---------------------------------------------------------------------------


class TestSdkComponents:
    """Tests for _sdk_components()."""

    def test_includes_authfoundation_when_imported(self) -> None:
        # authfoundation is always imported in our test suite
        components = _sdk_components()
        assert any("okta-authfoundation-python" in c for c in components)

    def test_each_component_contains_version(self) -> None:
        for token in _sdk_components():
            assert "/" in token
            _name, version = token.rsplit("/", 1)
            assert version == __version__

    def test_fallback_when_no_sdk_modules_loaded(self) -> None:
        """If somehow no SDK modules are in sys.modules, return generic name."""
        fake_modules = {k: v for k, v in sys.modules.items() if not k.startswith("okta_client")}
        with patch.dict(sys.modules, fake_modules, clear=True):
            result = _sdk_components()
        assert result == [f"okta-client-python/{__version__}"]

    def test_order_matches_declaration(self) -> None:
        """Components should appear in declaration order."""
        components = _sdk_components()
        names = [c.split("/")[0] for c in components]
        # authfoundation should always come first when present
        if "okta-authfoundation-python" in names:
            assert names[0] == "okta-authfoundation-python"


# ---------------------------------------------------------------------------
# _runtime_component
# ---------------------------------------------------------------------------


class TestRuntimeComponent:
    """Tests for _runtime_component()."""

    def test_contains_python_prefix(self) -> None:
        assert _runtime_component().startswith("python/")

    def test_contains_version(self) -> None:
        result = _runtime_component()
        assert result == f"python/{platform.python_version()}"


# ---------------------------------------------------------------------------
# _platform_component
# ---------------------------------------------------------------------------


class TestPlatformComponent:
    """Tests for _platform_component()."""

    def test_returns_nonempty_string(self) -> None:
        result = _platform_component()
        assert result
        assert "/" in result

    def test_darwin_maps_to_macos(self) -> None:
        with patch("okta_client.authfoundation.user_agent.platform") as mock_platform:
            mock_platform.system.return_value = "Darwin"
            mock_platform.mac_ver.return_value = ("14.2.1", ("", "", ""), "")
            mock_platform.release.return_value = "23.2.0"
            result = _platform_component()
        assert result == "macOS/14.2.1"

    def test_darwin_fallback_to_release(self) -> None:
        with patch("okta_client.authfoundation.user_agent.platform") as mock_platform:
            mock_platform.system.return_value = "Darwin"
            mock_platform.mac_ver.return_value = ("", ("", "", ""), "")
            mock_platform.release.return_value = "23.2.0"
            result = _platform_component()
        assert result == "macOS/23.2.0"

    def test_linux_with_distro(self) -> None:
        fake_distro = type(sys)("distro")
        fake_distro.id = lambda: "ubuntu"  # type: ignore[attr-defined]
        fake_distro.version = lambda: "22.04"  # type: ignore[attr-defined]
        with (
            patch("okta_client.authfoundation.user_agent.platform") as mock_platform,
            patch.dict(sys.modules, {"distro": fake_distro}),
        ):
            mock_platform.system.return_value = "Linux"
            result = _platform_component()
        assert result == "Linux/Ubuntu-22.04"

    def test_linux_with_distro_no_version(self) -> None:
        fake_distro = type(sys)("distro")
        fake_distro.id = lambda: "arch"  # type: ignore[attr-defined]
        fake_distro.version = lambda: ""  # type: ignore[attr-defined]
        with (
            patch("okta_client.authfoundation.user_agent.platform") as mock_platform,
            patch.dict(sys.modules, {"distro": fake_distro}),
        ):
            mock_platform.system.return_value = "Linux"
            result = _platform_component()
        assert result == "Linux/Arch"

    def test_linux_without_distro(self) -> None:
        hidden = {k: v for k, v in sys.modules.items() if k != "distro"}
        with (
            patch("okta_client.authfoundation.user_agent.platform") as mock_platform,
            patch.dict(sys.modules, hidden, clear=True),
        ):
            mock_platform.system.return_value = "Linux"
            mock_platform.release.return_value = "6.1.0"
            result = _platform_component()
        assert result == "Linux/6.1.0"

    def test_windows(self) -> None:
        with patch("okta_client.authfoundation.user_agent.platform") as mock_platform:
            mock_platform.system.return_value = "Windows"
            mock_platform.version.return_value = "10.0.22621"
            result = _platform_component()
        assert result == "Windows/10.0.22621"

    def test_unknown_os(self) -> None:
        with patch("okta_client.authfoundation.user_agent.platform") as mock_platform:
            mock_platform.system.return_value = "FreeBSD"
            mock_platform.release.return_value = "14.0"
            result = _platform_component()
        assert result == "FreeBSD/14.0"


# ---------------------------------------------------------------------------
# sdk_user_agent (integration)
# ---------------------------------------------------------------------------


class TestSdkUserAgent:
    """Tests for sdk_user_agent()."""

    def test_contains_sdk_components(self) -> None:
        result = sdk_user_agent()
        assert "python/" in result
        assert __version__ in result

    def test_does_not_start_with_space(self) -> None:
        assert not sdk_user_agent().startswith(" ")

    def test_token_count(self) -> None:
        """Should have at least 3 tokens: SDK component, python, platform."""
        tokens = sdk_user_agent().split(" ")
        assert len(tokens) >= 3

    def test_format_matches_pattern(self) -> None:
        """Each space-separated token should follow name/version pattern."""
        for token in sdk_user_agent().split(" "):
            assert re.match(r"[\w.-]+/[\w.+-]+", token), f"Token {token!r} doesn't match name/version pattern"
