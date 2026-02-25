# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
# License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# coding: utf-8

"""Authorization Code Flow (PKCE) sample application.

Usage
-----
**Step 1 - Start the flow (prints the authorize URL):**

    python -m samples.authorization_code --config okta.json

**Step 2 - Open the URL in a browser, sign in, then pass the redirect URL back:**

    python -m samples.authorization_code --config okta.json \\
        "https://your-redirect-uri?code=...&state=..."

The sample persists the flow context (PKCE verifier, state, nonce) to a
temporary JSON file between the two invocations so that ``resume()`` can
validate state and exchange the authorization code for tokens.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
from pathlib import Path

from okta_client.authfoundation import (
    ConfigurationFileNotFoundError,
    InvalidConfigurationError,
    OAuth2Error,
)
from okta_client.oauth2auth import (
    AuthorizationCodeContext,
    AuthorizationCodeFlow,
    Prompt,
)
from samples.common.sample_setup import build_oauth_client, load_configuration
from samples.common.token_output import print_token_details

_DEFAULT_CONTEXT_FILE = Path(tempfile.gettempdir()) / "okta_authcode_context.json"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Authorization Code Flow (PKCE) sample.",
        epilog=(
            "Run without a redirect URI to start the flow and print the authorize URL.\n"
            "Run with a redirect URI to exchange the authorization code for tokens."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--config", help="Path to okta.json or okta.ini")
    parser.add_argument("--issuer", help="Issuer URL")
    parser.add_argument("--client_id", help="Client ID")
    parser.add_argument("--scope", help="Scopes (space-separated)")
    parser.add_argument("--redirect_uri", help="Redirect URI (registered in Okta)")
    parser.add_argument("--logout_redirect_uri", help="Logout redirect URI")
    parser.add_argument("--client_secret", help="Client secret")
    parser.add_argument("--login_hint", help="Pre-populate the username field")
    parser.add_argument(
        "--prompt",
        choices=[p.value for p in Prompt],
        help="Prompt behavior (none, consent, login, login consent)",
    )
    parser.add_argument("--no-par", dest="par", action="store_false", default=True,
                        help="Disable Pushed Authorization Requests")
    parser.add_argument("--context-file", dest="context_file", default=None,
                        help="Path to save/load flow context between start and resume "
                             f"(default: {_DEFAULT_CONTEXT_FILE})")
    parser.add_argument("--verbose", action="store_true", help="Log raw requests and responses")
    parser.add_argument(
        "redirect_url",
        nargs="?",
        default=None,
        help="The full redirect URL from the browser (step 2). Omit for step 1.",
    )
    return parser


# ---------------------------------------------------------------------------
# Context persistence between start and resume
# ---------------------------------------------------------------------------


def _context_file_path(args: argparse.Namespace) -> Path:
    """Resolve the context file path from CLI args or the default."""
    if args.context_file:
        return Path(args.context_file)
    return _DEFAULT_CONTEXT_FILE


def _save_context(ctx: AuthorizationCodeContext, context_file: Path) -> None:
    """Persist the context fields needed for resume."""
    context_file.write_text(json.dumps(ctx.to_dict(), indent=2), encoding="utf-8")


def _load_context(context_file: Path) -> AuthorizationCodeContext:
    """Reload a context from the saved context file."""
    if not context_file.exists():
        print(f"No saved flow context found at {context_file}. Run without a redirect URL first.", file=sys.stderr)
        sys.exit(1)
    data = json.loads(context_file.read_text(encoding="utf-8"))
    return AuthorizationCodeContext.from_dict(data)


def _cleanup_context(context_file: Path) -> None:
    """Remove the saved context file after a successful resume."""
    if context_file.exists():
        context_file.unlink()


# ---------------------------------------------------------------------------
# Flow steps
# ---------------------------------------------------------------------------


def _run_start(args: argparse.Namespace) -> None:
    """Step 1: build the authorization URL and print it."""
    try:
        config = load_configuration(args)
    except (ConfigurationFileNotFoundError, InvalidConfigurationError) as error:
        print(f"Configuration error: {error}", file=sys.stderr)
        sys.exit(1)

    oauth_client = build_oauth_client(config, verbose=args.verbose)

    prompt = Prompt(args.prompt) if args.prompt else None
    ctx = AuthorizationCodeContext(
        login_hint=args.login_hint,
        prompt=prompt,
        pushed_authorization_request_enabled=args.par,
    )

    flow = AuthorizationCodeFlow(client=oauth_client)
    try:
        authorize_url = asyncio.run(flow.start(context=ctx))
    except OAuth2Error as error:
        print(f"Failed to build authorize URL: {error}", file=sys.stderr)
        sys.exit(1)
    except Exception as error:
        print(f"Unexpected error: {error}", file=sys.stderr)
        sys.exit(1)

    assert flow.context is not None
    _save_context(flow.context, _context_file_path(args))

    print()
    print("Open the following URL in your browser to sign in:")
    print()
    print(f"  {authorize_url}")
    print()
    print("After signing in, copy the full redirect URL from the browser address bar")
    print("and run this sample again, passing it as a positional argument:")
    print()
    print('  python -m samples.authorization_code --config <config> "<redirect_url>"')
    print()


def _run_resume(args: argparse.Namespace, redirect_url: str) -> None:
    """Step 2: exchange the authorization code for tokens."""
    try:
        config = load_configuration(args)
    except (ConfigurationFileNotFoundError, InvalidConfigurationError) as error:
        print(f"Configuration error: {error}", file=sys.stderr)
        sys.exit(1)

    oauth_client = build_oauth_client(config, verbose=args.verbose)
    saved_ctx = _load_context(_context_file_path(args))

    flow = AuthorizationCodeFlow(client=oauth_client)

    # Manually begin the flow and set the saved context so resume() can work.
    asyncio.run(flow._begin(saved_ctx))

    try:
        token = asyncio.run(flow.resume(redirect_url))
    except OAuth2Error as error:
        print(f"Token exchange failed: {error}", file=sys.stderr)
        sys.exit(1)
    except Exception as error:
        print(f"Unexpected error: {error}", file=sys.stderr)
        sys.exit(1)

    _cleanup_context(_context_file_path(args))

    print()
    print_token_details(token)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = _build_parser()
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        return

    args = parser.parse_args()

    if args.redirect_url:
        _run_resume(args, args.redirect_url)
    else:
        _run_start(args)


if __name__ == "__main__":
    main()
