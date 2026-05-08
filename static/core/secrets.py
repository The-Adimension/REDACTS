"""
REDACTS Secure Credential Store
Uses the OS-native credential manager via the ``keyring`` library:

- **Windows**: Windows Credential Manager (DPAPI-encrypted)
- **macOS**: macOS Keychain
- **Linux**: Secret Service API (GNOME Keyring / KWallet)

Secrets are stored under the service namespace ``REDACTS`` and are
encrypted at rest by the operating system.  Access requires the
current user's login session - no plaintext files on disk.

Precedence: the active ``FrozenCaseContract`` is the
authoritative source of credentials. The OS keyring is used only as
a runtime cache for values resolved from the contract.

Usage from CLI::

    redacts secrets set DAST_ADMIN_PASSWORD
    redacts secrets get DAST_ADMIN_PASSWORD
    redacts secrets delete DAST_ADMIN_PASSWORD
    redacts secrets list

Usage from Python::

    from static.core.secrets import get_secret, set_secret
    pw = get_secret("DAST_ADMIN_PASSWORD")
"""

from __future__ import annotations

import logging
import sys

logger = logging.getLogger(__name__)

SERVICE_NAME = "REDACTS"

# Keys that REDACTS recognises as sensitive - only these can be stored.
ALLOWED_KEYS = frozenset({
    "DAST_ADMIN_PASSWORD",
    "REDCAP_SOURCE_PATH",
})


def _keyring():
    """Return the keyring module or None if unavailable."""
    try:
        import keyring as _kr
        return _kr
    except ImportError:
        return None


def is_available() -> bool:
    """True if the OS credential store is usable."""
    kr = _keyring()
    if kr is None:
        return False
    try:
        # Verify we have a real backend, not the fail backend
        backend = kr.get_keyring()
        backend_name = type(backend).__name__
        if "fail" in backend_name.lower() or "null" in backend_name.lower():
            return False
        return True
    except Exception:
        return False


def _validate_key(key: str) -> None:
    """Ensure the key is in the allow-list."""
    if key not in ALLOWED_KEYS:
        allowed = ", ".join(sorted(ALLOWED_KEYS))
        raise ValueError(
            f"Unknown secret key '{key}'. Allowed keys: {allowed}"
        )


def get_secret(key: str) -> str | None:
    """Retrieve a secret from the OS credential store.

    Returns None if keyring is unavailable or the key is not set.
    """
    _validate_key(key)
    kr = _keyring()
    if kr is None:
        logger.debug("keyring not installed - skipping OS credential lookup")
        return None
    try:
        value = kr.get_password(SERVICE_NAME, key)
        if value is not None:
            logger.debug("Loaded '%s' from OS credential store", key)
        return value
    except Exception as exc:
        logger.debug("OS credential lookup failed for '%s': %s", key, exc)
        return None


def set_secret(key: str, value: str) -> None:
    """Store a secret in the OS credential store.

    Raises RuntimeError if keyring is not available.
    """
    _validate_key(key)
    kr = _keyring()
    if kr is None:
        raise RuntimeError(
            "Cannot store secrets - 'keyring' package is not installed.\n"
            "Install it with: pip install keyring"
        )
    kr.set_password(SERVICE_NAME, key, value)
    logger.info("Stored '%s' in OS credential store (%s)", key, kr.get_keyring().name)


def delete_secret(key: str) -> None:
    """Remove a secret from the OS credential store.

    Silently succeeds if the key does not exist or keyring is unavailable.
    """
    _validate_key(key)
    kr = _keyring()
    if kr is None:
        return
    try:
        kr.delete_password(SERVICE_NAME, key)
        logger.info("Deleted '%s' from OS credential store", key)
    except kr.errors.PasswordDeleteError:
        return
    except Exception as exc:
        logger.debug("Could not delete '%s': %s", key, exc)


def list_secrets() -> dict[str, bool]:
    """Return a dict of {key: is_set} for all allowed keys."""
    result = {}
    for key in sorted(ALLOWED_KEYS):
        result[key] = get_secret(key) is not None
    return result


def cli_main(argv: list[str] | None = None) -> int:
    """Handle ``redacts secrets <command> [key] [value]``."""
    import argparse
    import getpass

    parser = argparse.ArgumentParser(
        prog="redacts secrets",
        description="Manage secrets in the OS credential store",
    )
    sub = parser.add_subparsers(dest="command")

    # set
    p_set = sub.add_parser("set", help="Store a secret (prompts for value if omitted)")
    p_set.add_argument("key", choices=sorted(ALLOWED_KEYS), help="Secret key name")
    p_set.add_argument("value", nargs="?", default=None, help="Secret value (omit to be prompted securely)")

    # get
    p_get = sub.add_parser("get", help="Retrieve a secret")
    p_get.add_argument("key", choices=sorted(ALLOWED_KEYS), help="Secret key name")

    # delete
    p_del = sub.add_parser("delete", help="Remove a secret")
    p_del.add_argument("key", choices=sorted(ALLOWED_KEYS), help="Secret key name")

    # list
    sub.add_parser("list", help="Show which secrets are stored")

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    if not is_available():
        print(
            "ERROR: OS credential store is not available.\n"
            "Install 'keyring' with: pip install keyring",
            file=sys.stderr,
        )
        return 1

    if args.command == "set":
        value = args.value
        if value is None:
            value = getpass.getpass(f"Enter value for {args.key}: ")
        if not value:
            print("ERROR: Value cannot be empty.", file=sys.stderr)
            return 1
        set_secret(args.key, value)
        print(f"Stored '{args.key}' in OS credential store.")
        return 0

    if args.command == "get":
        val = get_secret(args.key)
        if val is None:
            print(f"'{args.key}' is not set.", file=sys.stderr)
            return 1
        print(val)
        return 0

    if args.command == "delete":
        delete_secret(args.key)
        print(f"Deleted '{args.key}' from OS credential store.")
        return 0

    if args.command == "list":
        secrets = list_secrets()
        if not secrets:
            print("No managed secret keys defined.")
            return 0
        print(f"{'Key':<30} {'Status'}")
        print(f"{'-' * 30} {'-' * 10}")
        for key, is_set in secrets.items():
            status = "SET" if is_set else "not set"
            print(f"{key:<30} {status}")
        return 0

    parser.print_help()
    return 1
