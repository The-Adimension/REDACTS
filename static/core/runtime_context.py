"""Process-wide accessor for the loaded ``FrozenCaseContract``.

The contract is the single source of truth (see :mod:`static.core.contract`).
Once it has been loaded by the parent process, every other module reads
configuration from it via this module.

Rules:
    * The contract is set exactly once per process. A second
      ``set_contract`` call with a different instance raises
      :class:`RuntimeError` - there is no legitimate reason to swap the
      contract mid-run.
    * ``get_contract()`` raises if the contract has not been set.
      Callers that may legitimately run before the contract is loaded
      (e.g. ``paths.output_dir`` during interactive preflight before
      ``--case`` is parsed) use ``get_optional_contract()``.
    * ``reset_contract()`` is provided **for tests only**.

Copyright 2024-2026 The Adimension / Shehab Anwer.
Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import threading

from .contract import FrozenCaseContract

_lock = threading.Lock()
_contract: FrozenCaseContract | None = None


def set_contract(contract: FrozenCaseContract) -> None:
    """Install the loaded contract. Idempotent on the same instance."""
    global _contract
    if not isinstance(contract, FrozenCaseContract):
        raise TypeError(
            f"set_contract expects a FrozenCaseContract, got {type(contract).__name__}"
        )
    with _lock:
        if _contract is not None and _contract is not contract:
            raise RuntimeError(
                "runtime_context: a different contract is already installed; "
                "the contract is process-wide and immutable for the run."
            )
        _contract = contract


def get_contract() -> FrozenCaseContract:
    """Return the installed contract or raise."""
    if _contract is None:
        raise RuntimeError(
            "runtime_context: no contract installed. The parent must call "
            "static.core.contract.load_and_freeze(...) and "
            "runtime_context.set_contract(...) before any consumer runs."
        )
    return _contract


def get_optional_contract() -> FrozenCaseContract | None:
    """Return the installed contract or ``None`` (no raise)."""
    return _contract


def reset_contract() -> None:
    """Test-only: clear the installed contract."""
    global _contract
    with _lock:
        _contract = None


__all__ = [
    "set_contract",
    "get_contract",
    "get_optional_contract",
    "reset_contract",
]
