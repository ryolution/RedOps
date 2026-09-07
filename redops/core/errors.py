"""Errors whose messages are safe to display to operators."""


class RedOpsError(Exception):
    """An expected configuration, validation, or integration failure."""


class InputError(RedOpsError):
    """Malformed or unsupported input."""


class ScopeError(RedOpsError):
    """Missing, expired, or insufficient scope declaration."""
