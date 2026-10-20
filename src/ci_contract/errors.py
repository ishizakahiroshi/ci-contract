"""Safe diagnostics and M1 exit status constants."""
OK = 0
INVALID_INPUT = 3
BLOCKED = 4
INTERNAL_ERROR = 9


class InputError(ValueError):
    """Input is not valid for the requested byte-layer operation."""


class DependencyError(RuntimeError):
    """An optional runtime dependency is unavailable."""


class BlockedError(RuntimeError):
    """A fixed safe reason code for unavailable or unsupported planning inputs."""

    def __init__(self, reason_code):
        super().__init__(reason_code)
        self.reason_code = reason_code
