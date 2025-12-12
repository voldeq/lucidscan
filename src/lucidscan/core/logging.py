from __future__ import annotations

import logging
from typing import Optional


def configure_logging(*, debug: bool = False, verbose: bool = False, quiet: bool = False) -> None:
    """Configure root logging level based on CLI flags.

    Precedence:
    - quiet → ERROR
    - debug → DEBUG
    - verbose → INFO
    - default → WARNING
    """

    if quiet:
        level = logging.ERROR
    elif debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    else:
        level = logging.WARNING

    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Return a module-level logger."""

    return logging.getLogger(name if name is not None else __name__)


