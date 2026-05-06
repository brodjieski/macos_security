# src/mscp/__main__.py

import sys

from .cli import parse_cli
from .common_utils import logger, ensure_custom_dirs


def main() -> None:
    logger.enable("mscp")
    ensure_custom_dirs()
    parse_cli()


if __name__ == "__main__":
    sys.exit(main())
