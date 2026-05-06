#! /usr/bin/env python
# filename: mscp_dev.py

import sys

from src.mscp.cli import parse_cli
from src.mscp.common_utils import logger, ensure_custom_dirs


def main() -> None:
    logger.enable("mscp")
    ensure_custom_dirs()
    parse_cli()


if __name__ == "__main__":
    sys.exit(main())
