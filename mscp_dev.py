#! /usr/bin/env python
# filename: mscp_dev.py

import sys

from src.mscp.cli import parse_cli
from src.mscp.common_utils import logger


def main() -> None:
    logger.enable("mscp")
    parse_cli()


if __name__ == "__main__":
    sys.exit(main())
