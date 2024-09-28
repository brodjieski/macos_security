#!/usr/bin/env python3
# Title         : mscp_common.py
# Description   : Functions to support MSCP
# Author        : Dan Brodjieski <brodjieski@gmail.com>
# Date          : 2024-09-03
# Version       : 0.1
# Notes         :

import logging
import platform

# Set up logger from main()
logger = logging.getLogger(__name__)

def get_running_macos():
    macos_names = {
        "13": "Ventura",
        "14": "Sonoma",
        "15": "Sequoia"
    }

    macos_version, _, _ = platform.mac_ver()

    major_version = macos_version.split(".")[0]

    if major_version in macos_names.keys():
        return macos_names[major_version]
    else:
        return "undetermined"


