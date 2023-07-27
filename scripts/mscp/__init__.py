#!/usr/bin/env python3
# Title         : mscp
# Description   : Initializer for MSCP modules
# Author        : Dan Brodjieski <brodjieski@gmail.com>
# Date          : 
# Version       : 0.1
# Namespace     : mscp
# Notes         : 

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from mscp_yaml import *
from mscp_baseline import *