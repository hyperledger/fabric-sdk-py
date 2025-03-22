#
# SPDX-License-Identifier: Apache-2.0
#

import logging
import os

os.environ['HLF_VERSION'] = '1.4.6'
sh = logging.StreamHandler()
sh.setLevel(logging.DEBUG)
logging.getLogger(__name__).addHandler(sh)
