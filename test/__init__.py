# SPDX-License-Identifier: Apache-2.0
#

import logging

sh = logging.StreamHandler()
sh.setLevel(logging.DEBUG)
logging.getLogger(__name__).addHandler(sh)
