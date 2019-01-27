# SPDX-License-Identifier: Apache-2.0
#

# Set default logging handler to avoid "No handler found" warnings.
import logging
from .client import Client  # noqa

try:  # Python 2.7+
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

logging.getLogger(__name__).addHandler(NullHandler())
