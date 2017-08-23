# Copyright IBM Corp. 2017 All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from hfc.util.utils import create_serialized_identity


class TXContext(object):
    """ A class represent Transaction context."""

    def __init__(self, user, crypto):
        """ Construct transaction context

        Args:
            user: user
            crypto: crypto
        """
        self._user = user
        self._crypto = crypto
        self._identity = create_serialized_identity(user)
        self._nonce = crypto.generate_nonce(24)
        hash_func = crypto.hash
        self._tx_id = hash_func(self._nonce + self._identity).hexdigest()

    @property
    def tx_id(self):
        """ Get transaction id."""
        return self._tx_id

    @property
    def epoch(self):
        """ Get epoch."""
        return 0

    @property
    def nonce(self):
        """ Get nonce"""
        return self._nonce

    @property
    def identity(self):
        """Get identity"""
        return self._identity

    def sign(self, plain_text):
        """Sign the text"""
        return self._crypto.sign(self._user.enrollment.private_key,
                                 plain_text)
