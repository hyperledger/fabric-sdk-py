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
from hfc.api.crypto.crypto import ecies


class MSP(object):
    """ Minimal Membership Service Provider.

    To manage identities by private keys, certificates with various crypto
    algorithms (e.g., ECDSA, RSA) and PKIs (software-managed or HSM based)
    """

    def __init__(self, identity, signer=None, crypto_suite=ecies(),
                 root_certs=None, admins=None):
        """ Init with configuration info.

        Args:
            root_certs: trust anchors at boot
            signer: signing identity
            admins: admin privileges
            crypto_suite: crypto algorithm family
            identity: id of the instance
        """
        self._root_certs = [] if not root_certs else root_certs
        self._signer = signer
        self._admins = [] if not admins else admins
        self._crypto_suite = crypto_suite
        self._id = identity

    @property
    def identity(self):
        """Get id

        Returns: id

        """
        return self._id

    @property
    def crypto_suite(self):
        """Get crypto suite.

        Returns: crypto suite

        """
        return self._crypto_suite

    def validate(self, identity):
        """ check whether the id is valid

        Args:
            identity: id to check

        Returns: Boolean
        """
        return True


def msp(identity, signer=None, crypto_suite=ecies(),
        root_certs=None, admins=None):
    """Create msp instance

    Args:
        identity: id
        signer: signing identity
        crypto_suite: crypto suite
        root_certs: root certs
        admins: admins

    Returns: msp instance

    """
    return MSP(identity, signer, crypto_suite, root_certs, admins)
