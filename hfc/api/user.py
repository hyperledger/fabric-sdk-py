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
from hfc.api.ca.caservice import ca_service
from .crypto.crypto import ecies
from .msp.identity import Identity, Signer, SigningIdentity
from .msp.msp import msp


class User(object):
    """ The User Object

    """

    def __init__(self, name, password='', roles=None,
                 affiliation="", msp_impl=msp('DEFAULT', ecies()),
                 ca=ca_service()):
        """Constructor for a user.

        Args:
            ca: ca service
            name: name
            password: password
            roles: roles
            affiliation: affiliation
            msp_impl: msp instance

        """
        self._name = name
        self._roles = ['fabric.user'] if roles is None else roles
        self._affiliation = affiliation
        self._enrollment_secret = password
        self._msp = msp_impl
        self._identity = None
        self._signing_identity = None
        self._ca = ca

    @property
    def name(self):
        """Get the user name

        Return: The user name
        """
        return self._name

    @property
    def roles(self):
        """Get the roles

        Return: The roles
        """
        return self._roles

    @roles.setter
    def roles(self, roles):
        """Set the roles

        Args:
            roles: the roles
        """
        self._roles = roles

    @property
    def affiliation(self):
        """Get the affiliation

        Return: The affiliation
        """
        return self._affiliation

    @property
    def identity(self):
        """Get the Identity object

        The Identity object for this User instance is used to
        verify signatures.

        Return:
            The identity object that encapsulates the user's
            enrollment certificate
        """
        return self._identity

    @property
    def signing_identity(self):
        """Get the SigningIdentity object

        The SigningIdentity object for this User instance is used to
        generate signatures.

        Return:
            The SigningIdentity object that encapsulates the user's
            private key for signing.
        """
        return self._signing_identity

    def enroll(self):
        """Enroll user."""
        priv_key, cert = self._ca.enroll(self.name, self._enrollment_secret)
        public_key = priv_key.public_key()
        self._identity = Identity(self._name + '_identity',
                                  cert,
                                  public_key,
                                  self._msp)
        signer = Signer(self._msp.crypto_suite, priv_key)
        print("cert={}".format(cert))
        print("public_key={}".format(public_key))
        self._signing_identity = SigningIdentity(
            self._name + '_signingIdentity',
            cert, public_key,
            self._msp, signer)

    def is_enrolled(self):
        """Determine if this name has been enrolled.

        Return: True if enrolled; otherwise, false.
        """
        return self._identity and self._signing_identity

    def from_string(self):
        """Set the current state of this user from a string based JSON object

        """
        pass

    def to_string(self):
        """Save the current state of this user as a string

        """
        pass
