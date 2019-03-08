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
import binascii
import logging
import pickle

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from hfc.fabric_ca.caservice import Enrollment
from hfc.util.crypto.crypto import ecies

_logger = logging.getLogger(__name__ + ".user")


class User(object):
    """ The default implementation of user. """

    def __init__(self, name, org, state_store):
        """Constructor for a user.

        Args:
            name: name
            org: org
            state_store: persistent state store as a cache

        """
        self._name = name
        self._org = org
        self._state_store = state_store
        self._state_store_key = "user." + name + "." + org
        self._roles = []
        self._account = None
        self._affiliation = None
        self._enrollment_secret = None
        self._enrollment = None
        self._msp_id = None
        self._cryptoSuite = None

        user_state = state_store.get_value(self._state_store_key)

        if not user_state:
            self._save_state()
        else:
            self._restore_state()

    @property
    def name(self):
        """Get the user name

        Return: The user name

        """
        return self._name

    @property
    def org(self):
        """Get the org

        Return: The org

        """
        return self._org

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
        self._save_state()

    @property
    def account(self):
        """Get the account

        Return: The account
        """
        return self._account

    @account.setter
    def account(self, account):
        """Set the account

        Args:
            account: the account
        """
        self._account = account
        self._save_state()

    @property
    def affiliation(self):
        """Get the affiliation

        Return: The affiliation
        """
        return self._affiliation

    @affiliation.setter
    def affiliation(self, affiliation):
        """Set the affiliation

        Args:
            affiliation: the affiliation
        """
        self._affiliation = affiliation
        self._save_state()

    @property
    def enrollment(self):
        """Get the enrollment

        Return: The enrollment
        """
        return self._enrollment

    @enrollment.setter
    def enrollment(self, enrollment):
        """Set the enrollment

        Args:
            enrollment: the enrollment
        """
        self._enrollment = enrollment
        self._save_state()

    @property
    def enrollment_secret(self):
        """Get the enrollment_secret

        Return: The enrollment_secret
        """
        return self._enrollment_secret

    @enrollment_secret.setter
    def enrollment_secret(self, enrollment_secret):
        """Set the enrollment_secret

        Args:
            enrollment_secret: the enrollment_secret
        """
        self._enrollment_secret = enrollment_secret
        self._save_state()

    @property
    def msp_id(self):
        """Get the msp_id

        Return: The msp_id
        """
        return self._msp_id

    @msp_id.setter
    def msp_id(self, msp_id):
        """Set the msp_id

        Args:
            msp_id: the msp_id
        """
        self._msp_id = msp_id
        self._save_state()

    @property
    def cryptoSuite(self):
        """Get the cryptoSuite

        Return: The cryptoSuite
        """
        return self._cryptoSuite

    @cryptoSuite.setter
    def cryptoSuite(self, cryptoSuite):
        """Set the cryptoSuite

        Args:
            msp_id: the cryptoSuite
        """
        self._cryptoSuite = cryptoSuite
        self._save_state()

    def is_registered(self):
        """Check if user registered

        Returns: boolean

        """
        return self._enrollment_secret is not None

    def is_enrolled(self):
        """Check if user enrolled

        Returns: boolean

        """
        return self._enrollment is not None

    def _save_state(self):
        """ Persistent user state. """
        try:
            state = {
                'name': self.name, 'org': self.org, 'roles': self.roles,
                'affiliation': self.affiliation, 'account': self.account,
                'enrollment_secret': self.enrollment_secret,
                'msp_id': self.msp_id
            }

            if self.enrollment:
                enrollment = {
                    'private_key':
                        self.enrollment.private_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption()
                        ),
                    'cert': self.enrollment.cert
                }

                state['enrollment'] = enrollment

            self._state_store.set_value(
                self._state_store_key,
                binascii.hexlify(pickle.dumps(state)).decode("utf-8"))
        except Exception as e:
            raise IOError("Cannot serialize the user", e)

    def _restore_state(self):
        """ Restore user state. """
        try:
            state = self._state_store.get_value(self._state_store_key)
            state_dict = pickle.loads(
                binascii.unhexlify(state.encode("utf-8")))
            self._name = state_dict['name']
            self.enrollment_secret = state_dict['enrollment_secret']
            enrollment = state_dict['enrollment']
            if enrollment:
                private_key = serialization.load_pem_private_key(
                    enrollment['private_key'],
                    password=None,
                    backend=default_backend()
                )
                cert = enrollment['cert']
                self.enrollment = Enrollment(private_key, cert)
            self.affiliation = state_dict['affiliation']
            self.account = state_dict['account']
            self.roles = state_dict['roles']
            self._org = state_dict['org']
            self.msp_id = state_dict['msp_id']
        except Exception as e:
            raise IOError("Cannot deserialize the user", e)

    def get_attrs(self):
        return ",".join("{}={}"
                        .format(k, getattr(self, k))
                        for k in self.__dict__.keys())

    def __str__(self):
        return "[{}:{}]".format(self.__class__.__name__, self.get_attrs())


def validate(user):
    """ Check the user.

    Args:
        user: A user object

    Raises:
        ValueError: When user property is invalid

    """
    if not user:
        raise ValueError("User cannot be empty.")

    if not user.name:
        raise ValueError("Missing user name.")

    enrollment = user.enrollment
    if not enrollment:
        raise ValueError("Missing user enrollment.")

    if not enrollment.cert:
        raise ValueError("Missing user enrollment cert.")

    if not enrollment.private_key:
        raise ValueError("Missing user enrollment key.")

    if not user.msp_id:
        raise ValueError("Missing msp id.")

    if not user.cryptoSuite:
        raise ValueError("Missing crypto suite.")

    return user


def create_user(name, org, state_store, msp_id, key_path, cert_path,
                crypto_suite=ecies()):
    """Create user

    Args:
        name: user's name
        org: org name
        state_store: user state store
        msp_id: msp id for the user
        crypto_suite: the cryptoSuite used to store crypto and key store
         settings
        key_path: identity private key path
        cert_path: identity public cert path

    Returns: a user instance

    """

    _logger.debug("Create user with {}:{}:{}:{}:{}:{}".format(
        name, org, state_store, msp_id, key_path, cert_path
    ))
    with open(key_path, 'rb') as key:
        key_pem = key.read()

    with open(cert_path, 'rb') as cert:
        cert_pem = cert.read()

    private_key = load_pem_private_key(key_pem, None, default_backend())
    enrollment = Enrollment(private_key, cert_pem)

    user = User(name, org, state_store)
    user.enrollment = enrollment
    user.msp_id = msp_id
    user.cryptoSuite = crypto_suite

    return validate(user)
