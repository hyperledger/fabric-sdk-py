import logging

from .msp.identity import Identity, Signer, SigningIdentity
from .msp.msp import MSP
from .crypto.crypto import Ecies


class User(object):
    """ The User Object

    """

    def __init__(self, client, **kwargs):
        """Constructor for a user.

        Args:
            client: the Client object associated with this user.
            kwargs: includes name=,roles=,affiliation= ...

        """
        self.name = ''
        self.roles = []
        self.affiliation = ''

        if 'name' in kwargs:
            self.name = kwargs['name']
        elif 'enrollmentID' in kwargs:
            self.name = kwargs['enrollmentID']
        if 'roles' in kwargs:
            self.roles = kwargs['roles']
        else:
            self.roles = ['fabric.user']
        if 'affiliation' in kwargs:
            self.affiliation = kwargs['affiliation']

        self.enrollment_secret = ''
        self.identity = None
        self.signing_identity = None
        self.client = client

        if client and client.get_crypto_suite():
            self.crypto_primitives = client.get_crypto_suite()
        else:
            # TODO: get crypto_suite from config
            self.crypto_primitives = Ecies()

        msp = MSP(trusted_certs=[], signer="blah", admins=[],
                  crypto_suite=self.crypto_primitives, id="DEFAULT")
        self.msp_impl = msp

        self.logger = logging.getLogger(__name__)

    def get_name(self):
        """Get the user name

        Return: The user name
        """
        return self.name

    def get_roles(self):
        """Get the roles

        Return: The roles
        """
        return self.roles

    def set_roles(self, roles):
        """Get the roles

        Args:
            roles: the roles
        """
        self.roles = roles

    def get_affiliation(self):
        """Get the affiliation

        Return: The affiliation
        """
        return self.affiliation

    def get_identity(self):
        """Get the Identity object

        The Identity object for this User instance is used to
        verify signatures.

        Return:
            The identity object that encapsulates the user's
            enrollment certificate
        """
        return self.identity

    def get_signing_identity(self):
        """Get the SigningIdentity object

        The SigningIdentity object for this User instance is used to
        generate signatures.

        Return:
            The SigningIdentity object that encapsulates the user's
            private key for signing.
        """
        return self.signing_identity

    def set_enrollment(self, private_key, certificate):
        """Set identity and signing_identity for this User instance

        Args:
            private_key: the private key object
            certificate: the PEM-encoded string of certificate
        """
        public_key = private_key.public_key()
        identity = Identity('testIdentity',
                            certificate,
                            public_key,
                            self.msp_impl)
        self.identity = identity
        signer = Signer(self.msp_impl.crypto_suite, private_key)
        self.signing_identity = SigningIdentity('testSigningIdentity',
                                                certificate, public_key,
                                                self.msp_impl, signer)

    def is_enrolled(self):
        """Determine if this name has been enrolled.

        Return: True if enrolled; otherwise, false.
        """
        return self.identity is not None and self.signing_identity is not None

    def from_string(self):
        """Set the current state of this user from a string based JSON object

        """
        pass

    def to_string(self):
        """Save the current state of this user as a string

        """
        pass
