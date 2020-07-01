import couchdb

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from hfc.fabric_ca.caservice import Enrollment
from hfc.fabric.user import User
from hfc.fabric.user import validate
from hfc.util.crypto.crypto import ecies


class CouchDBWalletStore(object):
    """CouchDBWalletStore stores the identities of users and admins
        in a CouchDB with given config
        ie. it contains the Private Key and Enrollment Certificate
    """

    def __init__(self, dbName, config='http://localhost:5984'):
        self.server = couchdb.Server(config)
        try:
            self.db = self.server[dbName]
        except Exception:
            self.db = self.server.create(dbName)

    def exists(self, enrollment_id):
        """Returns whether or not the creds of a user with a given user_id
            exists in the wallet

        :param enrollment_id: enrollment id
        :return: True or False
        """
        try:
            self.db[enrollment_id]
            return True
        except Exception:
            return False

    def remove(self, enrollment_id):
        """deletes identities of user with given enrollment_id

        :param enrollment_id: enrollment id
        :return:
        """
        self.db.delete(self.db[enrollment_id])

    def put(self, enrollment_id, user_enrollment):
        """Saves the particular Identity in the wallet

        :param enrollment_id: enrollment id
        :param user_enrollment: Enrollment object
        :return:
        """
        if not isinstance(user_enrollment, Enrollment):
            raise ValueError('"user_enrollment" is not a valid Enrollment object')
        PrivateKey = user_enrollment.private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                               format=serialization.PrivateFormat.PKCS8,
                                                               encryption_algorithm=serialization.NoEncryption()
                                                               ).decode()
        EnrollmentCert = user_enrollment.cert.decode()
        doc = {'EnrollmentCert': EnrollmentCert, 'PrivateKey': PrivateKey}
        self.db[enrollment_id] = doc

    def create_user(self, enrollment_id, org, msp_id, state_store=None):
        """Returns an instance of a user whose identity
            is stored in the CouchDBWallet

        :param enrollment_id: enrollment id
        :param org: organization
        :param msp_id: MSP id
        :param state_store:  (Default value = None)
        :return: a validated user instance
        """
        crypto_suit = ecies()

        if not self.exists(enrollment_id):
            raise AttributeError('"user" does not exist')

        key_pem = self.db[enrollment_id]['PrivateKey']
        cert_pem = self.db[enrollment_id]['EnrollmentCert']

        private_key = load_pem_private_key(key_pem, None, default_backend())
        enrollment = Enrollment(private_key, cert_pem)

        user = User(enrollment_id, org, state_store)
        user.enrollment = enrollment
        user.msp_id = msp_id
        user.cryptoSuite = crypto_suit

        return validate(user)
