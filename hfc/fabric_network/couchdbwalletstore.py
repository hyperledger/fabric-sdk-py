import couchdb

from cryptography.hazmat.primitives import serialization

from hfc.fabric_ca.caservice import Enrollment


class CouchDBWalletStore(object):
    """
        CouchDBWalletStore stores the identities of users and admins
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
        """
            Returns whether or not the creds of a user with a given user_id
            exists in the wallet
        """
        try:
            self.db[enrollment_id]
            return True
        except Exception:
            return False

    def remove(self, enrollment_id):
        """
            deletes identities of user with given enrollment_id
        """
        self.db.delete(self.db[enrollment_id])

    def put(self, enrollment_id, user_enrollment):
        """
            Saves the particular Identity in the wallet
        """
        if not isinstance(user_enrollment, Enrollment):
            raise ValueError('"user_enrollment" is not a valid Enrollment object')
        PrivateKey = user_enrollment.private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                               format=serialization.PrivateFormat.PKCS8,
                                                               encryption_algorithm=serialization.NoEncryption())
        EnrollmentCert = user_enrollment.cert
        doc = {'EnrollmentCert': EnrollmentCert, 'PrivateKey': PrivateKey}
        self.db[enrollment_id] = doc
