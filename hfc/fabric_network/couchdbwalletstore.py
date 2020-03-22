import couchdb

from cryptography.hazmat.primitives import serialization

from hfc.fabric_ca.caservice import Enrollment

class CouchDBWalletStore(object):
    def __init__(self, dbName, config='http://localhost:5984'):
        self.server = couchdb.Server(config)
        try:
            self.db = self.server[dbName]
        except:
            self.db = self.server.create(dbname)

    def exists(self, enrollment_id):
        try:
            enrollment_dict = self.db[enrollment_id]
            return True
        except:
            return False

    def put(self, enrollment_id, user_enrollment):
        if not isinstance(user_enrollment, Enrollment):
            raise ValueError('"user_enrollment" is not a valid Enrollment object')
        PrivateKey = user_enrollment.private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.PKCS8,
                                                    encryption_algorithm=serialization.NoEncryption())

        EnrollmentCert = user_enrollment.cert
        doc = {'EnrollmentCert':EnrollmentCert, 'PrivateKey':PrivateKey}
        self.db[enrollment_id] = doc