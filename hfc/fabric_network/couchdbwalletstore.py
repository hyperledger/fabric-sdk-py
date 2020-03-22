import couchdb

from hfc.fabric_ca.caservice import Enrollment

class CouchDBWalletStore(object):
    def __init__(self, config='http://localhost:5984',  dbName):
        self.server = couchdb.Server(config)
        try:
            self.db = self.server[dbName]
        except:
            self.db = self.server.create(dbname)

    def exists(self, enrollment_id):
        try:
            enrollment_dict = self.db[enrollment_id]
            if not isinstance(enrollment_dict[enrollment_id], Enrollment):
                raise ValueError('"user" is not a valid Enrollment object')
            else:
                return True
        except:
            return False

    def put(self, enrollment_id, user_enrollment):
        if not isinstance(user_enrollment, Enrollment):
            raise ValueError('"user_enrollment" is not a valid Enrollment object')
        doc = {enrollment_id: user_enrollment}
        self.db[enrollment_id] = doc