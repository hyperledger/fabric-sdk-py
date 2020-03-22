import couchdb

class CouchDBWalletStore(object):
    def __init__(self, config='http://localhost:5984',  dbName):
        self.server = couchdb.Server(config)
        try:
            self.db = self.server[dbName]
        except:
            self.db = self.server.create(dbname)

    def exists(self, enrollment_id):
        