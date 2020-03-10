class InMemoryWalletStore(object):
    """ InMemoryWalletStore stores the identities of users and admins
        in memory
    """
    def __init__(self):
        self._Map = {}
    
    def exists(self, enrollment_id):
        """ Returns whether or not the creds of a user with a given enrollment_id
            exists in the wallet
        """
        return enrollment_id in self._Map
        
    def remove(self, enrollment_id):
        """ Deletes identities of users with the given user_id """
        del self._Map[enrollment_id]

    def put(self, enrollment_id, user_enrollment):
        """ Saves the particular Identity in the wallet """
        self._Map[enrollment_id] = user_enrollment