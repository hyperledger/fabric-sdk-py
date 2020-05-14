from hfc.fabric_ca.caservice import Enrollment
from hfc.fabric.user import User
from hfc.fabric.user import validate
from hfc.util.crypto.crypto import ecies


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
        if not isinstance(user_enrollment, Enrollment):
            raise ValueError('"user_enrollment" is not a valid Enrollment object')
        self._Map[enrollment_id] = user_enrollment

    def create_user(self, enrollment_id, org, msp_id, state_store=None):
        """ Returns an instance of a user whose identity
            is stored in the InMemoryWallet
        """
        crypto_suit = ecies()

        if not self.exists(enrollment_id):
            raise AttributeError('"user" does not exist')

        user = User(enrollment_id, org, state_store)
        user.enrollment = self._Map[enrollment_id]
        user.msp_id = msp_id
        user.cryptoSuite = crypto_suit

        return validate(user)
