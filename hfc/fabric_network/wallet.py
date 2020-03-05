import os
import shutil


from cryptography.hazmat.primitives import serialization

from hfc.fabric_ca.caservice import Enrollment


class FileSystenWallet(object):
    """ FileSystemWallet stores the identities of users and admins
        ie. it contains the Private Key and Enrollment Certificate
    """
    def __init__(self, path=os.getcwd() + '/tmp/hfc-kvs'):
        self._path = path

        os.makedirs(path, exist_ok=True)

    def exists(self, enrollment_id):
        """ Returns whether or not the creds of a user with a given user_id
            exists in the wallet
        """
        return os.path.exists(self._path+'/'+enrollment_id)

    def remove(self, enrollment_id):
        """ Deletes identities of users with the given user_id """
        dirpath = self._path+'/'+enrollment_id
        if dirpath.exists() and dirpath.is_dir():
            shutil.rmtree(dirpath)


class Identity(object):
    """ Class represents a tuple containing
        1) enrollment_id
        2) Enrollment Certificate of user
        3) Private Key of user
    """
    def __init__(self, enrollment_id, user):

        if not isinstance(user, Enrollment):
            raise ValueError('"user" is not a valid Enrollment object')

        self._enrollment_id = enrollment_id
        self._EnrollmentCert = user.cert
        self._PrivateKey = user.private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                          format=serialization.PrivateFormat.PKCS8,
                                                          encryption_algorithm=serialization.NoEncryption())

    def CreateIdentity(self, Wallet):
        """ Saves the particular Identity in the wallet """
        sub_directory = Wallet._path + '/' + self._enrollment_id + '/'
        os.makedirs(sub_directory, exist_ok=True)

        f = open(sub_directory+'private_sk', 'wb')
        f.write(self._PrivateKey)
        f.close()

        f = open(sub_directory+'enrollmentCert.pem', 'wb')
        f.write(self._PrivateKey)
        f.close()
