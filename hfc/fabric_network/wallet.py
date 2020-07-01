import os
import shutil


from cryptography.hazmat.primitives import serialization

from hfc.fabric_ca.caservice import Enrollment
from hfc.fabric.user import create_user
from hfc.util.keyvaluestore import FileKeyValueStore


class FileSystenWallet(object):
    """FileSystemWallet stores the identities of users and admins
        ie. it contains the Private Key and Enrollment Certificate
    """

    def __init__(self, path=os.getcwd() + '/tmp/hfc-kvs'):
        self._path = path

        os.makedirs(path, exist_ok=True)

    def exists(self, enrollment_id):
        """Returns whether or not the credentials of a user with a given user_id
            exists in the wallet

        :param enrollment_id: enrollment id
        :return: True or False
        """
        return os.path.exists(self._path+'/'+enrollment_id)

    def remove(self, enrollment_id):
        """Deletes identities of users with the given user_id

        :param enrollment_id: enrollment id
        :return:
        """
        dirpath = self._path+'/'+enrollment_id
        if dirpath.exists() and dirpath.is_dir():
            shutil.rmtree(dirpath)

    def create_user(self, enrollment_id, org, msp_id, state_store=None):
        """Returns an instance of a user whose identity
            is stored in the FileSystemWallet

        :param enrollment_id: enrollment id
        :param org: organization
        :param msp_id: MSP id
        :param state_store: state store (Default value = None)
        :return: a user instance
        """
        if not self.exists(enrollment_id):
            raise AttributeError('"user" does not exist')
        state_store = FileKeyValueStore(self._path)
        key_path = self._path + '/' + enrollment_id + '/' + 'private_sk'
        cert_path = self._path + '/' + enrollment_id + '/' + 'enrollmentCert.pem'
        user = create_user(enrollment_id, org, state_store, msp_id, key_path, cert_path)
        return user


class Identity(object):
    """Class represents a tuple containing
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
        """Saves the particular Identity in the wallet

        :param Wallet:
        :return:
        """
        sub_directory = Wallet._path + '/' + self._enrollment_id + '/'
        os.makedirs(sub_directory, exist_ok=True)

        f = open(sub_directory+'private_sk', 'wb')
        f.write(self._PrivateKey)
        f.close()

        f = open(sub_directory+'enrollmentCert.pem', 'wb')
        f.write(self._EnrollmentCert)
        f.close()
