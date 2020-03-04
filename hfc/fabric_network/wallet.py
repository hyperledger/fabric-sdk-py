import os
import shutil

from hfc.fabric_ca.caservice import ca_service
from hfc.fabric_ca.caservice import Enrollment
from cryptography.hazmat.primitives import serialization


class FileSystenWallet(object):

    def __init__(self, path=os.getcwd() + '/tmp/hfc-kvs'):
        self._path = path
        
        os.makedirs(path, exist_ok=True)

    def exists(self, enrollment_id):
        return os.path.exists(self._path+'/'+enrollment_id)

    def remove(self, enrollment_id):
        dirpath = self._path+'/'+enrollment_id
        if dirpath.exists() and dirpath.is_dir():
            shutil.rmtree(dirpath)


class Identity(object):

    def __init__(self, enrollment_id, user):

        if not isinstance(user, Enrollment):
            raise ValueError('"user" is not a valid Enrollment object')

        self._enrollment_id = enrollment_id
        self._EnrollmentCert = user.cert
        self._PrivateKey = user.private_key.private_bytes(encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption())

    def CreateIdentity(self, Wallet):

        sub_directory = Wallet._path + '/' + self._enrollment_id + '/'
        os.makedirs(sub_directory, exist_ok=True)

        f = open(sub_directory+'private_sk', 'wb')
        f.write(self._PrivateKey)
        f.close()

        f = open(sub_directory+'enrollmentCert.pem', 'wb')
        f.write(self._PrivateKey)
        f.close()