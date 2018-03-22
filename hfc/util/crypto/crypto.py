# Copyright IBM Corp. 2016 All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import hashlib
import hmac
import sys
from abc import ABCMeta, abstractmethod

import six
from Cryptodome import Random
from Cryptodome.Cipher import AES
from cryptography import x509
from cryptography.hazmat.backends \
    import default_backend
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec \
    import EllipticCurvePublicNumbers
from cryptography.hazmat.primitives.asymmetric.utils \
    import decode_dss_signature, encode_dss_signature
from cryptography.exceptions import InvalidSignature
from hkdf import Hkdf

if sys.version_info < (3, 6):
    import sha3  # noqa: F401

DEFAULT_NONCE_SIZE = 24

CURVE_P_256_Size = 256
CURVE_P_384_Size = 384

SHA2 = "SHA2"
SHA3 = "SHA3"

AES_KEY_LENGTH = 32
HMAC_KEY_LENGTH = 32
IV_LENGTH = 16


@six.add_metaclass(ABCMeta)
class Key(object):
    """ An abstract base class for Key.

    Key represents a base cryptographic key. It can be symmetric or asymmetric.
    In asymmetric case, the private key can retrieve public key with the
    corresponding method.

    A key can be referenced via the Subject Key Identifier (SKI) with DER or
    PEM encoding.
    """

    @abstractmethod
    def is_symmetric(self):
        """ Return if this key is with symmetric crypt, i.e. whether it's a
        symmetric key.

        :Returns: True or False
        """

    @abstractmethod
    def get_SKI(self):
        """ Return the SKI string

        :Returns: string represent the SKI
        """


@six.add_metaclass(ABCMeta)
class AsymmetricKey(Key):
    """ An asymmetric key.

    Can be a public key or private key, the private key can retrieve public
    key with the corresponding method.
    """

    @abstractmethod
    def is_private(self):
        """ Return if this key is private key

        :Returns: True or False
        """

    @abstractmethod
    def get_public_key(self):
        """ Get the corresponding public key for this private key.

        If this key is already a public one, then return itself.

        :Returns: Public key
        """


@six.add_metaclass(ABCMeta)
class Crypto(object):
    """ An abstract base class for crypto. """

    @abstractmethod
    def generate_private_key(self):
        """ Generate asymmetric key pair.

        :Returns: An private key object which include public key object.
        """

    @abstractmethod
    def encrypt(self, public_key, message):
        """ Encrypt the message by encryption public key.

        :param public_key: Encryption public key
        :param message: message need encrypt

        :Returns: An object including secure context
        """

    @abstractmethod
    def decrypt(self, private_key, cipher_text):
        """ Decrypt the cipher text by encryption private key.

        :param private_key: Encryption private key
        :param cipher_text: Cipher text received

        :Returns: An object including secure context
        """

    @abstractmethod
    def sign(self, private_key, message):
        """ Sign the origin message by signing private key.

        :param private_key: Signing private key
        :param message: Origin message

        :Returns: An object including secure context
        """

    @abstractmethod
    def verify(self, public_key, message, signature):
        """ Verify the signature by signing public key.

        :param public_key: Signing public key
        :param message: Origin message
        :param signature: Signature of message

        :Returns: A boolean True as valid
        """

    @staticmethod
    def generate_nonce(size):
        """ Generate a secure random for cryptographic use.

        Args:
            size: Number of bytes for the nonce

        Returns: Generated random bytes

        """
        return Random.get_random_bytes(size)


def generate_nonce(size):
    # TODO still has old dependencies but has to be deleted
    """ Generate a secure random for cryptographic use.

    Args:
        size: Number of bytes for the nonce

    Returns: Generated random bytes
    """
    return Random.get_random_bytes(size)


class Ecies(Crypto):
    """ A crypto implementation based on ECDSA and SHA. """

    def __init__(self, security_level=CURVE_P_256_Size, hash_algorithm=SHA2):
        """ Init curve and hash function.

        :param security_level: security level
        :param hash_algorithm: hash function
        """
        if security_level == CURVE_P_256_Size:
            # order = openssl.backend._lib.BN_new()
            # curve = openssl.backend._lib.EC_GROUP_new_by_curve_name(
            #     openssl.backend._lib.NID_X9_62_prime256v1)
            # openssl.backend._lib.EC_GROUP_get_order(
            #     curve, order, openssl.backend._ffi.NULL)
            self.order = int("115792089210356248762697446949407573529"
                             "996955224135760342422259061068512044369")
            self.half_order = self.order >> 1
            self.curve = ec.SECP256R1
            self.sign_hash_algorithm = hashes.SHA256()
        else:
            # order = openssl.backend._lib.BN_new()
            # curve = openssl.backend._lib.EC_GROUP_new_by_curve_name(
            #     openssl.backend._lib.NID_secp384r1)
            # openssl.backend._lib.EC_GROUP_get_order(
            #     curve, order, openssl.backend._ffi.NULL)
            self.order = int("39402006196394479212279040100"
                             "14361380507973927046544666794"
                             "69052796276593991132635693989"
                             "56308152294913554433653942643")
            self.half_order = self.order >> 1
            self.curve = ec.SECP384R1
            self.sign_hash_algorithm = hashes.SHA384()

        if hash_algorithm == SHA2:
            self._hash = hashlib.sha256
        elif hash_algorithm == SHA3 and security_level == CURVE_P_256_Size:
            self._hash = hashlib.sha3_256
        else:
            self._hash = hashlib.sha3_384

    @property
    def hash(self):
        """Get hash function

        Returns: hash function

        """
        return self._hash

    def sign(self, private_key, message):
        """ECDSA sign message.

        :param private_key: private key
        :param message: message to sign
        :Returns: signature
        """
        signer = private_key.sign(message, ec.ECDSA(self.sign_hash_algorithm))
        return self._prevent_malleability(signer)

    def verify(self, public_key, message, signature):
        """ECDSA verify signature.

        :param public_key: Signing public key
        :param message: Origin message
        :param signature: Signature of message
        :Returns: verify result boolean, True means valid
        """
        if not (self._check_malleability(signature)):
            return False
        try:
            public_key.verify(signature, message,
                              ec.ECDSA(self.sign_hash_algorithm))
        except InvalidSignature:
            return False
        except Exception as e:
            raise e
        return True

    def _prevent_malleability(self, sig):
        r, s = decode_dss_signature(sig)
        if s > self.half_order:
            s = self.order - s
        return encode_dss_signature(r, s)

    def _check_malleability(self, sig):
        r, s = decode_dss_signature(sig)
        if s > self.half_order:
            return False
        return True

    def generate_private_key(self):
        """ECDSA key pair generation by current curve.

        :Returns: A private key object which include public key object.
        """
        return ec.generate_private_key(self.curve, default_backend())

    def decrypt(self, private_key, cipher_text):
        """Ecies decrypt cipher text.

        First restore the ephemeral public key from bytes(97 bytes for 384,
         65 bytes for 256).
        Then derived a shared key based ecdh, using the key based hkdf to
        generate aes key and hmac key,
        using hmac-sha3 to verify the hmac bytes.
        Last using aes-256-cfb to decrypt the bytes.

        :param private_key: private key
        :param cipher_text: cipher text
        :Returns: plain text
        """
        key_len = private_key.curve.key_size
        if key_len != self.curve.key_size:
            raise ValueError(
                "Invalid key. Input security level {} does not "
                "match the current security level {}".format(
                    key_len,
                    self.curve.key_size))

        d_len = key_len >> 3
        rb_len = ((key_len + 7) // 8) * 2 + 1
        ct_len = len(cipher_text)
        if ct_len <= rb_len + d_len:
            raise ValueError(
                "Illegal cipherText length: cipher text length {} "
                "must be > rb length plus d_len {}".format(ct_len,
                                                           rb_len + d_len)
            )

        rb = cipher_text[:rb_len]
        em = cipher_text[rb_len:ct_len - d_len]
        d = cipher_text[ct_len - d_len:ct_len]

        ephemeral_public_key = EllipticCurvePublicNumbers \
            .from_encoded_point(self.curve(), rb) \
            .public_key(default_backend())
        z = private_key.exchange(ec.ECDH(), ephemeral_public_key)
        hkdf_output = Hkdf(salt=None, input_key_material=z, hash=self._hash) \
            .expand(length=AES_KEY_LENGTH + HMAC_KEY_LENGTH)
        aes_key = hkdf_output[:AES_KEY_LENGTH]
        hmac_key = hkdf_output[AES_KEY_LENGTH:AES_KEY_LENGTH +
                               HMAC_KEY_LENGTH]

        mac = hmac.new(hmac_key, em, self._hash)
        recovered_d = mac.digest()
        if not constant_time.bytes_eq(recovered_d, d):
            raise ValueError("Hmac verify failed.")

        iv = em[:IV_LENGTH]
        aes_cipher = AES.new(key=aes_key, mode=AES.MODE_CFB, iv=iv)
        return aes_cipher.decrypt(em[IV_LENGTH:len(em)])

    def encrypt(self, public_key, plain_text):
        """Ecies encrypt plain text.

        First create a ephemeral ecdsa key pair, then serialize the public
        key for part of result.
        Then derived a shared key based ecdh, using the key based hkdf to
        generate aes key and hmac key,
        using aes-256-cfb to generate the part of result.
        Last using hmac-sha3 and the part of previous step to generate
        last part
        of result.

        :param public_key: public key
        :param plain_text: plain text
        :Returns: cipher text
        """
        ephemeral_private_key = self.generate_private_key()
        rb = ephemeral_private_key.public_key().public_numbers().encode_point()

        z = ephemeral_private_key.exchange(ec.ECDH(), public_key)
        hkdf_output = Hkdf(salt=None, input_key_material=z, hash=self._hash) \
            .expand(length=AES_KEY_LENGTH + HMAC_KEY_LENGTH)
        aes_key = hkdf_output[:AES_KEY_LENGTH]
        hmac_key = hkdf_output[AES_KEY_LENGTH:AES_KEY_LENGTH +
                               HMAC_KEY_LENGTH]

        aes_cipher = AES.new(aes_key, AES.MODE_CFB)
        em = aes_cipher.iv + aes_cipher.encrypt(plain_text)
        mac = hmac.new(hmac_key, em, self._hash)
        d = mac.digest()

        return rb + em + d

    def generate_csr(self, private_key, subject_name, extensions=None):
        """Generate certificate signing request.

        Args:
            private_key: Private key
            subject_name (x509.Name): Subject name
            extensions
        Returns: x509.CertificateSigningRequest

        """
        builder = x509.CertificateSigningRequestBuilder(
            subject_name, [] if extensions is None else extensions)

        return builder.sign(
            private_key, self.sign_hash_algorithm, default_backend())


def ecies(security_level=CURVE_P_256_Size, hash_algorithm=SHA2):
    """Factory method for creating a Ecies instance.

    Args:
        security_level: Security level
        hash_algorithm: Hash algorithm

    Returns: A Ecies instance

    """
    return Ecies(security_level, hash_algorithm)
