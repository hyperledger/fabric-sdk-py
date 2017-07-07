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
import unittest

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import NameOID

from hfc.util.crypto.crypto import \
    CURVE_P_256_Size, SHA3, SHA2, CURVE_P_384_Size, ecies


class CryptoTest(unittest.TestCase):
    """Test for crypto module. """

    def setUp(self):
        self.plain_text = b'Hello world!'

    def test_ecies_secp384r1_sha3(self):
        """Test case for security level 384, hash SHA3."""
        ecies384 = ecies(CURVE_P_384_Size, SHA3)
        private_key = ecies384.generate_private_key()
        cipher_text = ecies384.encrypt(private_key.public_key(),
                                       self.plain_text)

        self.assertEqual(ecies384.decrypt(private_key, cipher_text),
                         self.plain_text)

    def test_ecies_secp256r1_sha3(self):
        """Test case for security level 256, hash SHA3."""
        ecies256 = ecies(CURVE_P_256_Size, SHA3)
        private_key = ecies256.generate_private_key()
        cipher_text = ecies256.encrypt(private_key.public_key(),
                                       self.plain_text)

        self.assertEqual(ecies256.decrypt(private_key, cipher_text),
                         self.plain_text)

    def test_ecies_secp256r1_sha2(self):
        """Test case for security level 256, hash SHA2."""
        ecies256 = ecies(CURVE_P_256_Size, SHA2)
        private_key = ecies256.generate_private_key()
        cipher_text = ecies256.encrypt(private_key.public_key(),
                                       self.plain_text)

        self.assertEqual(ecies256.decrypt(private_key, cipher_text),
                         self.plain_text)

    def test_ecies_secp256r1_sha2_sign_verify(self):
        """Test case for security level 256, hash SHA2."""
        ecies256 = ecies(CURVE_P_256_Size, SHA2)
        private_key = ecies256.generate_private_key()
        signature = ecies256.sign(private_key,
                                  self.plain_text)

        self.assertEqual(ecies256.verify(private_key.public_key(),
                                         self.plain_text,
                                         signature),
                         True)

        self.assertEqual(ecies256.verify(private_key.public_key(),
                                         self.plain_text + b'!',
                                         signature),
                         False)

    def test_ecies_secp384r1_sha2_sign_verify(self):
        """Test case for security level 256, hash SHA2."""
        ecies384 = ecies(CURVE_P_384_Size, SHA2)
        private_key = ecies384.generate_private_key()
        signature = ecies384.sign(private_key,
                                  self.plain_text)

        self.assertEqual(ecies384.verify(private_key.public_key(),
                                         self.plain_text,
                                         signature),
                         True)

        self.assertEqual(ecies384.verify(private_key.public_key(),
                                         self.plain_text + b'!',
                                         signature),
                         False)

    def test_ecies_generate_csr(self):
        """Test case for generate certificate signing request."""
        ecies256 = ecies()
        private_key = ecies256.generate_private_key()
        csr = ecies256.generate_csr(private_key, x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, u"test")]))
        csr_pem = csr.public_bytes(Encoding.PEM)
        self.assertTrue(csr_pem.startswith(
            b"-----BEGIN CERTIFICATE REQUEST-----"))

    def test_secp256r1_check_malleability_and_check_prevent_malleability(self):
        """Test case for check_malleability and prevent_malleability."""
        ecies256 = ecies(CURVE_P_256_Size, SHA2)
        private_key = ecies256.generate_private_key()
        signature = ecies256.sign(private_key,
                                  self.plain_text)

        self.assertEqual(ecies256._check_malleability(signature),
                         True)

        self.assertEqual(ecies256._check_malleability(
            ecies256._prevent_malleability(signature)),
            True)

    def test_secp384r1_check_malleability_and_check_prevent_malleability(self):
        """Test case for check_malleability and prevent_malleability."""
        ecies384 = ecies(CURVE_P_384_Size, SHA2)
        private_key = ecies384.generate_private_key()
        signature = ecies384.sign(private_key,
                                  self.plain_text)

        self.assertEqual(ecies384._check_malleability(signature),
                         True)

        self.assertEqual(ecies384._check_malleability(
            ecies384._prevent_malleability(signature)),
            True)


if __name__ == '__main__':
    unittest.main()
