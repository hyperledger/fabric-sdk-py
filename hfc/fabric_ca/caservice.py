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
import base64
import logging

import requests
import six
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import NameOID

from hfc.util.crypto.crypto import ecies

DEFAULT_CA_ENDPOINT = 'http://localhost:7054'
DEFAULT_CA_BASE_URL = '/api/v1/'

_logger = logging.getLogger(__name__)


class Enrollment(object):
    """ Class represents enrollment. """

    def __init__(self, private_key, cert):
        self._private_key = private_key
        self._cert = cert

    @property
    def private_key(self):
        """ Get private key

        Returns: private key

        """
        return self._private_key

    @private_key.setter
    def private_key(self, private_key):
        """ Set the private key

        Args:
            private_key: private key

        """
        self._private_key = private_key

    @property
    def cert(self):
        """ Get cert

        Returns: cert

        """
        return self._cert

    @cert.setter
    def cert(self, cert):
        """ Set cert

        Args:
            cert: cert

        """
        self._cert = cert

    def get_attrs(self):
        return ",".join("{}={}"
                        .format(k, getattr(self, k))
                        for k in self.__dict__.keys())

    def __str__(self):
        return "[{}:{}]".format(self.__class__.__name__, self.get_attrs())


class CAClient(object):
    """Client for communicating with the Fabric CA APIs."""

    def __init__(self, target=DEFAULT_CA_ENDPOINT, ca_certs_path=None,
                 base_url=DEFAULT_CA_BASE_URL, ca_name=""):
        """ Init CA client.

        Args:
            target (str): CA server address including protocol,hostname,port
            ca_certs_path (str): Local ca certs path
            ca_name (str): The optional name of the CA. Fabric-ca servers
            support multiple Certificate Authorities from a single server
            If omitted or null or an empty string, then the default CA is
            the target of requests.
        """
        self._ca_certs_path = ca_certs_path
        self._base_url = target + base_url
        self._ca_name = ca_name

    def _send_ca_post(self, path, **param):
        """ Send a post request to the ca service

        Args:
            path: sub path after the base_url
            **param: post request params

        Returns: the response body in json

        """
        return requests.post(url=self._base_url + path, **param).json()

    def get_cainfo(self):
        """Query the ca service information.

        Args:

        Returns: The base64 encoded CA PEM file content for the caname

        """
        if self._ca_name != "":
            body_data = {"caname": self._ca_name}
        else:
            body_data = {}
        response = self._send_ca_post(path="cainfo", json=body_data,
                                      verify=self._ca_certs_path)
        _logger.debug("Raw response json {0}".format(response))
        if (response['success'] and response['result']['CAName']
                == self._ca_name):
            return base64.b64decode(response['result']['CAChain'])
        else:
            raise ValueError("get_cainfo failed with errors {0}"
                             .format(response['errors']))

    def enroll(self, enrollment_id, enrollment_secret, csr):
        """Enroll a registered user in order to receive a signed X509 certificate

        Args:
            enrollment_id (str): The registered ID to use for enrollment
            enrollment_secret (str): The secret associated with the
                                     enrollment ID
            csr (bytes or file-like object): PEM-encoded PKCS#10 certificate
                                             signing request

        Returns: PEM-encoded X509 certificate

        Raises:
            RequestException: errors in requests.exceptions
            ValueError: Failed response, json parse error, args missing

        """
        if not enrollment_id or not enrollment_secret or not csr:
            raise ValueError("Missing required parameters. "
                             "'enrollmentID', 'enrollmentSecret' and 'csr'"
                             " are all required.")

        if self._ca_name != "":
            req = {
                "caName": self._ca_name,
                "certificate_request": csr
            }
        else:
            req = {"certificate_request": csr}

        response = self._send_ca_post(path="enroll", json=req,
                                      auth=(enrollment_id, enrollment_secret),
                                      verify=self._ca_certs_path)

        _logger.debug("Raw response json {0}".format(response))

        if response['success']:
            return base64.b64decode(response['result']['Cert'])
        else:
            raise ValueError("Enrollment failed with errors {0}"
                             .format(response['errors']))


class CAService(object):
    """This is a ca server delegate."""

    def __init__(self, target=DEFAULT_CA_ENDPOINT,
                 ca_certs_path=None, crypto=ecies(), ca_name=""):
        """ Init CA service.

        Args:
            target (str): CA server address including protocol,hostname,port
            ca_certs_path (str): Local ca certs path
            crypto (Crypto): A crypto instance
            ca_name (str): The optional name of the CA, Fabric-ca servers
            support multiple Certificate Authorties from a signle server.
            If omitted or null or an empty string, then the default CA
            is the target of requests
        """
        self._ca_client = CAClient(target, ca_certs_path, ca_name=ca_name)
        self._crypto = crypto

    def enroll(self, enrollment_id, enrollment_secret):
        """Enroll a registered user in order to receive a signed X509 certificate

        Args:
            enrollment_id (str): The registered ID to use for enrollment
            enrollment_secret (str): The secret associated with the
                                     enrollment ID

        Returns: PEM-encoded X509 certificate

        Raises:
            RequestException: errors in requests.exceptions
            ValueError: Failed response, json parse error, args missing

        """
        private_key = self._crypto.generate_private_key()
        csr = self._crypto.generate_csr(private_key, x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, six.u(enrollment_id))]))
        cert = self._ca_client.enroll(
            enrollment_id, enrollment_secret,
            csr.public_bytes(Encoding.PEM).decode("utf-8"))

        return Enrollment(private_key, cert)


def ca_service(target=DEFAULT_CA_ENDPOINT,
               ca_certs_path=None, crypto=ecies(), ca_name=""):
    """Create ca service

    Args:
        target: url
        ca_certs_path: certs path
        crypto: crypto
        ca_name: CA name

    Returns: ca service instance

    """
    return CAService(target, ca_certs_path, crypto, ca_name)
