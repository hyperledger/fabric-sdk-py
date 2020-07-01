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
import json
import logging

from numbers import Number

import requests
import six
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import NameOID

from hfc.fabric_ca.certificateService import CertificateService
from hfc.fabric_ca.identityService import IdentityService
from hfc.fabric_ca.affiliationService import AffiliationService
from hfc.util.crypto.crypto import ecies

DEFAULT_CA_ENDPOINT = 'http://localhost:7054'
DEFAULT_CA_BASE_URL = '/api/v1/'

_logger = logging.getLogger(__name__)

reasons = (
    (1, 'unspecified'),
    (2, 'keycompromise'),
    (3, 'cacompromise'),
    (4, 'affiliationchange'),
    (5, 'superseded'),
    (6, 'cessationofoperation'),
    (7, 'certificatehold'),
    (8, 'removefromcrl'),
    (9, 'privilegewithdrawn'),
    (10, 'aacompromise')
)


class Enrollment(object):
    """Class represents enrollment."""

    def __init__(self, private_key, enrollmentCert, caCertChain=None,
                 service=None):
        self._service = service
        self._private_key = private_key
        self._cert = enrollmentCert
        self._caCert = caCertChain

    @property
    def private_key(self):
        """Get private key

        :return: private key
        """
        return self._private_key

    @private_key.setter
    def private_key(self, private_key):
        """Set the private key

        :param private_key: private key
        :return:
        """
        self._private_key = private_key

    @property
    def cert(self):
        """Get cert

        :return: cert
        """
        return self._cert

    @cert.setter
    def cert(self, cert):
        """Set cert

        :param cert: cert
        :return:
        """
        self._cert = cert

    @property
    def caCert(self):
        """Get caCert

        :return: caCert
        """
        return self._caCert

    @caCert.setter
    def caCert(self, caCert):
        """Set caCert

        :param caCert: caCert
        :return:
        """
        self._caCert = caCert

    def get_attrs(self):
        return ",".join("{}={}"
                        .format(k, getattr(self, k))
                        for k in self.__dict__.keys())

    def register(self, enrollmentID, enrollmentSecret=None, role=None,
                 affiliation=None, maxEnrollments=1, attrs=None):

        # TODO, default should be equal to registrar
        # https://hyperledger-fabric-ca.readthedocs.io/en/latest/users-guide.ht
        # ml#registering-a-new-identity
        if affiliation is None:
            affiliation = ''

        if not enrollmentID:
            msg = 'Missing required parameter. \'enrollmentID\' is required.'
            raise ValueError(msg)
        if not isinstance(maxEnrollments, Number):
            msg = 'Wrong parameter. \'maxEnrollments\' must be a' \
                  ' number'
            raise ValueError(msg)

        return self._service.register(enrollmentID, enrollmentSecret, role,
                                      affiliation, maxEnrollments, attrs, self)

    # https://hyperledger-fabric-ca.readthedocs.io/en/latest/users-guide.html
    # #revoking-a-certificate-or-identity
    def revoke(self, enrollmentID=None, aki=None, serial=None,
               reason=None, gencrl=False):
        if not enrollmentID:
            if not aki or not serial:
                msg = 'Enrollment ID is empty, thus both "aki" and "serial"' \
                      ' must have non-empty values'
                raise ValueError(msg)

        if reason and reason not in [r[1] for r in reasons]:
            msg = 'Reason is not a valid one. Please review reasons listed' \
                  ' in fabric-ca specifications.'
            raise ValueError(msg)

        return self._service.revoke(enrollmentID, aki, serial,
                                    reason, gencrl, self)

    def generateCRL(self, revokedBefore=None, revokedAfter=None,
                    expireBefore=None, expireAfter=None):

        if revokedAfter and revokedBefore:
            try:
                if revokedAfter > revokedBefore:
                    msg = 'revokedAfter Date cannot be greater than the' \
                          ' revokedBefore Date'
                    raise ValueError(msg)
            except Exception:
                msg = 'revokedAfter and revokedBefore are not Date'
                raise ValueError(msg)

        # pass date to YYYY-MM-DDTHH:mm:ss.sssZ
        try:
            revokedBefore = revokedBefore.isoformat()
        except Exception:
            revokedBefore = None

        try:
            revokedAfter = revokedAfter.isoformat()
        except Exception:
            revokedAfter = None

        try:
            expireBefore = expireBefore.isoformat()
        except Exception:
            expireBefore = None

        try:
            expireAfter = expireAfter.isoformat()
        except Exception:
            expireAfter = None

        return self._service.generateCRL(revokedBefore, revokedAfter,
                                         expireBefore, expireAfter, self)

    def __str__(self):
        return "[{}:{}]".format(self.__class__.__name__, self.get_attrs())


class CAClient(object):
    """Client for communicating with the Fabric CA APIs."""

    def __init__(self, target=DEFAULT_CA_ENDPOINT, ca_certs_path=None,
                 base_url=DEFAULT_CA_BASE_URL, ca_name="",
                 cryptoPrimitives=ecies()):
        """ Init CA client.

        :param target: CA server address including protocol,hostname,port
        :param ca_certs_path: Local ca certs path
        :param ca_name: The optional name of the CA. Fabric-ca servers
        support multiple Certificate Authorities from a single server
        If omitted or null or an empty string, then the default CA is
        the target of requests.
        :return: An instance of CAClient
        """
        self._ca_certs_path = ca_certs_path
        self._base_url = target + base_url
        self._ca_name = ca_name
        self._cryptoPrimitives = cryptoPrimitives

    def generateAuthToken(self, req, registrar):
        """Generate authorization token required for accessing fabric-ca APIs

        :param req: request body
        :type req: dict
        :param registrar: Required. The identity of the registrar
        (i.e. who is performing the request)
        :type registrar: Enrollment
        :return: auth token
        """
        b64Cert = base64.b64encode(registrar._cert)

        if req:
            reqJson = json.dumps(req, ensure_ascii=False)
            b64Body = base64.b64encode(reqJson.encode())

            # /!\ cannot mix f format and b
            # https://stackoverflow.com/questions/45360480/is-there-a-
            # formatted-byte-string-literal-in-python-3-6
            bodyAndCert = b'%s.%s' % (b64Body, b64Cert)
        else:
            bodyAndCert = b'.%s' % b64Cert

        sig = self._cryptoPrimitives.sign(registrar._private_key, bodyAndCert)
        b64Sign = base64.b64encode(sig)

        # /!\ cannot mix f format and b
        return b'%s.%s' % (b64Cert, b64Sign)

    def _send_ca_post(self, path, **param):
        """Send a post request to the ca service

        :param path: sub path after the base_url
        :param **param: post request params
        :return: the response body in json
        """
        r = requests.post(url=self._base_url + path, **param)
        return r.json(), r.status_code

    def _send_ca_get(self, path, **param):
        """Send a get request to the ca service

        :param path: sub path after the base_url
        :param **param: get request params
        :return: the response body in json
        """
        r = requests.get(url=self._base_url + path, **param)
        return r.json(), r.status_code

    def _send_ca_delete(self, path, **param):
        """Send a delete request to the ca service

        :param path: sub path after the base_url
        :param **param: delete request params
        :return: the response body in json
        """
        r = requests.delete(url=self._base_url + path, **param)
        return r.json(), r.status_code

    def _send_ca_update(self, path, **param):
        """Send a update request to the ca service

        :param path: sub path after the base_url
        :param **param: update request params
        :return: the response body in json
        """
        r = requests.put(url=self._base_url + path, **param)
        return r.json(), r.status_code

    def get_cainfo(self):
        """Query the ca service information.

        :return: The base64 encoded CA PEM file content for the caname
        """
        if self._ca_name != "":
            body_data = {"caname": self._ca_name}
        else:
            body_data = {}
        res, st = self._send_ca_post(path="cainfo", json=body_data,
                                     verify=self._ca_certs_path)
        _logger.debug("Response status {0}".format(st))
        _logger.debug("Raw response json {0}".format(res))

        if res['success'] and res['result']['CAName'] == self._ca_name:
            return base64.b64decode(res['result']['CAChain'])
        else:
            raise ValueError("get_cainfo failed with errors {0}"
                             .format(res['errors']))

    def enroll(self, enrollment_id, enrollment_secret, csr, profile='',
               attr_reqs=None):
        if not enrollment_id or not enrollment_secret or not csr:
            raise ValueError("Missing required parameters. "
                             "'enrollmentID', 'enrollmentSecret' and 'csr'"
                             " are all required.")

        req = {'certificate_request': csr}
        if self._ca_name != '':
            req.update({
                'caname': self._ca_name
            })
        if profile:
            req.update({
                'profile': profile
            })
        if attr_reqs:
            req.update({
                'attr_reqs': attr_reqs
            })

        res, st = self._send_ca_post(path='enroll',
                                     json=req,
                                     auth=(enrollment_id, enrollment_secret),
                                     verify=self._ca_certs_path)

        _logger.debug("Response status {0}".format(st))
        _logger.debug("Raw response json {0}".format(res))

        if res['success']:
            return base64.b64decode(res['result']['Cert']), \
                base64.b64decode(res['result']['ServerInfo']['CAChain'])
        else:
            raise ValueError("Enrollment failed with errors {0}"
                             .format(res['errors']))

    def register(self, req, registrar):
        authorization = self.generateAuthToken(req, registrar)

        res, st = self._send_ca_post(path="register",
                                     json=req,
                                     headers={'Authorization': authorization},
                                     verify=self._ca_certs_path)

        _logger.debug("Response status {0}".format(st))
        _logger.debug("Raw response json {0}".format(res))

        if res['success']:
            return res['result']['secret']
        else:
            raise ValueError("Registering failed with errors {0}"
                             .format(res['errors']))

    def reenroll(self, req, registrar):
        authorization = self.generateAuthToken(req, registrar)

        res, st = self._send_ca_post(path='reenroll',
                                     json=req,
                                     headers={'Authorization': authorization},
                                     verify=self._ca_certs_path)

        _logger.debug("Response status {0}".format(st))
        _logger.debug("Raw response json {0}".format(res))

        if res['success']:
            return base64.b64decode(res['result']['Cert']), \
                base64.b64decode(res['result']['ServerInfo']['CAChain'])
        else:
            raise ValueError("Reenrollment failed with errors {0}"
                             .format(res['errors']))

    def revoke(self, req, registrar):
        authorization = self.generateAuthToken(req, registrar)

        res, st = self._send_ca_post(path="revoke",
                                     json=req,
                                     headers={'Authorization': authorization},
                                     verify=self._ca_certs_path)

        _logger.debug("Response status {0}".format(st))
        _logger.debug("Raw response json {0}".format(res))

        if res['success']:
            return res['result']['RevokedCerts'], res['result']['CRL']
        else:
            raise ValueError("Revoking failed with errors {0}"
                             .format(res['errors']))

    def generateCRL(self, req, registrar):
        authorization = self.generateAuthToken(req, registrar)
        res, st = self._send_ca_post(path='gencrl',
                                     json=req,
                                     headers={'Authorization': authorization},
                                     verify=self._ca_certs_path)

        _logger.debug('Response status {0}'.format(st))
        _logger.debug('Raw response json {0}'.format(res))

        if res['success']:
            return res['result']['CRL']
        else:
            raise ValueError('generating CRL failed with errors {0}'
                             .format(res['errors']))

    def newIdentityService(self):
        return IdentityService(self)

    def newAffiliationService(self):
        return AffiliationService(self)

    def newCertificateService(self):
        return CertificateService(self)


class CAService(object):
    """This is a ca server delegate."""

    def __init__(self, target=DEFAULT_CA_ENDPOINT,
                 ca_certs_path=None, crypto=ecies(), ca_name=''):
        """ Init CA service.

        :param target: CA server address including protocol, hostname, port
        :param ca_certs_path: Local ca certs path
        :param crypto:  A crypto instance
        :param ca_name: The optional name of the CA, Fabric-ca servers
        support multiple Certificate Authorties from a signle server.
        If omitted or null or an empty string, then the default CA
        is the target of requests
        :return: An instance of CAService
        """
        self._crypto = crypto
        self._ca_client = CAClient(target, ca_certs_path, ca_name=ca_name,
                                   cryptoPrimitives=self._crypto)

    def enroll(self, enrollment_id, enrollment_secret, csr=None, profile='',
               attr_reqs=None):
        """Enroll a registered user in order to receive a signed X509
         certificate

        :param enrollment_id: The registered ID to use for enrollment
        :type enrollment_id: str
        :param enrollment_secret: The secret associated with the
                                     enrollment ID
        :type enrollment_secret: str
        :param profile: The profile name.  Specify the 'tls' profile for a
             TLS certificate; otherwise, an enrollment certificate is issued. (Default value = '')
        :type profile: str
        :param csr: Optional. PEM-encoded PKCS#10 Certificate Signing
             Request. The message sent from client side to Fabric-ca for the
              digital identity certificate. (Default value = None)
        :type csr: str
        :param attr_reqs: An array of AttributeRequest
        :return: PEM-encoded X509 certificate (Default value = None)
        :type attr_reqs: list
        :raises RequestException: errors in requests.exceptions
        :raises ValueError: Failed response, json parse error, args missing
        """

        if attr_reqs:
            if not isinstance(attr_reqs, list):
                raise ValueError("attr_reqs must be an array of"
                                 " AttributeRequest objects")
            else:
                for attr in attr_reqs:
                    if not attr['name']:
                        raise ValueError("attr_reqs object is missing the name"
                                         " of the attribute")

        private_key = None
        if csr:
            _logger.debug("try to enroll with a csr")
        else:
            private_key = self._crypto.generate_private_key()
            csr = self._crypto.generate_csr(private_key, x509.Name(
                [x509.NameAttribute(NameOID.COMMON_NAME,
                                    six.u(enrollment_id))]))

        enrollmentCert, caCertChain = self._ca_client.enroll(
            enrollment_id,
            enrollment_secret,
            csr.public_bytes(Encoding.PEM).decode('utf-8'),
            profile,
            attr_reqs)

        return Enrollment(private_key, enrollmentCert, caCertChain, self)

    def reenroll(self, currentUser, attr_reqs=None):
        """Re-enroll the member in cases such as the existing enrollment
         certificate is about to expire, or it has been compromised

        :param currentUser: The identity of the current user that
             holds the existing enrollment certificate
        :type currentUser: Enrollment
        :param attr_reqs: Optional. An array of AttributeRequest that
             indicate attributes to be included in the certificate
        :return: PEM-encoded X509 certificate (Default value = None)
        :type attr_reqs: list
        :raises RequestException: errors in requests.exceptions
        :raises ValueError: Failed response, json parse error, args missing
        """

        if not isinstance(currentUser, Enrollment):
            raise ValueError('"currentUser" is not a valid Enrollment object')

        if attr_reqs:
            if not isinstance(attr_reqs, list):
                raise ValueError("attr_reqs must be an array of"
                                 " AttributeRequest objects")
            else:
                for attr in attr_reqs:
                    if not attr.name:
                        raise ValueError("attr_reqs object is missing the name"
                                         " of the attribute")

        cert = currentUser.cert
        cert = x509.load_pem_x509_certificate(cert, default_backend())

        private_key = self._crypto.generate_private_key()
        csr = self._crypto.generate_csr(private_key, cert.subject)

        req = {'certificate_request': csr.public_bytes(Encoding.PEM).decode(
            'utf-8')}
        if attr_reqs:
            req.update({
                'attr_reqs': attr_reqs
            })

        enrollmentCert, caCertChain = self._ca_client.reenroll(req,
                                                               currentUser)

        return Enrollment(private_key, enrollmentCert, caCertChain, self)

    def register(self, enrollmentID, enrollmentSecret, role, affiliation,
                 maxEnrollments, attrs, registrar):
        """Register a user in order to receive a secret

        :param registrar: The registrar
        :type registrar: Enrollment
        :param enrollmentID: enrollmentID ID which will be used for
             enrollment
        :type enrollmentID: str
        :param enrollmentSecret: enrollmentSecret Optional enrollment secret
             to set for the registered user.
             If not provided, the server will generate one.
             When not including, use a null for this parameter.
        :type enrollmentSecret: str
        :param role: Optional type of role for this user.
                        When not including, use a null for this parameter.
        :type role: str
        :param affiliation: Affiliation with which this user will be
             associated
        :type affiliation: str
        :param maxEnrollments: The maximum number of times the user is
             permitted to enroll
        :type maxEnrollments: number
        :param attrs: Array of key/value attributes to assign to the user
        :return The enrollment secret to use when this user
         enrolls
        :type attrs: dict
        :raises RequestException: errors in requests.exceptions
        :raises ValueError: Failed response, json parse error, args missing
        """
        req = {
            "id": enrollmentID,
            "affiliation": affiliation,
            "max_enrollments": maxEnrollments,
        }

        if role:
            req['type'] = role

        if attrs:
            req['attrs'] = attrs

        if isinstance(enrollmentSecret, str) and len(enrollmentSecret):
            req['secret'] = enrollmentSecret

        return self._ca_client.register(req, registrar)

    def revoke(self, enrollmentID, aki, serial, reason, gencrl, registrar):
        """Revoke an existing certificate (enrollment certificate or
         transaction certificate), or revoke all certificates issued to an
          enrollment id. If revoking a particular certificate, then both the
           Authority Key Identifier and serial number are required. If
            revoking by enrollment id, then all future requests to enroll this
             id will be rejected.

        :param registrar: The registrar
        :type registrar: Enrollment
        :param enrollmentID: enrollmentID ID to revoke
        :type enrollmentID: str
        :param aki: Authority Key Identifier string, hex encoded, for the
             specific certificate to revoke
        :type aki: str
        :param serial: Serial number string, hex encoded, for the specific
             certificate to revoke
        :type serial: str
        :param reason: The reason for revocation.
             See https://godoc.org/golang.org/x/crypto/ocsp for valid values
        :type reason: str
        :param gencrl: GenCRL specifies whether to generate a CRL
        :return: The revocation results
        :type gencrl: bool
        :raises RequestException: errors in requests.exceptions
        :raises ValueError: Failed response, json parse error, args missing
        """
        req = {
            "id": enrollmentID,
            "aki": aki,
            "serial": serial,
            "reason": reason,
            "gencrl": gencrl
        }

        if self._ca_client._ca_name != '':
            req.update({
                'caname': self._ca_client._ca_name
            })

        return self._ca_client.revoke(req, registrar)

    def generateCRL(self, revokedBefore, revokedAfter, expireBefore,
                    expireAfter, registrar):
        """Generate CRL

        :param revokedBefore: Include certificates that were revoked before
         this UTC timestamp (in RFC3339 format) in the CRL
        :param revokedAfter: Include certificates that were revoked after
         this UTC timestamp (in RFC3339 format) in the CRL
        :param expireBefore: Include revoked certificates that expire before
         this UTC timestamp (in RFC3339 format) in the CRL
        :param expireAfter: Include revoked certificates that expire after
         this UTC timestamp (in RFC3339 format) in the CRL
        :param registrar: registrar
        :return: The Certificate Revocation List (CRL)
        """
        req = {
            'revokedBefore': revokedBefore,
            'revokedAfter': revokedAfter,
            'expireBefore': expireBefore,
            'expireAfter': expireAfter
        }

        if self._ca_client._ca_name != '':
            req.update({
                'caname': self._ca_client._ca_name
            })

        return self._ca_client.generateCRL(req, registrar)

    def newIdentityService(self):
        return self._ca_client.newIdentityService()

    def newAffiliationService(self):
        return self._ca_client.newAffiliationService()

    def newCertificateService(self):
        return self._ca_client.newCertificateService()


def ca_service(target=DEFAULT_CA_ENDPOINT,
               ca_certs_path=None, crypto=ecies(), ca_name=""):
    """Create ca service

    :param target: url (Default value = DEFAULT_CA_ENDPOINT)
    :param ca_certs_path: certs path (Default value = None)
    :param crypto: crypto (Default value = ecies())
    :param ca_name: CA name
    :return: ca service instance (Default value = "")
    """
    return CAService(target, ca_certs_path, crypto, ca_name)
