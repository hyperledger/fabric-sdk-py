import logging

from numbers import Number

_logger = logging.getLogger(__name__)


class IdentityService(object):

    def __init__(self, client):
        self._client = client

    def create(self, registrar, enrollmentID, enrollmentSecret=None, role=None,
               affiliation=None, maxEnrollments=1, attrs=None):
        """
        Create a new identity with the Fabric CA server.
        An enrollment secret is returned which can then be used, along with
         the enrollment ID, to enroll a new identity.
        The caller must have `hf.Registrar` authority.

        enrollmentID (str): enrollmentID ID which will be used for
         enrollment
        enrollmentSecret (str): enrollmentSecret Optional enrollment secret
         to set for the registered user.
         If not provided, the server will generate one.
         When not including, use a null for this parameter.
        role (str): Optional type of role for this user.
                    When not including, use a null for this parameter.
        affiliation (str):  Affiliation with which this user will be
         associated
        maxEnrollments (number): The maximum number of times the user is
         permitted to enroll
        attrs (dict):  Array of key/value attributes to assign to the user

        Returns: secret (str): The enrollment secret to use when this user
         enrolls

        Raises:
            RequestException: errors in requests.exceptions
            ValueError: Failed response, json parse error, args missing
        """

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

        req = {
            'id': enrollmentID,
            'affiliation': affiliation,
            'max_enrollments': maxEnrollments,
        }

        if role:
            req['type'] = role

        if attrs:
            req['attrs'] = attrs

        if isinstance(enrollmentSecret, str) and len(enrollmentSecret):
            req['secret'] = enrollmentSecret

        authorization = self._client.generateAuthToken(req, registrar)
        headers = {'Authorization': authorization}
        verify = self._client._ca_certs_path
        res, st = self._client._send_ca_post(path='identities',
                                             json=req,
                                             headers=headers,
                                             verify=verify)

        _logger.debug("Response status {0}".format(st))
        _logger.debug("Raw response json {0}".format(res))

        if res['success']:
            return res['result']['secret']
        else:
            raise ValueError("Registering failed with errors {0}"
                             .format(res['errors']))

    def getOne(self, enrollmentID, registrar):

        if not isinstance(enrollmentID, str):
            raise ValueError('argument "enrollmentID" is not a valid string')

        path = 'identities/' + enrollmentID + '?ca=' + self._client._ca_name
        authorization = self._client.generateAuthToken(None, registrar)
        headers = {'Authorization': authorization}
        verify = self._client._ca_certs_path
        res, st = self._client._send_ca_get(path,
                                            headers=headers,
                                            verify=verify)

        _logger.debug("Response status {0}".format(st))
        _logger.debug("Raw response json {0}".format(res))

        return res

    def getAll(self, registrar):

        path = 'identities?ca=' + self._client._ca_name
        authorization = self._client.generateAuthToken(None, registrar)
        headers = {'Authorization': authorization}
        verify = self._client._ca_certs_path
        res, st = self._client._send_ca_get(path,
                                            headers=headers,
                                            verify=verify)

        _logger.debug("Response status {0}".format(st))
        _logger.debug("Raw response json {0}".format(res))

        return res

    def delete(self, enrollmentID, registrar, force=False):

        if not isinstance(enrollmentID, str):
            raise ValueError('argument "enrollmentID" is not a valid string')

        path = 'identities/' + enrollmentID
        if force is True:
            path += '?force=true'

        authorization = self._client.generateAuthToken(None, registrar)
        headers = {'Authorization': authorization}
        verify = self._client._ca_certs_path
        res, st = self._client._send_ca_delete(path,
                                               headers=headers,
                                               verify=verify)

        _logger.debug("Response status {0}".format(st))
        _logger.debug("Raw response json {0}".format(res))

        return res

    def update(self, enrollmentID, registrar, type=None, affiliation=None,
               maxEnrollments=None, attrs=None, enrollmentSecret=None,
               caname=None):

        if not isinstance(enrollmentID, str):
            raise ValueError('argument "enrollmentID" is not a valid string')

        path = 'identities/' + enrollmentID

        req = {}
        if type:
            req['type'] = type
        if affiliation:
            req['affiliation'] = affiliation
        if isinstance(maxEnrollments, Number):
            req['max_enrollments'] = maxEnrollments
        if attrs:
            req['attrs'] = attrs
        if enrollmentSecret:
            req['secret'] = enrollmentSecret
        if caname:
            req['caname'] = caname

        authorization = self._client.generateAuthToken(req, registrar)
        headers = {'Authorization': authorization}
        verify = self._client._ca_certs_path
        res, st = self._client._send_ca_update(path,
                                               json=req,
                                               headers=headers,
                                               verify=verify)

        _logger.debug("Response status {0}".format(st))
        _logger.debug("Raw response json {0}".format(res))

        return res
