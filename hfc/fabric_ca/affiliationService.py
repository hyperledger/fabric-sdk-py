import logging

_logger = logging.getLogger(__name__)


class AffiliationService(object):

    def __init__(self, client):
        self._client = client

    def create(self, registrar, name, caname='', force=False):
        """
        Create a new affiliation.
        The caller must have hf.AffiliationMgr authority.

        If any of the parent affiliations do not exist and 'force' is true,
        create all parent affiliations also.

        name (str): The affiliation path to create
        caname (str): Optional. Name of the CA to send the request to within
         the Fabric CA server
        force (boolean): Optional.
        registrar (Enrollment): Required. The identity of the registrar
         (i.e. who is performing the registration)

        Returns: res (Dict): result

        Raises:
            RequestException: errors in requests.exceptions
            ValueError: Failed response, json parse error, args missing
        """

        path = 'affiliations'

        if force is True:
            path += '?force=true'

        _logger.debug("create new affiliation with url {0}".format(path))

        req = {
            'name': name,
            'caname': caname
        }

        authorization = self._client.generateAuthToken(req, registrar)
        headers = {'Authorization': authorization}
        verify = self._client._ca_certs_path

        res, st = self._client._send_ca_post(path=path,
                                             json=req,
                                             headers=headers,
                                             verify=verify)

        _logger.debug("Response status {0}".format(st))
        _logger.debug("Raw response json {0}".format(res))

        return res

    def getOne(self, affiliation, registrar):
        """
        List a specific affiliation at or below the caller's affinity.
        The caller must have hf.AffiliationMgr authority.

        affiliation (str): The affiliation path to be queried.
        registrar (Enrollment): Required. The identity of the registrar
         (i.e. who is performing the registration)

        Returns: res (Dict): result

        Raises:
            RequestException: errors in requests.exceptions
            ValueError: Failed response, json parse error, args missing
        """

        if not isinstance(affiliation, str):
            raise ValueError('argument "affiliation" is not a valid string')

        path = 'affiliations/' + affiliation
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
        """
        List all affiliations equal to and below the caller's affiliation.
        The caller must have hf.AffiliationMgr authority.

        registrar (Enrollment): Required. The identity of the registrar
         (i.e. who is performing the registration)

        Returns: res (Dict): result

        Raises:
            RequestException: errors in requests.exceptions
            ValueError: Failed response, json parse error, args missing
        """

        path = 'affiliations'
        authorization = self._client.generateAuthToken(None, registrar)
        headers = {'Authorization': authorization}
        verify = self._client._ca_certs_path
        res, st = self._client._send_ca_get(path,
                                            headers=headers,
                                            verify=verify)

        _logger.debug("Response status {0}".format(st))
        _logger.debug("Raw response json {0}".format(res))

        return res

    def delete(self, affiliation, registrar, force=False):
        """
        Delete an affiliation.
        The caller must have hf.AffiliationMgr authority.
        Ca server must have cfg.affiliations.allowremove: true

        If force is true and there are any child affiliations or any identities
        are associated with this affiliation or child affiliations, these
         identities and child affiliations
        will be deleted; otherwise, an error is returned.

        registrar (Enrollment): Required. The identity of the registrar
         (i.e. who is performing the registration)

        Returns: res (Dict): result

        Raises:
            RequestException: errors in requests.exceptions
            ValueError: Failed response, json parse error, args missing
        """

        if not isinstance(affiliation, str):
            raise ValueError('argument "affiliation" is not a valid string')

        path = 'affiliations/' + affiliation
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

    def update(self, affiliation, registrar, name, caname='',
               force=False):
        """
        Rename an affiliation.
        The caller must have hf.AffiliationMgr authority.

        If any identities are associated with this affiliation, 'force' is true
        causes these identities' affiliations to be renamed; otherwise, an
         error is returned.

        affiliation (str): The affiliation path to be updated.
        name (str): The affiliation path to create
        caname (str): Optional. Name of the CA to send the request to within
         the Fabric CA server
        force (boolean): Optional.
        registrar (Enrollment): Required. The identity of the registrar
         (i.e. who is performing the registration)

        Returns: res (Dict): result

        Raises:
            RequestException: errors in requests.exceptions
            ValueError: Failed response, json parse error, args missing
        """

        if not isinstance(affiliation, str):
            raise ValueError('argument "affiliation" is not a valid string')

        if not isinstance(name, str):
            raise ValueError('argument "name" is not a valid string')

        path = 'affiliations/' + affiliation

        if force:
            path += '?force=true'

        req = {
            'name': name
        }
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
