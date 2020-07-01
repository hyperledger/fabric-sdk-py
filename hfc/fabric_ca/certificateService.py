import logging
import urllib.parse

_logger = logging.getLogger(__name__)


class CertificateService(object):

    def __init__(self, client):

        if not client:
            raise Exception('Missing Required Argument client<FabricCAClient>')

        self.client = client

    def getCertificates(self, registrar, id=None, aki=None, serial=None,
                        revoked_start=None, revoked_end=None,
                        expired_start=None, expired_end=None,
                        notexpired=None, notrevoked=None, ca=None):
        """The caller will be able to view certificates that it owns. In addition,
        if the caller has **hf.Registrar.Roles** or **hf.Revoker** attribute,
        it will be able to view certificates for identities that have
         affiliations equal to or below the caller's affiliation.

        :param registrar: Required. The identity of the registrar
         (i.e. who is performing the revocation) signing certificate, hash
          algorithm and signature algorithm
        :param id: The enrollment ID that uniquely identifies an identity (Default value = None)
        :param aki: Authority Key Identifier string, hex encoded, for the
          specific certificate (Default value = None)
        :param serial: The serial number for a certificate (Default value = None)
        :param revoked_start: Get revoked certificates starting at the specified time,
         either as timestamp (RFC3339 format) or duration (-30d) (Default value = None)
        :param revoked_end: Get revoked certificates before the specified time,
         either as timestamp * (RFC3339 format) or duration (-15d) (Default value = None)
        :param expired_start: Get expired certificates starting at the
         specified time, either as timestamp (RFC3339 format) or duration (-30d) (Default value = None)
        :param expired_end:  Get expired certificates before the specified time,
         either as timestamp (RFC3339 format) or duration (-15d) (Default value = None)
        :param notexpired: Don't return expired certificates (Default value = None)
        :param notrevoked: Don't return revoked certificates (Default value = None)
        :param ca: The name of the CA to direct this request to within the
         server, or the default CA if not specified (Default value = None)
        :return: result
        :raises RequestException: errors in requests.exceptions
        :raises ValueError: Failed response, json parse error, args missing
        """

        path = 'certificates'

        req = {}
        if id and isinstance(id, str):
            req['id'] = id
        if aki and isinstance(aki, str):
            req['aki'] = aki
        if serial and isinstance(serial, str):
            req['serial'] = serial
        if revoked_start and isinstance(revoked_start, str):
            req['revoked_start'] = revoked_start
        if revoked_end and isinstance(revoked_end, str):
            req['revoked_end'] = revoked_end
        if expired_start and isinstance(expired_start, str):
            req['expired_start'] = expired_start
        if expired_end and isinstance(expired_end, str):
            req['expired_end'] = expired_end
        if notrevoked and isinstance(notrevoked, bool):
            req['notrevoked'] = notrevoked
        if notexpired and isinstance(notexpired, bool):
            req['notexpired'] = notexpired
        if ca and isinstance(ca, str):
            req['ca'] = ca

        queryString = urllib.parse.quote_plus(urllib.parse.urlencode(req))
        if queryString:
            path += '?' + queryString

        authorization = self.client.generateAuthToken(None, registrar)
        headers = {'Authorization': authorization}
        verify = self.client._ca_certs_path

        _logger.debug('getCertificates with url: {0}'.format(path))
        res, st = self.client._send_ca_get(path,
                                           headers=headers,
                                           verify=verify)

        _logger.debug('Response status {0}'.format(st))
        _logger.debug('Raw response json {0}'.format(res))

        return res
