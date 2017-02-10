class Identity(object):
    """ MSP Identity.

    Use by client to validate certificates from endorser's sign, and also
    verify the endorser's signature.
    """

    def __init__(self, id, certificate, public_key, msp):
        """ Init.

        Args:
            id: id of this object
            certificate: certificate HEX string for the PEM encoded certificate
            public_key: The public key represented by the certificate
            msp: The associated MSP that manages this identity
        """
        pass
