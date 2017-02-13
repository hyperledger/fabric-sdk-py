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
        self.id = id
        self.certificate = certificate
        self.public_key = public_key
        self.msp = msp

    def get_msp_id(self):
        """ Get the id of the msp

        Returns: id string of the msp
        """
        return self.msp.id

    def verify(self, msg, signature, opts={}):
        """ Verify a signagure on the msg

        Args:
            msg: Message to be verified
            signature: Message signature to match
            opts: Potential policy and labels

        Returns: Boolean

        """
        # TODO: imlement with crypto_suite's verify
        return True


class Signer(object):
    """ To help sign with crypto algorithms.
    """

    def __init__(self, crypto_suite, key):
        """ Init.

        Args:
            crypto_suite: signature algorithms
            key:  private key
        """
        self.cryto_suite = crypto_suite
        self.key = key

    def get_public_key(self):
        """ Get the public key

        Returns: The public key

        """
        # TODO: imeplement with crypto algorithms
        return ""

    def sign(self, digest, opts={}):
        """ sign a digest

        Args:
            digest: message digest
            opts:  hash function to use for generate the digest

        Returns: The public key
        """
        return self.cryto_suite.sign(self.key, digest, opts)


class SigningIdentity(Identity):
    """ Extended identity to support signing operations.
    """

    def __init__(self, id, certificate, public_key, msp, signer):
        """ Init.

        Args:
            id: id of this object
            certificate: certificate HEX string for the PEM encoded certificate
            public_key: The public key represented by the certificate
            msp: The associated MSP that manages this identity
            signer: Signer
        """
        super(SigningIdentity, self).__init__(id, certificate, public_key, msp)
        self.signer = signer

    def sign(self, msg):
        """ Sign a message

        Args:
            msg: message to sign

        Returns: signed results
        """
        digest = self.msp.crypto_suite.hash(msg)
        return self.signer.sign(digest)
