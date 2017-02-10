class MSP(object):
    """ Minimal Membership Service Provider.

    To manage identities by private keys, certificates with various crypto
    algorithms (e.g., ECDSA, RSA) and PKIs (software-managed or HSM based)
    """

    def __init__(self, trusted_certs, signer, admins, crypto_suite, id):
        """ Init with configuration info.

        Args:
            trusted_certs: trust anchors at boot
            signer: signing identity
            admins: admin privileges
            crypto_suites: crypto algorithm family
            id: id of the instance
        """
        self.trusted_certs = trusted_certs
        self.signer = signer
        self.admins = admins
        self.crypto_suite = crypto_suite
        self.id = id

    def validate(self, id):
        """ check whether the id is valid

        Args:
            id: id to check

        Returns: Boolean
        """
        return True
