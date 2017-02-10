class MSP(object):
    """ Minimal Membership Service Provider.

    To manage identities by private keys, certificates with various crypto
    algorithms (e.g., ECDSA, RSA) and PKIs (software-managed or HSM based)
    """

    def __init__(self, config):
        """ Init with configuration info.

        Args:
            config: include trusted_certs, signer, admins, id, crypto_suites.
        """
        pass
