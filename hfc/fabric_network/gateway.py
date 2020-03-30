import logging

from hfc.fabric import Client

consoleHandler = logging.StreamHandler()
_logger = logging.getLogger(__name__)

_logger.setLevel(logging.DEBUG)
_logger.addHandler(consoleHandler)


class Gateway(object):
    def __init(self):
        self.client = None
        self.wallet = None
        self.network = {}
        self.options = {}

    async def connect(self, config, options):

        if 'wallet' not in options:
            _logger.error("A wallet must be assigned to a gateway instance")

        if not config:
            self.client = Client()
        else:
            self.client = Client(net_profile=config)

        if 'identity' in options:
            self.current_identity = self.clientget_user(org_name=options['identity']['org_name'],
                                                        name=options['identity']['name'])

    def get_current_identity(self):
        return self.current_identity

    def get_client(self):
        return self.client

    def get_options(self):
        return self.options
