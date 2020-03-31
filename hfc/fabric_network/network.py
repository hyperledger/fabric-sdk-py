import logging

from hfc.fabric.channel.channel import Channel

consoleHandler = logging.StreamHandler()
_logger = logging.getLogger(__name__)

_logger.setLevel(logging.DEBUG)
_logger.addHandler(consoleHandler)


class Network(object):
    def __init__(self, gateway, channel):
        self.gateway = gateway
        self.channel = channel
        self.contracts = {}
        self.initialized = False
        self.listeners = {}
        self.discovery_enabled = False

    async def __init_internal_channel(self, discovery):
        if discovery:
            self.discovery_enabled = True
            client = self.gateway.get_client()
            ledger_peers = client._peers
            if len(ledger_peers) == 0:
                _logger.error("No peers defined")
        else:
            if not isinstance(self.channel, Channel):
                _logger.error("network.channel should be an instance of channel")
            ledger_peers = self.channel._peers
            if len(ledger_peers) == 0:
                _logger.error("No peers defined")

        success = False

        for ledger_peer in ledger_peers:
            if success:
                break
            try:
                await self.gateway.client.init_with_discovery(discovery.requestor,
                                                              ledger_peer,
                                                              self.channel)
                self.channel = self.gateway.client.get_channel(self.channel)
                success = True
            except Exception:
                _logger.warning('Unable to initialize channel. Attempted to contact %s Peers. Last error was %s',
                                ledger_peer,
                                Exception)

    async def _initialize(self, discover=None):
        if self.initialized:
            return
        await self.__init_internal_channel(discover)
        self.initialized = True
