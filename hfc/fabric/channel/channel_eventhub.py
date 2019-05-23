# Copyright IBM Corp. 2017 All Rights Reserved.
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
import re
import sys
import logging
from copy import copy
from hashlib import sha256

from hfc.protos.common import common_pb2
from hfc.protos.common.common_pb2 import BlockMetadataIndex
from hfc.protos.peer.transaction_pb2 import TxValidationCode
from hfc.protos.utils import create_seek_info, create_seek_payload, \
    create_envelope
from hfc.util.utils import current_timestamp, \
    build_header, build_channel_header, pem_to_der
from hfc.fabric.transaction.tx_context import TXContext
from hfc.fabric.transaction.tx_proposal_request import TXProposalRequest
from hfc.fabric.block_decoder import BlockDecoder, FilteredBlockDecoder

_logger = logging.getLogger(__name__ + ".channel_eventhub")


class EventRegistration(object):
    def __init__(self, onEvent=None, unregister=True, disconnect=False):
        self.onEvent = onEvent
        self.unregister = unregister
        self.disconnect = disconnect


class ChaincodeRegistration(object):
    def __init__(self, ccid, pattern, er):
        self.ccid = ccid
        self.pattern = pattern
        self.er = er


class ChannelEventHub(object):
    """A class represents channel event hub."""

    def __init__(self, peer, channel_name, requestor):
        self._peer = peer
        self._requestor = requestor
        self._channel_name = channel_name

        self.stream = None
        self._filtered = True
        self._reg_nums = []
        self._tx_ids = {}
        self._reg_ids = {}
        self._connected = False
        self._last_seen = None

    @property
    def connected(self):
        """Get the connected

        Return: The connected
        """
        return self._connected

    @connected.setter
    def connected(self, connected):
        """Set the connected

        Args:
            connected: the connected
        """
        self._connected = connected

    def _get_stream(self, start=None, stop=None, filtered=True,
                    behavior='BLOCK_UNTIL_READY'):
        """ get the events of the channel.
        Return: the events in success or None in fail.
        """
        _logger.info("get events")

        seek_info = create_seek_info(start, stop, behavior)

        kwargs = {}
        if self._peer._client_cert_path:
            with open(self._peer._client_cert_path, 'rb') as f:
                b64der = pem_to_der(f.read())
                kwargs['tls_cert_hash'] = sha256(b64der).digest()

        tx_context = TXContext(self._requestor, self._requestor.cryptoSuite,
                               TXProposalRequest())

        seek_info_header = build_channel_header(
            common_pb2.HeaderType.Value('DELIVER_SEEK_INFO'),
            tx_context.tx_id,
            self._channel_name,
            current_timestamp(),
            tx_context.epoch,
            **kwargs
        )

        seek_header = build_header(
            tx_context.identity,
            seek_info_header,
            tx_context.nonce)

        seek_payload_bytes = create_seek_payload(seek_header, seek_info)
        sig = tx_context.sign(seek_payload_bytes)
        envelope = create_envelope(sig, seek_payload_bytes)

        # this is a stream response
        return self._peer.delivery(envelope, filtered=filtered)

    def _processBlockEvents(self, block):
        for reg_num in self._reg_nums:

            if reg_num.unregister:
                self.unregisterBlockEvent(reg_num)

            if reg_num.onEvent is not None:
                reg_num.onEvent(block)

            if reg_num.disconnect:
                self.disconnect()

    # TODO support startBlock, endBlock
    def registerBlockEvent(self, unregister=True,
                           disconnect=False, onEvent=None):
        reg_num = EventRegistration(onEvent,
                                    unregister=unregister,
                                    disconnect=disconnect)
        self._reg_nums.append(reg_num)
        return reg_num

    def unregisterBlockEvent(self, reg_num):
        self._reg_nums.remove(reg_num)

    def handle_filtered_tx(self, block, tx_id, er):
        for ft in block['filtered_transactions']:
            if tx_id == ft['txid']:
                if ft['tx_validation_code'] != 'VALID':
                    raise Exception(ft['tx_validation_code'])

                if er.unregister:
                    self.unregisterTxEvent(tx_id)
                if er.onEvent is not None:
                    er.onEvent(block)
                if er.disconnect:
                    self.disconnect()

    def handle_full_tx(self, block, tx_id, er):
        txStatusCodes = block['metadata']['metadata'][
            BlockMetadataIndex.Value('TRANSACTIONS_FILTER')]
        for index, data in enumerate(block['data']['data']):
            channel_header = data['payload']['header']['channel_header']
            if tx_id == channel_header['tx_id']:
                if txStatusCodes[index] != TxValidationCode.Value('VALID'):
                    raise Exception(
                        TxValidationCode.Name(txStatusCodes[index]))

                if er.unregister:
                    self.unregisterTxEvent(tx_id)
                if er.onEvent is not None:
                    er.onEvent(block)
                if er.disconnect:
                    self.disconnect()

    def _processTxEvents(self, block):
        for tx_id, er in copy(self._tx_ids).items():
            # filtered block case
            if self._filtered:
                self.handle_filtered_tx(block, tx_id, er)
            else:
                self.handle_full_tx(block, tx_id, er)

    # TODO support txid ALL
    # TODO support startBlock, endBlock
    def registerTxEvent(self, tx_id, unregister=True,
                        disconnect=False, onEvent=None):
        self._tx_ids[tx_id] = EventRegistration(onEvent,
                                                unregister=unregister,
                                                disconnect=disconnect)
        return tx_id

    def unregisterTxEvent(self, tx_id):
        del self._tx_ids[tx_id]

    def _callChaincodeListener(self, cr, block_events, block):
        if block_events['chaincode_id'] == cr.ccid and \
                re.match(cr.pattern, block_events['event_name']):

            if cr.er.unregister:
                self.unregisterChaincodeEvent(cr)

            if cr.er.onEvent is not None:
                cr.er.onEvent(block)

            if cr.er.disconnect:
                self.disconnect()

    def handle_filtered_chaincode(self, block, cr):
        for ft in block['filtered_transactions']:
            if 'transaction_actions' in ft:
                block_events = ft['transaction_actions']
                self._callChaincodeListener(cr, block_events, block)

    def handle_full_chaincode(self, block, cr):
        if 'data' in block:
            for env in block['data']['data']:
                payload = env['payload']
                channel_header = payload['header']['channel_header']

                # only  ENDORSER_TRANSACTION have chaincode  events
                if channel_header['type'] == 3:
                    tx = payload['data']

                    if 'actions' in tx:
                        for t in tx['actions']:
                            ppl_r_p = t['payload']['action'][
                                'proposal_response_payload']
                            block_events = ppl_r_p['extension']['events']
                            self._callChaincodeListener(cr, block_events,
                                                        block)

    def _processChaincodeEvents(self, block):
        for ccid in copy(self._reg_ids).keys():
            for cr in self._reg_ids[ccid]:
                if self._filtered:
                    self.handle_filtered_chaincode(block, cr)
                else:
                    self.handle_full_chaincode(block, cr)

    # TODO support startBlock, endBlock
    def registerChaincodeEvent(self, ccid, pattern, unregister=False,
                               disconnect=False, onEvent=None):
        er = EventRegistration(onEvent, unregister=unregister,
                               disconnect=disconnect)
        cr = ChaincodeRegistration(ccid, pattern, er)

        if ccid in self._reg_ids:
            self._reg_ids[ccid].append(cr)
        else:
            self._reg_ids[ccid] = [cr]
        return cr

    def unregisterChaincodeEvent(self, reg_id):
        self._reg_ids[reg_id.ccid].remove(reg_id)

        if not self._reg_ids[reg_id.ccid]:
            del self._reg_ids[reg_id.ccid]

    async def handle_stream(self, stream):
        async for event in stream:
            self.connected = True
            if self._filtered:
                block = FilteredBlockDecoder().decode(
                    event.filtered_block.SerializeToString())
                self._last_seen = block['number']
            else:
                block = BlockDecoder().decode(event.block.SerializeToString())
                self._last_seen = block['header']['number']

            self._processBlockEvents(block)
            self._processTxEvents(block)
            self._processChaincodeEvents(block)

            # if nothing to handle return true
            # TODO handle last_seen and empty block (last one)
            if self._reg_nums == []\
                    and self._tx_ids == {}\
                    and self._reg_ids == {}:
                return True

    def connect(self, filtered=True, start=None, stop=sys.maxsize,
                behavior='BLOCK_UNTIL_READY'):
        self._filtered = filtered
        self.stream = self._get_stream(start=start, stop=stop,
                                       filtered=self._filtered,
                                       behavior=behavior)

        return self.handle_stream(self.stream)

    def disconnect(self):
        self.stream.cancel()
        self._filtered = True
        self._peer = None
        self._requestor = None
        self._channel_name = None
        self.connected = False
