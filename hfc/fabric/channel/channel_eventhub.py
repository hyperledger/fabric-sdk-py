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
from hfc.protos.orderer import ab_pb2
from hfc.protos.peer.transaction_pb2 import TxValidationCode
from hfc.protos.utils import create_seek_payload, \
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
    def __init__(self, ccid, pattern, er, tx_id):
        self.ccid = ccid
        self.pattern = pattern
        self.er = er
        self.tx_id = tx_id


class ChannelEventHub(object):
    """A class represents channel event hub."""

    def __init__(self, peer, channel_name, requestor):
        self._peer = peer
        self._requestor = requestor
        self._channel_name = channel_name

        self.stream = None
        self._start = None
        self._stop = None
        self._filtered = True
        self._reg_nums = []
        self._tx_ids = {}
        self._reg_ids = {}
        self._connected = False
        self._start_stop_action = False
        self._start_stop_connect = False
        self._last_seen = None

        self._ending_block_newest = False

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

    def _create_seek_info(self, start=None, stop=None):

        behavior = 'BLOCK_UNTIL_READY'

        # build start
        seek_start = ab_pb2.SeekPosition()
        if start is None or start == 'newest':
            seek_start.newest.CopyFrom(ab_pb2.SeekNewest())
        elif start == 'oldest':
            seek_start.oldest.CopyFrom(ab_pb2.SeekOldest())
        else:
            seek_specified_start = ab_pb2.SeekSpecified()
            seek_specified_start.number = start
            seek_start.specified.CopyFrom(seek_specified_start)

        # build stop
        seek_stop = ab_pb2.SeekPosition()
        if stop == 'newest':
            self._ending_block_newest = True
            seek_stop.newest.CopyFrom(ab_pb2.SeekNewest())
            behavior = 'FAIL_IF_NOT_READY'
        elif start == 'oldest':
            seek_stop.oldest.CopyFrom(ab_pb2.SeekOldest())
            behavior = 'FAIL_IF_NOT_READY'
        else:
            seek_specified_stop = ab_pb2.SeekSpecified()
            if stop is not None:
                seek_specified_stop.number = stop
                behavior = 'FAIL_IF_NOT_READY'
            else:
                seek_specified_stop.number = sys.maxsize
            seek_stop.specified.CopyFrom(seek_specified_stop)

        # seek info with all parts
        seek_info = ab_pb2.SeekInfo()
        seek_info.start.CopyFrom(seek_start)
        seek_info.stop.CopyFrom(seek_stop)

        # BLOCK_UNTIL_READY will mean hold the stream open and keep sending
        # as the blocks come in
        # FAIL_IF_NOT_READY will mean if the block is not there throw an error
        seek_info.behavior = ab_pb2.SeekInfo.SeekBehavior.Value(behavior)

        return seek_info

    def _get_stream(self):
        """ get the events of the channel.
        Return: the events in success or None in fail.
        """
        _logger.info("create peer delivery stream")

        seek_info = self._create_seek_info(self._start, self._stop)

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
        return self._peer.delivery(envelope, filtered=self._filtered)

    def check_start_stop_connect(self, start=None, stop=None):
        if start is not None or stop is not None:
            if self._start_stop_action:
                raise Exception('Not able to connect with start/stop'
                                ' block when a registered listener has'
                                ' those options.')

            if not ((isinstance(start, int)
                     or start in ('oldest', 'newest'))
                    or start is None):
                raise Exception(f'start value must be: last_seen, oldest,'
                                f' newest or an integer')

            if not ((isinstance(stop, int)
                     or stop == 'newest')
                    or stop is None):
                raise Exception(f'stop value must be: last_seen, newest,'
                                f' sys.maxsize or an integer')

            if isinstance(start, int) \
                    and isinstance(stop, int)\
                    and start > stop:
                raise Exception('start cannot be greater than stop')

            self._start = start
            self._stop = stop
            self._start_stop_connect = True

    def check_start_stop_listener(self, start=None, stop=None):

        if self._start_stop_action:
            raise Exception('This ChannelEventHub is not open to event'
                            ' listener registrations')

        if start is not None or stop is not None:
            if self.have_registrations():
                raise Exception('Only one event registration is allowed when'
                                ' start/stop block are used.')

            if self._start_stop_connect:
                raise Exception('The registration with a start/stop block'
                                ' must be done before calling connect()')

            if stop is not None:
                if not (isinstance(stop, int)
                        or stop == 'newest'):
                    raise Exception('stop must be an integer, newest or'
                                    ' sys.maxsize')

            if start is not None:
                if not isinstance(start, int):
                    raise Exception('start must be an integer')

            if isinstance(start, int) \
                    and isinstance(stop, int) \
                    and start > stop:
                raise Exception('start cannot be greater than stop')

            self._start = start
            self._stop = stop

        self._start_stop_action = True

    def _processBlockEvents(self, block):
        for reg_num in self._reg_nums:

            if reg_num.unregister:
                self.unregisterBlockEvent(reg_num)

            if reg_num.onEvent is not None:
                reg_num.onEvent(block)

            if reg_num.disconnect:
                self.disconnect()

    def registerBlockEvent(self, unregister=True,
                           start=None, stop=None,
                           disconnect=False, onEvent=None):

        self.check_start_stop_listener(start, stop)

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
    def registerTxEvent(self, tx_id, unregister=True,
                        start=None, stop=None,
                        disconnect=False, onEvent=None):

        self.check_start_stop_listener(start, stop)

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

    def _handle_filtered_chaincode(self, ft, block, cr):
        if 'transaction_actions' in ft:
            tx_actions = ft['transaction_actions']
            for chaincode_action in tx_actions['chaincode_actions']:
                chaincode_event = chaincode_action['chaincode_event']
                # need to remove the payload since with filtered blocks it
                # has an empty byte array value which is not the real value
                # we do not want the listener to think that is the value
                del chaincode_event['payload']
                self._callChaincodeListener(cr, chaincode_event, block)

    def handle_filtered_chaincode(self, block, cr):
        for ft in block['filtered_transactions']:

            if cr.tx_id is not None:
                if cr.tx_id == ft['txid']:
                    if ft['tx_validation_code'] != 'VALID':
                        raise Exception(ft['tx_validation_code'])
                    self._handle_filtered_chaincode(ft, block, cr)
            else:
                self._handle_filtered_chaincode(ft, block, cr)

    def _handle_full_chaincode(self, tx, block, cr):
        if 'actions' in tx:
            for t in tx['actions']:
                ppl_r_p = t['payload']['action']['proposal_response_payload']
                chaincode_event = ppl_r_p['extension']['events']
                self._callChaincodeListener(cr, chaincode_event, block)

    def _handle_endorser_transaction(self, index, tx, cr,
                                     channel_header, block):
        txStatusCodes = block['metadata']['metadata'][
            BlockMetadataIndex.Value('TRANSACTIONS_FILTER')]

        if cr.tx_id is not None:
            if cr.tx_id == channel_header['tx_id']:
                if txStatusCodes and txStatusCodes[index] != \
                        TxValidationCode.Value('VALID'):
                    exc = TxValidationCode.Name(txStatusCodes[index])
                    raise Exception(exc)
                self._handle_full_chaincode(tx, block, cr)
        else:
            self._handle_full_chaincode(tx, block, cr)

    def handle_full_chaincode(self, block, cr):
        if 'data' in block:
            for index, data in enumerate(block['data']['data']):
                payload = data['payload']
                channel_header = payload['header']['channel_header']

                # only  ENDORSER_TRANSACTION have chaincode  events
                if channel_header['type'] == 3:
                    tx = payload['data']
                    self._handle_endorser_transaction(index, tx, cr,
                                                      channel_header, block)

    def _processChaincodeEvents(self, block):
        for ccid in copy(self._reg_ids).keys():
            for cr in self._reg_ids[ccid]:
                if self._filtered:
                    self.handle_filtered_chaincode(block, cr)
                else:
                    self.handle_full_chaincode(block, cr)

    def registerChaincodeEvent(self, ccid, pattern, unregister=False,
                               tx_id=None,
                               start=None, stop=None,
                               disconnect=False, onEvent=None):

        self.check_start_stop_listener(start, stop)

        er = EventRegistration(onEvent, unregister=unregister,
                               disconnect=disconnect)
        cr = ChaincodeRegistration(ccid, pattern, er, tx_id)

        if ccid in self._reg_ids:
            self._reg_ids[ccid].append(cr)
        else:
            self._reg_ids[ccid] = [cr]
        return cr

    def have_registrations(self):
        return self._reg_nums != [] \
               or self._tx_ids != {} \
               or self._reg_ids != {}

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
            # TODO handle empty block (last one)
            if not self.have_registrations():
                return True

    def connect(self, filtered=True, start=None, stop=None):
        self._filtered = filtered

        self.check_start_stop_connect(start, stop)

        self.stream = self._get_stream()

        return self.handle_stream(self.stream)

    def disconnect(self):
        self.stream.cancel()
        self._start = None
        self._stop = None
        self._filtered = True
        self._peer = None
        self._requestor = None
        self._channel_name = None
        self._start_stop_action = False
        self._start_stop_connect = False

        self._ending_block_newest = False

        self.connected = False
