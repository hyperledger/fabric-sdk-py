# SPDX-License-Identifier: Apache-2.0

import asyncio
import itertools
import logging
from time import sleep

from grpc._channel import _MultiThreadedRendezvous

from hfc.protos.peer.chaincode_pb2 import ChaincodeData, CDSData
from hfc.fabric.block_decoder import decode_proposal_response_payload, decode_signature_policy_envelope
from hfc.fabric.transaction.tx_context import create_tx_context
from hfc.fabric.transaction.tx_proposal_request import create_tx_prop_req, TXProposalRequest
from hfc.util import utils
from hfc.util.consts import CC_INSTALL, CC_INSTANTIATE, CC_UPGRADE, CC_INVOKE, CC_QUERY, CC_TYPE_GOLANG, \
    DEFAULT_WAIT_FOR_EVENT_TIMEOUT, GRPC_BROKER_UNAVAILABLE_RETRY_DELAY, \
    SUCCESS_STATUS
from hfc.fabric.base_chaincode import BaseChaincode

_logger = logging.getLogger(__name__)


class ChaincodeExecutionError(Exception):
    pass


class ChaincodeOperation:
    def __init__(self, fcn, operation_type, send_proposal):
        self.fcn = fcn
        self.operation_type = operation_type
        self.send_proposal = send_proposal


class Chaincode(BaseChaincode):
    def __init__(self, client, cc_name):
        super().__init__(cc_name)
        self._client = client

        self.operation_mapping = {
            CC_INSTANTIATE: lambda fcn: ChaincodeOperation(fcn, CC_INSTANTIATE, self.send_instantiate_proposal),
            CC_UPGRADE: lambda fcn: ChaincodeOperation(fcn, CC_UPGRADE, self.send_upgrade_proposal)
        }

    def send_instantiate_proposal(self, tx_context, peers,
                                  channel):
        """Send instantiate proposal

        :param tx_context: transaction context
        :param peers: peers
        :param channel: channel instance
        :return: A set of proposal_response
        """
        return channel.send_instantiate_proposal(tx_context, peers)

    def send_upgrade_proposal(self, tx_context, peers,
                              channel):
        """Send upgrade proposal

        :param tx_context: transaction context
        :param peers: peers
        :param channel: channel instance
        :return: A set of proposal_response
        """
        return channel.send_upgrade_proposal(tx_context, peers)

    async def install(self, requestor, peers, cc_path,
                      cc_version, cc_type=CC_TYPE_GOLANG,
                      packaged_cc=None, transient_map=None):
        """
        Install chaincode to given peers by requestor role

        :param requestor: User role who issue the request
        :param peers: List of  peer name and/or Peer to install
        :param cc_path: chaincode path
        :param cc_version: chaincode version
        :param cc_type: language type of the chaincode
        :param packaged_cc: packaged chaincode
        :param transient_map: transient map
        :return: True or False
        """
        target_peers = self._client.get_target_peers(peers)

        tran_prop_req = create_tx_prop_req(CC_INSTALL, cc_path, cc_type,
                                           self._name, cc_version,
                                           packaged_cc=packaged_cc,
                                           transient_map=transient_map)
        tx_context = create_tx_context(requestor, requestor.cryptoSuite,
                                       tran_prop_req)

        responses, proposal, header = utils.send_install_proposal(tx_context,
                                                                  target_peers)
        res = await asyncio.gather(*responses)
        # install returns package ids
        return res

    async def instantiate(self, requestor, channel_name, peers,
                          cc_version,
                          cc_endorsement_policy=None,
                          args=None,
                          transient_map=None,
                          collections_config=None,
                          wait_for_event=False,
                          wait_for_event_timeout=DEFAULT_WAIT_FOR_EVENT_TIMEOUT,
                          cc_type=CC_TYPE_GOLANG):
        """
            Instantiate installed chaincode to particular peer in
            particular channel

        :param requestor: User role who issue the request
        :param channel_name: the name of the channel to send tx proposal
        :param peers: List of  peer name and/or Peer to install
        :param cc_version: chaincode version
        :param cc_endorsement_policy: chaincode endorsement policy
        :param args (list): arguments (keys and values) for initialization
        :param transient_map: transient map
        :param collections_config: collection configuration
        :param wait_for_event: Whether to wait for the event from each peer's
         deliver filtered service signifying that the 'invoke' transaction has
          been committed successfully
        :param wait_for_event_timeout: Time to wait for the event from each
         peer's deliver filtered service signifying that the 'invoke'
          transaction has been committed successfully (default 30s)
        :param cc_type: the language type of the chaincode
        :return: chaincode data payload
        """
        return await self._instantiate_or_upgrade(CC_INSTANTIATE, requestor, channel_name, peers,
                                                  cc_version,
                                                  cc_endorsement_policy=cc_endorsement_policy,
                                                  args=args,
                                                  transient_map=transient_map,
                                                  collections_config=collections_config,
                                                  wait_for_event=wait_for_event,
                                                  wait_for_event_timeout=wait_for_event_timeout,
                                                  cc_type=cc_type)

    async def upgrade(self, requestor, channel_name, peers,
                      cc_version,
                      cc_endorsement_policy=None,
                      fcn='init', args=None,
                      transient_map=None,
                      collections_config=None,
                      wait_for_event=False,
                      wait_for_event_timeout=DEFAULT_WAIT_FOR_EVENT_TIMEOUT,
                      cc_type=CC_TYPE_GOLANG):
        """
           Upgrade installed chaincode to particular peer in
           particular channel

       :param requestor: User role who issue the request
       :param channel_name: the name of the channel to send tx proposal
       :param peers: List of  peer name and/or Peer to install
       :param cc_version: chaincode version
       :param cc_endorsement_policy: chaincode endorsement policy
       :param fcn: chaincode function to send
       :param args: chaincode function arguments
       :param transient_map: transient map
       :param collections_config: collection configuration
       :param wait_for_event: Whether to wait for the event from each peer's
        deliver filtered service signifying that the 'invoke' transaction has
         been committed successfully
       :param wait_for_event_timeout: Time to wait for the event from each
        peer's deliver filtered service signifying that the 'invoke'
         transaction has been committed successfully (default 30s)
       :param cc_type: the language type of the chaincode
       :return: chaincode data payload
       """
        return await self._instantiate_or_upgrade(CC_UPGRADE, requestor, channel_name, peers,
                                                  cc_version,
                                                  cc_endorsement_policy=cc_endorsement_policy,
                                                  fcn=fcn,
                                                  args=args,
                                                  transient_map=transient_map,
                                                  collections_config=collections_config,
                                                  wait_for_event=wait_for_event,
                                                  wait_for_event_timeout=wait_for_event_timeout,
                                                  cc_type=cc_type)

    async def _instantiate_or_upgrade(self, operation_name, requestor, channel_name, peers, cc_version,
                                      cc_endorsement_policy=None,
                                      fcn='init', args=None,
                                      transient_map=None,
                                      collections_config=None,
                                      wait_for_event=False,
                                      wait_for_event_timeout=DEFAULT_WAIT_FOR_EVENT_TIMEOUT,
                                      cc_type=CC_TYPE_GOLANG):
        """
            Instantiate installed chaincode to particular peer in
            particular channel

        :param operation_name: CC_INSTANTIATE or CC_UPGRADE
        :param requestor: User role who issue the request
        :param channel_name: the name of the channel to send tx proposal
        :param peers: List of  peer name and/or Peer to install
        :param cc_version: chaincode version
        :param cc_endorsement_policy: chaincode endorsement policy
        :param fcn: chaincode function to send
        :param args (list): arguments (keys and values) for initialization
        :param transient_map: transient map
        :param collections_config: collection configuration
        :param wait_for_event: Whether to wait for the event from each peer's
         deliver filtered service signifying that the 'invoke' transaction has
          been committed successfully
        :param wait_for_event_timeout: Time to wait for the event from each
         peer's deliver filtered service signifying that the 'invoke'
          transaction has been committed successfully (default 30s)
        :param cc_type: the language type of the chaincode
        :return: chaincode data payload
        """
        target_peers = self._client.get_target_peers(peers)
        operation = self.operation_mapping[operation_name](fcn)

        tran_prop_req_dep = create_tx_prop_req(
            prop_type=operation.operation_type,
            cc_type=cc_type,
            cc_name=self._name,
            cc_version=cc_version,
            cc_endorsement_policy=cc_endorsement_policy,
            fcn=operation.fcn,
            args=args,
            transient_map=transient_map,
            collections_config=collections_config
        )

        tx_context_dep = create_tx_context(
            requestor,
            requestor.cryptoSuite,
            tran_prop_req_dep
        )

        channel = self._client.get_channel(channel_name)

        responses, proposal, header = operation.send_proposal(
            tx_context_dep, target_peers, channel)
        res = await asyncio.gather(*responses)
        # if proposal was not good, return
        if not all([x.response.status == SUCCESS_STATUS for x in res]):
            raise RuntimeError(res[0].response.message)

        tran_req = utils.build_tx_req((res, proposal, header))

        tx_context = create_tx_context(requestor,
                                       requestor.cryptoSuite,
                                       TXProposalRequest())
        responses = utils.send_transaction(self._client.orderers, tran_req, tx_context)

        # responses will be a stream
        async for v in responses:
            if not v.status == SUCCESS_STATUS:
                raise RuntimeError(v.message)

        res = decode_proposal_response_payload(res[0].payload)

        # wait for transaction id proposal available in ledger and block
        # commited
        if wait_for_event:
            await self.wait_for_event(tx_context_dep, target_peers, channel, requestor, None, wait_for_event_timeout)

        ccd = ChaincodeData()
        payload = res['extension']['response']['payload']
        ccd.ParseFromString(payload)

        cdsData = CDSData()
        cdsData.ParseFromString(ccd.data)

        policy = decode_signature_policy_envelope(
            ccd.policy.SerializeToString())
        instantiation_policy = decode_signature_policy_envelope(
            ccd.instantiation_policy.SerializeToString())
        chaincode = {
            'name': ccd.name,
            'version': ccd.version,
            'escc': ccd.escc,
            'vscc': ccd.vscc,
            'policy': policy,
            'data': {
                'hash': cdsData.hash,
                'metadatahash': cdsData.metadatahash,
            },
            'id': ccd.id,
            'instantiation_policy': instantiation_policy,
        }
        return chaincode

    async def query(self, requestor, channel_name, peers, args,
                    cc_type=CC_TYPE_GOLANG, fcn='query', transient_map=None):
        """
        Query chaincode

        :param requestor: User role who issue the request
        :param channel_name: the name of the channel to send tx proposal
        :param peers: List of  peer name and/or Peer to install
        :param args (list): arguments (keys and values) for initialization
        :param cc_type: chaincode type language
        :param fcn: chaincode function
        :param transient_map: transient map
        :return: requested value
        """
        target_peers = self._client.get_target_peers(peers)

        tran_prop_req = create_tx_prop_req(
            prop_type=CC_QUERY,
            cc_name=self._name,
            cc_type=cc_type,
            fcn=fcn,
            args=args,
            transient_map=transient_map
        )

        tx_context = create_tx_context(
            requestor,
            requestor.cryptoSuite,
            tran_prop_req
        )

        responses, proposal, header = self._client.get_channel(
            channel_name).send_tx_proposal(tx_context, target_peers)
        res = await asyncio.gather(*responses)
        tran_req = utils.build_tx_req((res, proposal, header))

        if not all([x.response.status == SUCCESS_STATUS for x in tran_req.responses]):
            raise ChaincodeExecutionError(res)

        return res[0].response.payload.decode('utf-8')

    async def invoke(self, requestor, channel_name, peers, args,
                     cc_type=CC_TYPE_GOLANG,
                     fcn='invoke', cc_pattern=None,
                     transient_map=None,
                     wait_for_event=False,
                     wait_for_event_timeout=DEFAULT_WAIT_FOR_EVENT_TIMEOUT,
                     grpc_broker_unavailable_retry=0,
                     grpc_broker_unavailable_retry_delay=GRPC_BROKER_UNAVAILABLE_RETRY_DELAY,  # ms
                     raise_broker_unavailable=True,
                     raise_on_error=False, is_init=False):
        """
        Invoke chaincode for ledger update

        :param requestor: User role who issue the request
        :param channel_name: the name of the channel to send tx proposal
        :param peers: List of  peer name and/or Peer to install
        :param args (list): arguments (keys and values) for initialization
        :param cc_type: chaincode type language
        :param fcn: chaincode function
        :param cc_pattern: chaincode event name regex
        :param transient_map: transient map
        :param wait_for_event: Whether to wait for the event from each peer's
         deliver filtered service signifying that the 'invoke' transaction has
          been committed successfully
        :param wait_for_event_timeout: Time to wait for the event from each
         peer's deliver filtered service signifying that the 'invoke'
          transaction has been committed successfully (default 30s)
        :param grpc_broker_unavailable_retry: Number of retry if a broker
         is unavailable (default 0)
        :param grpc_broker_unavailable_retry_delay : Delay in ms to retry
         (default 3000 ms)
        :param raise_broker_unavailable: Raise if any broker is unavailable,
         else always send the proposal regardless of unavailable brokers.
        :param raise_on_error: Raise if any of peers or orderers returned unsuccessful response .

        :return: invoke result
        """
        target_peers = self._client.get_target_peers(peers)

        tran_prop_req = create_tx_prop_req(
            prop_type=CC_INVOKE,
            cc_name=self._name,
            cc_type=cc_type,
            fcn=fcn,
            args=args,
            transient_map=transient_map,
            is_init=is_init
        )

        tx_context = create_tx_context(
            requestor,
            requestor.cryptoSuite,
            tran_prop_req
        )

        channel = self._client.get_channel(channel_name)

        # send proposal
        responses, proposal, header = channel.send_tx_proposal(tx_context, target_peers)

        # The proposal return does not contain the transient map
        # because we do not sent it in the real transaction later
        res = await asyncio.gather(*responses, return_exceptions=True)
        failed_res = list(map(lambda x: isinstance(x, _MultiThreadedRendezvous), res))

        # remove failed_res from res, orderer will take care of unmet policy (can be different between app,
        # you should costumize this method to your own needs)
        if any(failed_res):
            res = list(filter(lambda x: hasattr(x, 'response') and x.response.status == SUCCESS_STATUS, res))

            # should we retry on failed?
            if grpc_broker_unavailable_retry:
                _logger.debug('Retry on failed proposal responses')

                retry = 0

                # get failed peers
                failed_target_peers = list(itertools.compress(target_peers, failed_res))

                while retry < grpc_broker_unavailable_retry:
                    _logger.debug(f'Retrying getting proposal responses from peers:'
                                  f' {[x.name for x in failed_target_peers]}, retry: {retry}')

                    retry_responses, _, _ = channel.send_tx_proposal(tx_context, failed_target_peers)
                    retry_res = await asyncio.gather(*retry_responses, return_exceptions=True)

                    # get failed res
                    failed_res = list(map(lambda x: isinstance(x, _MultiThreadedRendezvous), retry_res))

                    # add successful responses to res and recompute failed_target_peers
                    res += list(
                        filter(lambda x: hasattr(x, 'response') and x.response.status == SUCCESS_STATUS, retry_res)
                    )
                    failed_target_peers = list(itertools.compress(failed_target_peers, failed_res))

                    if len(failed_target_peers) == 0:
                        break

                    retry += 1
                    # TODO should we use a backoff?
                    _logger.debug(f'Retry in {grpc_broker_unavailable_retry_delay}ms')
                    sleep(grpc_broker_unavailable_retry_delay / 1000)  # milliseconds

                if len(failed_target_peers) > 0:
                    if raise_broker_unavailable:
                        raise Exception(f'Could not reach peer grpc broker {[x.name for x in failed_target_peers]}'
                                        f' even after {grpc_broker_unavailable_retry} retries.')
                    else:
                        _logger.debug(f'Could not reach peer grpc broker {[x.name for x in failed_target_peers]}'
                                      f' even after {grpc_broker_unavailable_retry} retries.')
                else:
                    _logger.debug('Proposals retrying successful.')

        # if proposal was not good, return
        if any([x.response.status != SUCCESS_STATUS for x in res]):
            error_message = '; '.join({x.response.message for x in res if x.response.status != SUCCESS_STATUS})
            if raise_on_error:
                raise ChaincodeExecutionError(error_message)
            else:
                return error_message

        # send transaction to the orderer
        tran_req = utils.build_tx_req((res, proposal, header))
        tx_context_tx = create_tx_context(
            requestor,
            requestor.cryptoSuite,
            tran_req
        )

        # response is a stream
        response = utils.send_transaction(self._client.orderers, tran_req,
                                          tx_context_tx)

        async for v in response:
            if not v.status == SUCCESS_STATUS:
                if raise_on_error:
                    raise ChaincodeExecutionError(v.message)
                else:
                    return v.message
        # wait for transaction id proposal available in ledger and block
        # commited
        if wait_for_event:
            await self.wait_for_event(tx_context, target_peers, channel, requestor, cc_pattern, wait_for_event_timeout)

        res = decode_proposal_response_payload(res[0].payload)
        return res['extension']['response']['payload'].decode('utf-8')
