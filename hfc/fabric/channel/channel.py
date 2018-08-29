# Copyright 281165273@qq.com. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

import io
import logging
import os
import random
import sys
import tarfile

import rx

from hfc.fabric.transaction.tx_proposal_request import \
    create_tx_prop_req, CC_INSTALL, CC_TYPE_GOLANG, \
    CC_INSTANTIATE, CC_UPGRADE, CC_INVOKE, CC_QUERY
from hfc.protos.common import common_pb2
from hfc.protos.orderer import ab_pb2
from hfc.protos.peer import chaincode_pb2, proposal_pb2
from hfc.protos.utils import create_cc_spec, create_seek_info, \
    create_seek_payload, create_envelope
from hfc.util import utils
from hfc.util.utils import proto_str, current_timestamp, proto_b, \
    build_header, build_channel_header, build_cc_proposal, \
    send_transaction_proposal

if sys.version_info < (3, 0):
    from Queue import Queue
else:
    from queue import Queue


SYSTEM_CHANNEL_NAME = "testchainid"

_logger = logging.getLogger(__name__)


class Channel(object):
    """The class represents of the channel.
    This is a client-side-only call. To create a new channel in the fabric
    call client._create_channel().
    """

    def __init__(self, name, client, is_sys_chan=False):
        """Construct channel instance

        Args:
            is_sys_chan (bool): if system channel
            client (object): fabric client instance
            name (str): channel name
        """
        self._client = client
        self._orderers = {}
        self._peers = {}
        self._initialized = False
        self._shutdown = False
        self._is_sys_chan = is_sys_chan
        self._is_dev_mode = False

        if self._is_sys_chan:
            self._name = SYSTEM_CHANNEL_NAME
            self._initialized = True
        else:
            if not name:
                raise ValueError(
                    "Channel name is invalid can not be null or empty.")
            self._name = name

    def add_orderer(self, orderer):
        """Add orderer endpoint to a channel object.

        A channel instance may choose to use a single orderer node, which
        will broadcast requests to the rest of the orderer network. Or if
        the application does not trust the orderer nodes, it can choose to
        use more than one by adding them to the channel instance. And all
        APIs concerning the orderer will broadcast to all _orderers
        simultaneously.

        Args:
             orderer: an instance of the Orderer class

        """
        self._orderers[orderer.endpoint] = orderer

    def remove_orderer(self, orderer):
        """Remove orderer endpoint from a channel object.

        Args:
            orderer: an instance of the Orderer class

        """
        if orderer.endpoint in self._orderers:
            self._orderers.pop(orderer.endpoint, None)

    def add_peer(self, peer):
        """Add peer endpoint to a chain object.

        Args:
             peer: an instance of the Peer class
        """
        self._peers[peer.endpoint] = peer

    def remove_peer(self, peer):
        """Remove peer endpoint from a channel object.

        Args:
            peer: an instance of the Peer class
        """
        if peer.endpoint in self._peers:
            self._peers.pop(peer.endpoint, None)

    @property
    def orderers(self):
        """Get _orderers of a channel.

        Returns: The orderer list on the channel

        """
        return self._orderers

    @property
    def peers(self):
        """Get peers of a channel.

        Returns: The peer list on the chain
        """
        return self._peers

    @property
    def is_dev_mode(self):
        """Get is_dev_mode

        Returns: is_dev_mode

        """
        return self._is_dev_mode

    @is_dev_mode.setter
    def is_dev_mode(self, mode):
        self._is_dev_mode = mode

    def _get_latest_block(self, tx_context, orderer):
        """ Get latest block from orderer.

        Args:
            tx_context (object): a tx_context instance
            orderer (object): a orderer instance
        """
        seek_info = ab_pb2.SeekInfo()
        seek_info.start.newest = ab_pb2.SeekNewest()
        seek_info.stop.newest = ab_pb2.SeekNewest()
        seek_info.behavior = \
            ab_pb2.SeekInfo.SeekBehavior.Value('BLOCK_UNTIL_READY')

        seek_info_header = self._build_channel_header(
            common_pb2.HeaderType.Value('DELIVER_SEEK_INFO'),
            tx_context.tx_id, self._name, current_timestamp(),
            tx_context.epoch)

        signature_header = common_pb2.SignatureHeader()
        signature_header.creator = tx_context.identity
        signature_header.nonce = tx_context.nonce

        seek_payload = common_pb2.Payload()
        seek_payload.header.signature_header = \
            signature_header.SerializeToString()
        seek_payload.header.channel_header = \
            seek_info_header.SerializeToString()
        seek_payload.data = seek_info.SerializeToString()

        envelope = common_pb2.Envelope()
        envelope.signature = tx_context.sign(seek_payload.SerializeToString())
        envelope.payload = seek_payload.SerializeToString()

    def _get_random_orderer(self):
        if sys.version_info < (3, 0):
            return random.choice(self._orderers.values())
        else:
            return random.choice(list(self._orderers.values()))

    @property
    def name(self):
        """Get channel name.

        Returns: channel name

        """
        return self._name

    def state_store(self):
        """Get the key val store instance of the instantiating client.
        Get the KeyValueStore implementation (if any)
        that is currently associated with this channel
        Returns: the current KeyValueStore associated with this
        channel / client.

        """
        return self._client.state_store

    def _validate_state(self):
        """Validate channel state.

        Raises:
            ValueError

        """
        if self._shutdown:
            raise ValueError(
                "Channel {} has been shutdown.".format(self._name))

        if not self._initialized:
            raise ValueError(
                "Channel {} has not been initialized.".format(self._name))

    @property
    def is_sys_chan(self):
        """Get if system channel"""
        return self._is_sys_chan

    def _validate_peer(self, peer):
        """Validate peer

        Args:
            peer: peer

        Raises:
            ValueError

        """
        if not peer:
            raise ValueError("Peer value is null.")

        if self._is_sys_chan:
            return

        if peer not in self._peers.values():
            raise ValueError(
                "Channel %s does not have peer %s".format(self._name,
                                                          peer.endpoint))

        if self not in peer.channels:
            raise ValueError(
                "Peer %s not joined this channel %s".format(peer.endpoint,
                                                            self._name)
            )

    def _validate_peers(self, peers):
        """Validate peer set

        Args:
            peers: peers

        Raises:
            ValueError

        """
        if not peers:
            raise ValueError("Collection of peers is null.")

        if len(peers) == 0:
            raise ValueError("Collection of peers is empty.")

        for peer in peers:
            self._validate_peer(peer)

    def send_install_proposal(self, tx_context, peers=None, scheduler=None):
        """ Send install chaincode proposal

        Args:
            schedule: Rx schedule
            install_proposal_req: install proposal request
            targets: a set of peer to send

        Returns: a set of proposal response

        """
        if peers is None:
            targets = self._peers.values()
        else:
            targets = peers
        # self._validate_state() # TODO: enable this later
        # self._validate_peers(targets)  # TODO: enable this later

        if not tx_context:
            raise ValueError("InstallProposalRequest is null.")

        cc_deployment_spec = chaincode_pb2.ChaincodeDeploymentSpec()
        cc_deployment_spec.chaincode_spec.type = \
            chaincode_pb2.ChaincodeSpec.Type.Value(
                proto_str(tx_context.tx_prop_req.cc_type))
        cc_deployment_spec.chaincode_spec.chaincode_id.name = \
            proto_str(tx_context.tx_prop_req.cc_name)
        cc_deployment_spec.chaincode_spec.chaincode_id.path = \
            proto_str(tx_context.tx_prop_req.cc_path)
        cc_deployment_spec.chaincode_spec.chaincode_id.version = \
            proto_str(tx_context.tx_prop_req.cc_version)
        if not self._is_dev_mode:
            if not tx_context.tx_prop_req.packaged_cc:
                cc_deployment_spec.code_package = \
                    self._package_chaincode(
                        tx_context.tx_prop_req.cc_path,
                        tx_context.tx_prop_req.cc_type)
            else:
                cc_deployment_spec.code_package = \
                    tx_context.tx_prop_req.packaged_cc

        cc_deployment_spec.effective_date.seconds = \
            tx_context.tx_prop_req.effective_date.seconds
        cc_deployment_spec.effective_date.nanos = \
            tx_context.tx_prop_req.effective_date.nanos

        channel_header_extension = proposal_pb2.ChaincodeHeaderExtension()
        channel_header_extension.chaincode_id.name = \
            proto_str("lscc")
        channel_header = utils.build_channel_header(
            common_pb2.ENDORSER_TRANSACTION,
            tx_context.tx_id,
            '',
            utils.current_timestamp(),
            tx_context.epoch,
            channel_header_extension.SerializeToString()
        )

        header = utils.build_header(tx_context.identity,
                                    channel_header,
                                    tx_context.nonce)

        cci_spec = chaincode_pb2.ChaincodeInvocationSpec()
        cci_spec.chaincode_spec.type = \
            chaincode_pb2.ChaincodeSpec.Type.Value(CC_TYPE_GOLANG)
        cci_spec.chaincode_spec.chaincode_id.name = proto_str("lscc")
        cci_spec.chaincode_spec.input.args.extend(
            [proto_b(CC_INSTALL), cc_deployment_spec.SerializeToString()])
        proposal = utils.build_cc_proposal(
            cci_spec, header,
            tx_context.tx_prop_req.transient_map)
        signed_proposal = utils.sign_proposal(tx_context, proposal)

        send_executions = [peer.send_proposal(signed_proposal, scheduler)
                           for peer in targets]

        return rx.Observable.merge(send_executions).to_iterable() \
            .map(lambda responses: (responses, proposal, header))

    def _build_channel_header(type, tx_id, channel_id,
                              timestamp, epoch=0, extension=None):
        """Build channel.

        Args:
            extension: extension
            timestamp: timestamp
            channel_id: channel id
            tx_id: transaction id
            type: type
            epoch: epoch

        Returns: common_proto.Header instance

        """
        channel_header = common_pb2.ChannelHeader()
        channel_header.type = type
        channel_header.version = 1
        channel_header.channel_id = proto_str(channel_id)
        channel_header.tx_id = proto_str(tx_id)
        channel_header.epoch = epoch
        channel_header.timestamp = timestamp
        if extension:
            channel_header.extension = extension

        return channel_header

    def initialize(self):
        """Initialize a new channel

        start the channel and connect the event hubs.
        :return: True if the channel initialization process was successful,
            False otherwise.

        """
        return True

    def is_readonly(self):
        """Check the channel if read-only

        Get the channel status to see if the underlying channel has been
        terminated, making it a read-only channel, where information
        (transactions and state_store) can be queried but no new transactions
        can be submitted.

        Returns: True if the channel is read-only, False otherwise.

        """
        pass

    def _package_chaincode(self, cc_path, cc_type):
        """ Package all chaincode env into a tar.gz file

        Args:
            cc_path: path to the chaincode

        Returns: The chaincode pkg path or None

        """
        _logger.debug('Packaging chaincode path={}, chaincode type={}'.format(
            cc_path, cc_type))

        if cc_type == CC_TYPE_GOLANG:
            go_path = os.environ['GOPATH']
            if not cc_path:
                raise ValueError("Missing chaincode path parameter "
                                 "in install proposal request")

            if not go_path:
                raise ValueError("No GOPATH env variable is found")

            proj_path = go_path + '/src/' + cc_path
            _logger.debug('Project path={}'.format(proj_path))

            with io.BytesIO() as temp:
                with tarfile.open(fileobj=temp, mode='w|gz') as code_writer:
                    for dir_path, _, file_names in os.walk(proj_path):
                        if not file_names:
                            raise ValueError("No chaincode file found!")
                        for filename in file_names:
                            file_path = os.path.join(dir_path, filename)
                            _logger.debug("The file path {}".format(file_path))
                            code_writer.add(
                                file_path,
                                arcname=os.path.relpath(file_path, go_path))
                temp.seek(0)
                code_content = temp.read()
            if code_content:
                return code_content
            else:
                raise ValueError('No chaincode found')

        else:
            raise ValueError('Currently only support install GOLANG chaincode')

    def join_channel(self, request):
        """
        To join the peer to a channel.

        Args:
            request: the request to join a channel
        Return:
            True in sucess or False in failure
        """
        _logger.debug('channel_join - start')

        for key in ['targets', 'block', 'tx_context']:
            if key not in request:
                err_msg = "Missing parameter {}".format(key)
                _logger.error('channel_join error: {}'.format(err_msg))
                raise ValueError(err_msg)

        chaincode_input = chaincode_pb2.ChaincodeInput()
        chaincode_input.args.extend([proto_b("JoinChain"), request['block']])
        chaincode_id = chaincode_pb2.ChaincodeID()
        chaincode_id.name = proto_str("cscc")

        cc_spec = create_cc_spec(chaincode_input, chaincode_id, 'GOLANG')
        cc_invoke_spec = chaincode_pb2.ChaincodeInvocationSpec()
        cc_invoke_spec.chaincode_spec.CopyFrom(cc_spec)

        tx_context = request['tx_context']
        extension = proposal_pb2.ChaincodeHeaderExtension()
        extension.chaincode_id.name = proto_str('cscc')
        channel_header = build_channel_header(
            common_pb2.HeaderType.Value('ENDORSER_TRANSACTION'),
            tx_context.tx_id,
            '',
            current_timestamp(),
            tx_context.epoch,
            extension=extension.SerializeToString())

        header = build_header(tx_context.identity,
                              channel_header,
                              tx_context.nonce)
        proposal = build_cc_proposal(cc_invoke_spec,
                                     header,
                                     request['transient_map'])

        try:
            responses = send_transaction_proposal(proposal,
                                                  tx_context,
                                                  request['targets'])
        except Exception as e:
            raise IOError("fail to send transanction proposal", e)

        q = Queue(1)
        result = True
        for r in responses:
            r.subscribe(on_next=lambda x: q.put(x),
                        on_error=lambda x: q.put(x))
            res = q.get(timeout=5)
            _logger.debug(res)
            proposal_res = res[0]
            result = result and (proposal_res.response.status == 200)
        if result:
            _logger.info("successfully join the peers")

        return result

    def send_instantiate_proposal(self, tx_context, peers):
        """Send instatiate chaincode proposal.

        Args:
            tx_context: transaction context
            peers: peers to send this proposal

        Return: True in success False in failure
        """
        if not peers:
            peers = self.peers.values()
        if not tx_context:
            raise Exception("The transaction context is null.")

        return self._send_cc_proposal(tx_context, CC_INSTANTIATE, peers)

    def send_upgrade_proposal(self, tx_context, peers):
        """ Upgrade the chaincode.

        Args:
            tx_context: transaction context
            peers: peers to send this proposal

        Return: True in success and False in failure

        Note: The policy must the one from instantiate
        """

        if not peers:
            peers = self.peers.values()
        if not tx_context:
            raise Exception("The transaction context is null.")

        return self._send_cc_proposal(tx_context, CC_UPGRADE, peers)

    def _send_cc_proposal(self, tx_context, command, peers):

        args = []
        request = tx_context.tx_prop_req

        args.append(proto_b(request.fcn))
        for arg in request.args:
            args.append(proto_b(arg))

        # construct the deployment spec
        cc_id = chaincode_pb2.ChaincodeID()
        cc_id.name = request.cc_name
        cc_id.version = request.cc_version

        cc_input = chaincode_pb2.ChaincodeInput()
        cc_input.args.extend(args)
        cc_spec = create_cc_spec(cc_input, cc_id, CC_TYPE_GOLANG)

        cc_dep_spec = chaincode_pb2.ChaincodeDeploymentSpec()
        cc_dep_spec.chaincode_spec.CopyFrom(cc_spec)
        cc_dep_spec.effective_date.seconds = \
            tx_context.tx_prop_req.effective_date.seconds
        cc_dep_spec.effective_date.nanos = \
            tx_context.tx_prop_req.effective_date.nanos

        # construct the invoke spec
        # TODO: if the policy not provided, new one should be built.
        if request.cc_endorsement_policy:
            policy = request.cc_endorsement_policy
        else:
            policy = ''

        invoke_input = chaincode_pb2.ChaincodeInput()
        invoke_input.args.extend(
            [proto_b(command),
             proto_b(self.name),
             cc_dep_spec.SerializeToString(),
             proto_b(policy),
             proto_b('escc'),
             proto_b('vscc')])

        invoke_cc_id = chaincode_pb2.ChaincodeID()
        invoke_cc_id.name = proto_str('lscc')

        cc_invoke_spec = chaincode_pb2.ChaincodeInvocationSpec()
        cc_invoke_spec.chaincode_spec.CopyFrom(create_cc_spec(invoke_input,
                                                              invoke_cc_id,
                                                              CC_TYPE_GOLANG)
                                               )

        extension = proposal_pb2.ChaincodeHeaderExtension()
        extension.chaincode_id.name = proto_str('lscc')
        channel_header = build_channel_header(
            common_pb2.ENDORSER_TRANSACTION,
            tx_context.tx_id,
            self.name,
            current_timestamp(),
            epoch=0,
            extension=extension.SerializeToString()
        )

        header = build_header(tx_context.identity,
                              channel_header,
                              tx_context.nonce)
        proposal = build_cc_proposal(
            cc_invoke_spec,
            header,
            request.transient_map)

        signed_proposal = utils.sign_proposal(tx_context, proposal)
        send_executions = [peer.send_proposal(signed_proposal)
                           for peer in peers]

        return rx.Observable.merge(send_executions).to_iterable() \
            .map(lambda responses: (responses, proposal, header))

    def send_tx_proposal(self, tx_context, peers):
        """
        Invoke the chaincode

        Send a transaction proposal to one or more endorser without
        creating a channel.

        Args:
        peers: the pees to send this proposal
                 if it is None the channel peers list will be used.
        channel_id(required): channel id
        client(required): client context

        Return: True in success or False in failure.

        """
        if not peers:
            peers = self.peers.values()

        return Channel._send_tx_proposal(self.name, tx_context, peers)

    @staticmethod
    def _send_tx_proposal(channel_id, tx_context, peers):

        request = tx_context.tx_prop_req

        args = []
        if request.fcn:
            args.append(proto_b(request.fcn))
        else:
            args.append(proto_b(CC_INVOKE))

        for arg in request.args:
            if isinstance(arg, bytes):
                args.append(arg)
            else:
                args.append(proto_b(arg))

        cc_id = chaincode_pb2.ChaincodeID()
        cc_id.name = request.cc_name
        if request.prop_type != CC_QUERY:
            cc_id.version = request.cc_version

        cc_input = chaincode_pb2.ChaincodeInput()
        cc_input.args.extend(args)

        cc_spec = chaincode_pb2.ChaincodeSpec()
        cc_spec.type = chaincode_pb2.ChaincodeSpec.Type.Value(CC_TYPE_GOLANG)
        cc_spec.chaincode_id.CopyFrom(cc_id)
        cc_spec.input.CopyFrom(cc_input)

        extension = proposal_pb2.ChaincodeHeaderExtension()
        extension.chaincode_id.name = request.cc_name
        cc_invoke_spec = chaincode_pb2.ChaincodeInvocationSpec()
        cc_invoke_spec.chaincode_spec.CopyFrom(cc_spec)
        channel_header = build_channel_header(
            common_pb2.ENDORSER_TRANSACTION,
            tx_context.tx_id,
            channel_id,
            current_timestamp(),
            tx_context.epoch,
            extension=extension.SerializeToString())

        header = build_header(tx_context.identity,
                              channel_header,
                              tx_context.nonce)
        proposal = build_cc_proposal(cc_invoke_spec, header,
                                     request.transient_map)
        signed_proposal = utils.sign_proposal(tx_context, proposal)
        send_executions = [peer.send_proposal(signed_proposal)
                           for peer in peers]

        return rx.Observable.merge(send_executions).to_iterable() \
            .map(lambda responses: (responses, proposal, header))

    def query_instantiated_chaincodes(self, tx_context, peers):
        """
        Args:
            tx_context: tx_context instance
            peers: peers in the channel
        Returns: chain code response
        """
        request = create_tx_prop_req(
            prop_type=CC_QUERY,
            fcn='getchaincodes',
            cc_name='lscc',
            cc_type=CC_TYPE_GOLANG,
            args=[])

        tx_context.tx_prop_req = request
        return self.send_tx_proposal(tx_context, peers)

    def query_transaction(self, tx_context, peers, tx_id):
        """Queries the ledger for Transaction by transaction ID.

        Args:
            tx_context: tx_context instance
            peers: peers in the channel
            tx_id: transaction ID (string)
        Returns: chain code response
        """
        request = create_tx_prop_req(
            prop_type=CC_QUERY,
            fcn='GetTransactionByID',
            cc_name='qscc',
            args=[self.name, tx_id],
            cc_type=CC_TYPE_GOLANG)

        tx_context.tx_prop_req = request
        return self.send_tx_proposal(tx_context, peers)

    def get_block_between(self, tx_context, orderer, start, end):
        """
        Args:
            tx_context: tx_context instance
            orderer: orderer instance
            start: id of block to start query for
            end: id of block to end query for

        Returns: block(s)
        """
        seek_info = create_seek_info(start, end)
        seek_info_header = build_channel_header(
            common_pb2.HeaderType.Value('DELIVER_SEEK_INFO'),
            tx_context.tx_id,
            self._name,
            current_timestamp(),
            tx_context.epoch)

        seek_header = build_header(
            tx_context.identity,
            seek_info_header,
            tx_context.nonce)

        seek_payload_bytes = create_seek_payload(seek_header, seek_info)
        sig = tx_context.sign(seek_payload_bytes)

        envelope = create_envelope(sig, seek_payload_bytes)
        q = Queue(1)
        response = orderer.delivery(envelope)
        response.subscribe(on_next=lambda x: q.put(x),
                           on_error=lambda x: q.put(x))

        res, _ = q.get(timeout=5)
        _logger.debug(res)

        if res.block is None or res.block == '':
            _logger.error("fail to get block start from %s to %s" %
                          (str(start), str(end)))
            return None

        _logger.info("get block successfully, start from %s to %s" %
                     (str(start), str(end)))

        return res.block

    def query_block(self, tx_context, peers, block_number):
        """Queries the ledger for Block by block number.

        Args:
            tx_context: tx_context instance
            peers: peers in the channel
            block_number: block to query for

        Returns:
            :class: `BlockDecoder`
        """
        request = create_tx_prop_req(
            prop_type=CC_QUERY,
            fcn='GetBlockByNumber',
            cc_name='qscc',
            args=[self.name, block_number],
            cc_type=CC_TYPE_GOLANG)

        tx_context.tx_prop_req = request
        return self.send_tx_proposal(tx_context, peers)

    def query_block_by_hash(self, tx_context, peers, block_hash):
        """
        Args:
            tx_context: tx_context instance
            peers: peers in the channel
            block_hash: block to query for

        Returns:
            :class: `ChaincodeQueryResponse`
        """
        request = create_tx_prop_req(
            prop_type=CC_QUERY,
            fcn='GetBlockByHash',
            cc_name='qscc',
            args=[self.name, block_hash],
            cc_type=CC_TYPE_GOLANG)

        tx_context.tx_prop_req = request
        return self.send_tx_proposal(tx_context, peers)

    def query_block_by_txid(self, tx_context, peers, tx_id):
        """
        Args:
            tx_context: tx_context instance
            peers: peers in the channel
            tx_id: transaction id

        Returns:
            :class: `ChaincodeQueryResponse`
        """
        request = create_tx_prop_req(
            prop_type=CC_QUERY,
            fcn='GetBlockByTxID',
            cc_name='qscc',
            args=[self.name, tx_id],
            cc_type=CC_TYPE_GOLANG)

        tx_context.tx_prop_req = request
        return self.send_tx_proposal(tx_context, peers)

    def query_info(self, tx_context, peers):
        """Query the information of channel

        Queries for various useful information on the state of the channel
        (height, known peers).

        Args:
            tx_context: tx_context instance
            peers: peers in the channel

        Returns:
            :class:`ChaincodeQueryResponse` channelinfo with height,
            currently the only useful information.
        """
        request = create_tx_prop_req(
            prop_type=CC_QUERY,
            fcn='GetChainInfo',
            cc_name='qscc',
            args=[self.name],
            cc_type=CC_TYPE_GOLANG)

        tx_context.tx_prop_req = request
        return self.send_tx_proposal(tx_context, peers)


def create_system_channel(client, name=SYSTEM_CHANNEL_NAME):
    """ Create system channel instance

    Args:
        client: client instance

    Returns: system channel instance

    """
    return Channel(name, client, True)


def create_app_channel(client, name="businesschannel"):
    """ Create application channel instance

    Args:
        client: client instance

    Returns: system channel instance

    """
    return Channel(name, client, False)
