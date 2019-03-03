# Copyright arxanfintech.com 2016 All Rights Reserved.
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

import logging
import json
import sys
import os
import subprocess
import shutil
import time

from hfc.fabric.channel.channel import Channel
from hfc.fabric.orderer import Orderer
from hfc.fabric.peer import Peer
from hfc.fabric.organization import create_org
from hfc.fabric.transaction.tx_context import TXContext, create_tx_context
from hfc.fabric.transaction.tx_proposal_request import TXProposalRequest, \
    create_tx_prop_req, CC_INSTALL, CC_TYPE_GOLANG, CC_INSTANTIATE, \
    CC_INVOKE, CC_QUERY
from hfc.protos.common import common_pb2, configtx_pb2, ledger_pb2
from hfc.protos.peer import query_pb2
from hfc.protos.msp import identities_pb2
from hfc.protos.gossip import message_pb2
from hfc.fabric.block_decoder import BlockDecoder
from hfc.util import utils
from hfc.util.crypto.crypto import Ecies, ecies
from hfc.util.keyvaluestore import FileKeyValueStore

# inject global default config
from hfc.fabric.config.default import DEFAULT

assert DEFAULT
# consoleHandler = logging.StreamHandler()
_logger = logging.getLogger(__name__)
# _logger.setLevel(logging.DEBUG)
# _logger.addHandler(consoleHandler)


class Client(object):
    """
        Main interaction handler with end user.
        Client can maintain several channels.
    """

    def __init__(self, net_profile=None):
        """ Construct client"""
        self._crypto_suite = None
        self._tx_context = None
        self.kv_store_path = None  # TODO: fix t.his as private later
        self._state_store = None
        self._is_dev_mode = False
        self.network_info = dict()

        self._organizations = dict()
        self._users = dict()
        self._channels = dict()
        self._peers = dict()
        self._orderers = dict()
        self._CAs = dict()

        if net_profile:
            _logger.debug("Init client with profile={}".format(net_profile))
            self.init_with_net_profile(net_profile)

    def init_with_net_profile(self, profile_path='network.json'):
        """
        Load the connection profile from external file to network_info.

        Init the handlers for orgs, peers, orderers, ca nodes

        :param profile_path: The connection profile file path
        :return:
        """
        with open(profile_path, 'r') as profile:
            d = json.load(profile)
            self.network_info = d

        # read kv store path
        self.kv_store_path = self.get_net_info('client', 'credentialStore',
                                               'path')
        if self.kv_store_path:
            self._state_store = FileKeyValueStore(self.kv_store_path)
        else:
            _logger.warning('No kv store path exists in profile {}'.format(
                profile_path))

        # Init organizations
        orgs = self.get_net_info('organizations')
        for name in orgs:
            _logger.debug("create org with name={}".format(name))
            org = create_org(name, orgs[name], self.state_store)
            self._organizations[name] = org

        # Init CAs
        # TODO

        # Init orderer nodes
        orderers = self.get_net_info('orderers')
        _logger.debug("Import orderers = {}".format(orderers.keys()))
        for name in orderers:
            orderer = Orderer(name=name, endpoint=orderers[name]['url'])
            orderer.init_with_bundle(orderers[name])
            self.orderers[name] = orderer

        # Init peer nodes
        peers = self.get_net_info('peers')
        _logger.debug("Import peers = {}".format(peers.keys()))
        for name in peers:
            peer = Peer(name=name)
            peer.init_with_bundle(peers[name])
            self._peers[name] = peer

    def get_user(self, org_name, name):
        """
        Get a user instance.
        :param org_name: Name of org belongs to
        :param name: Name of the user
        :return: user instance or None
        """
        if org_name in self.organizations:
            org = self.organizations[org_name]
            return org.get_user(name)

        return None

    def get_orderer(self, name):
        """
        Get an orderer instance with the name.
        :param name:  Name of the orderer node.
        :return: The orderer instance or None.
        """
        if name in self.orderers:
            return self.orderers[name]
        else:
            _logger.warning("Cannot find orderer with name {}".format(name))
            return None

    def get_peer(self, name):
        """
        Get a peer instance with the name.
        :param name:  Name of the peer node.
        :return: The peer instance or None.
        """
        if name in self._peers:
            return self._peers[name]
        else:
            _logger.warning("Cannot find peer with name {}".format(name))
            return None

    def export_net_profile(self, export_file='network_exported.json'):
        """
        Export the current network profile into external file
        :param export_file: External file to save the result into
        :return:
        """
        with open(export_file, 'w') as f:
            json.dump(self.network_info, f, indent=4)

    def get_net_info(self, *key_path):
        """
        Get the info from self.network_info
        :param key_path: path of the key, e.g., a.b.c means info['a']['b']['c']
        :return: The value, or None
        """
        result = self.network_info
        if result:
            for k in key_path:
                try:
                    result = result[k]
                except KeyError:
                    _logger.warning('No key path {} exists in net info'.format(
                        key_path))
                    return None

        return result

    @property
    def organizations(self):
        """
        Get the organizations in the network.

        :return: organizations as dict
        """
        return self._organizations

    @property
    def orderers(self):
        """
        Get the orderers in the network.

        :return: orderers as dict
        """
        return self._orderers

    @property
    def peers(self):
        """
        Get the peers instance in the network.

        :return: peers as dict
        """
        return self._peers

    @property
    def CAs(self):
        """
        Get the CAs in the network.

        :return: CAs as dict
        """
        return self._CAs

    def new_channel(self, name):
        """Create a channel handler instance with given name.

        Args:
            name (str): The name of the channel.

        Returns:
            channel: The inited channel.

        """
        _logger.debug("New channel with name = {}".format(name))
        if name not in self._channels:
            self._channels[name] = Channel(name, self)
        return self._channels[name]

    def get_channel(self, name):
        """Get a channel handler instance.

        Args:
            name (str): The name of the channel.

        Returns:
            Get the channel instance with the name or None

        """
        return self._channels.get(name, None)

    def channel_create(self, orderer_name, channel_name, requestor,
                       config_yaml, channel_profile):
        """
        Create a channel, send request to orderer, and check the response

        :param orderer_name: Name of orderer to send request to
        :param channel_name: Name of channel to create
        :param requestor: Name of creator
        :param config_yaml: Directory path of config yaml to be set for FABRIC_
        CFG_PATH variable
        :param channel_profile: Name of the channel profile defined inside
        config yaml file
        :return: True (creation succeeds) or False (creation failed)
        """
        if self.get_channel(channel_name):
            _logger.warning("channel {} already existed when creating".format(
                channel_name))
            return False

        orderer = self.get_orderer(orderer_name)
        if not orderer:
            _logger.error("No orderer_name instance found with name {}".format(
                orderer_name))
            return False

        tx = self.generate_channel_tx(channel_name, config_yaml,
                                      channel_profile)
        if tx is None:
            _logger.error('Configtx is empty')
            return False
        _logger.info("Configtx file successfully created in current directory")

        with open(tx, 'rb') as f:
            envelope = f.read()
            config = utils.extract_channel_config(envelope)

        # convert envelope to config
        self.tx_context = TXContext(requestor, Ecies(), {})
        tx_id = self.tx_context.tx_id
        nonce = self.tx_context.nonce
        signatures = []
        org1_admin_signature = self.sign_channel_config(config)
        # append org1_admin_signature to signatures
        signatures.append(org1_admin_signature)

        request = {
            'tx_id': tx_id,
            'nonce': nonce,
            'signatures': signatures,
            'config': config,
            'orderer': orderer,
            'channel_name': channel_name
        }
        response = self._create_channel(request)

        if response[0].status == 200:
            self.new_channel(channel_name)
            return True
        else:
            return False

    def channel_join(self, requestor, channel_name, peer_names, orderer_name):
        """
        Join a channel.
        Get genesis block from orderer, then send request to peer

        :param requestor: User to send the request
        :param channel_name: Name of channel to create
        :param peer_names: List of peers to join to the channel
        :param orderer_name: Name of orderer to get genesis block from

        :return: True (creation succeeds) or False (creation failed)
        """
        channel = self.get_channel(channel_name)
        if not channel:
            _logger.warning("channel {} not existed when join".format(
                channel_name))
            return False

        orderer = self.get_orderer(orderer_name)
        if not orderer:
            _logger.warning("orderer {} not existed when channel join".format(
                orderer_name))
            return False

        tx_prop_req = TXProposalRequest()

        # get the genesis block
        orderer_admin = self.get_user(orderer_name, 'Admin')
        tx_context = TXContext(orderer_admin, ecies(), tx_prop_req)
        genesis_block = orderer.get_genesis_block(
            tx_context,
            channel.name).SerializeToString()

        # create the peer
        tx_context = TXContext(requestor, ecies(), tx_prop_req)

        peers = []
        for peer_name in peer_names:
            peer = self.get_peer(peer_name)
            peers.append(peer)

        """
        # connect the peer
        eh = EventHub()
        event = peer_config['grpc_event_endpoint']

        tx_id = client.tx_context.tx_id
        eh.set_peer_addr(event)
        eh.connect()
        eh.register_block_event(block_event_callback)
        all_ehs.append(eh)
        """

        request = {
            "targets": peers,
            "block": genesis_block,
            "tx_context": tx_context,
            "transient_map": {}
        }

        return channel.join_channel(request)

    def chaincode_install(self, requestor, peer_names, cc_path, cc_name,
                          cc_version):
        """
        Install chaincode to given peers by requestor role

        :param requestor: User role who issue the request
        :param peer_names: Names of the peers to install
        :param cc_path: chaincode path
        :param cc_name: chaincode name
        :param cc_version: chaincode version
        :return: True or False
        """
        peers = []
        for peer_name in peer_names:
            peer = self.get_peer(peer_name)
            peers.append(peer)

        tran_prop_req = create_tx_prop_req(CC_INSTALL, cc_path, CC_TYPE_GOLANG,
                                           cc_name, cc_version)
        tx_context = create_tx_context(requestor, ecies(), tran_prop_req)

        responses = self.send_install_proposal(tx_context, peers)
        return responses

    def _create_channel(self, request):
        """Calls the orderer to start building the new channel.

        Args:
            request (dct): The create channel request.

        Returns:
            OrdererResponse or an error.

        """
        have_envelope = False
        _logger.debug(request)
        if request and 'envelope' in request:
            _logger.debug('_create_channel - have envelope')
            have_envelope = True

        return self._create_or_update_channel_request(request, have_envelope)

    def update_channel(self, request):
        """Calls the orderer to update an existing channel.

        Args:
            request (dct): The update channel request.

        Returns:
            OrdererResponse or an error.

        """
        have_envelope = False
        if request and 'envelope' in request:
            _logger.debug('_create_channel - have envelope')
            have_envelope = True

        return self._create_or_update_channel_request(request, have_envelope)

    def _validate_request(self, request):
        """
        Validate a request
        :param request: request to validate
        :return:
        """
        # TODO: implement this to validate the request
        pass

    def _create_or_update_channel_request(self, request, have_envelope):
        """Inits the create of update channel process.

        Args:
            request (dct): A create_update channel request.
            have_envelope (bool): Signals if the requests contains a finished
            protobuf envelope.

        Returns:
            BroadcastResponse which includes status and info

        """
        _logger.debug('_create_or_update_channel - start')

        error_msg = None

        if 'config' not in request and not have_envelope:
            error_msg = 'Missing config request parameter containing ' \
                        'the configuration of the channel'

        if 'signatures' not in request and not have_envelope:
            error_msg = 'Missing signatures request parameter for the ' \
                        'new channel'
        elif 'signatures' in request and \
                not isinstance(request['signatures'], list) \
                and not have_envelope:
            error_msg = 'Signatures request parameter must be an array ' \
                        'of signatures'

        if 'tx_id' not in request and not have_envelope:
            error_msg = 'Missing tx_id request parameter'

        if 'nonce' not in request and not have_envelope:
            error_msg = 'Missing nonce request parameter'

        if 'orderer' not in request:
            error_msg = 'Missing orderer request parameter'

        if 'channel_name' not in request:
            error_msg = 'Missing channel_name request parameter'

        if error_msg:
            _logger.error('_create_or_update_channel error: {}'
                          .format(error_msg))
            raise ValueError(error_msg)

        if have_envelope:
            _logger.debug('_create_or_update_channel - have envelope')
            envelope = common_pb2.Envelope()
            envelope.ParseFromString(request['envelope'])

            signature = envelope.signature
            payload = envelope.payload

        else:
            _logger.debug('_create_or_update_channel - have config_update')
            proto_config_update_envelope = configtx_pb2.ConfigUpdateEnvelope()

            proto_config_update_envelope.config_update = request['config']

            # convert signatures to protobuf signature
            signatures = request['signatures']
            proto_signatures = utils.string_to_signature(signatures)

            proto_config_update_envelope.signatures.extend(proto_signatures)

            proto_channel_header = utils.build_channel_header(
                common_pb2.HeaderType.Value('CONFIG_UPDATE'),
                request['tx_id'],
                request['channel_name'],
                utils.current_timestamp()
            )

            proto_header = utils.build_header(self.tx_context.identity,
                                              proto_channel_header,
                                              request['nonce'])

            proto_payload = common_pb2.Payload()

            proto_payload.header.CopyFrom(proto_header)
            proto_payload.data = proto_config_update_envelope \
                .SerializeToString()
            payload_bytes = proto_payload.SerializeToString()

            signature_bytes = self.tx_context.sign(payload_bytes)

            signature = signature_bytes
            payload = payload_bytes

        # assemble the final envelope
        out_envelope = common_pb2.Envelope()
        out_envelope.signature = signature
        out_envelope.payload = payload

        orderer = request['orderer']

        return orderer.broadcast(out_envelope)

    def sign_channel_config(self, config, to_string=True):
        """This method uses the client instance's current signing identity to
         sign over the configuration bytes passed in.

        Args:
            config: The configuration update in bytes form.
            to_string: Whether to convert the result to string

        Returns:
            config_signature (common_pb2.ConfigSignature):
            The signature of the current user of the config bytes.

        """

        sign_channel_context = self.tx_context

        proto_signature_header = common_pb2.SignatureHeader()
        proto_signature_header.creator = sign_channel_context.identity
        proto_signature_header.nonce = sign_channel_context.nonce

        proto_signature_header_bytes = \
            proto_signature_header.SerializeToString()

        signing_bytes = proto_signature_header_bytes + config
        signature_bytes = sign_channel_context.sign(signing_bytes)

        proto_config_signature = configtx_pb2.ConfigSignature()
        proto_config_signature.signature_header = proto_signature_header_bytes
        proto_config_signature.signature = signature_bytes

        if to_string:
            return proto_config_signature.SerializeToString()
        else:
            return proto_config_signature

    @property
    def crypto_suite(self):
        """Get the crypto suite.

        Returns: The crypto_suite instance or None

        """
        return self._crypto_suite

    @crypto_suite.setter
    def crypto_suite(self, crypto_suite):
        """Set the crypto suite to given one.

        Args:
            crypto_suite: The crypto_suite to use.

        Returns: None

        """
        self._crypto_suite = crypto_suite

    @property
    def tx_context(self):
        """ Get the current tx_context for the client.

        Returns: The tx_context object or None

        """
        return self._tx_context

    @tx_context.setter
    def tx_context(self, tx_context):
        """Set the tx_context to the given one.

        Args:
            tx_context: The tx_context to be used.

        Return: None

        """
        self._tx_context = tx_context

    @property
    def state_store(self):
        """ Get the KeyValue store.

        Return the keyValue store instance or None

        """
        return self._state_store

    @state_store.setter
    def state_store(self, state_store):
        """ Set the KeyValue store.

        Args:
            state_store: the KeyValue store to use.

        No return Value

        """
        self._state_store = state_store

    def send_install_proposal(self, tx_context, peers):
        """ Send install proposal
        Args:
            tx_context: transaction context
            peers: peers
            scheduler: rx scheduler
        Returns: A set of proposal_response
        """
        return utils.send_install_proposal(tx_context, peers)

    def send_instantiate_proposal(self, tx_context, peers,
                                  channel_name):
        """ Send instantiate proposal

        Args:
            tx_context: transaction context
            peers: peers
            channel_name: the name of channel

        Returns: A set of proposal_response

        """
        app_channel = self.get_channel(channel_name)
        _logger.debug("context {}".format(tx_context))
        return app_channel.send_instantiate_proposal(tx_context, peers)

    def generate_channel_tx(self, channel_name, cfg_path, channel_profile):
        """ Creates channel configuration transaction

        Args:
            :param channel_name: Name of the channel
            :param cfg_path: Directory path of config yaml to be set for
            FABRIC_CFG_PATH variable
            :param channel_profile: Name of the channel profile defined inside
            config yaml file
        Returns: path to tx file if success else None

        """
        # check if configtxgen is in PATH

        if shutil.which('configtxgen') is None:
            _logger.error("configtxgen not in PATH.")
            return None

        # Generate channel.tx with configtxgen
        tx_path = "/tmp/channel.tx"
        cfg_path = cfg_path if os.path.isabs(cfg_path) else \
            os.getcwd() + "/" + cfg_path
        _logger.info("FABRIC_CFG_PATH set to {}".format(cfg_path))
        new_env = dict(os.environ, FABRIC_CFG_PATH=cfg_path)
        output = subprocess.Popen(['configtxgen',
                                   '-configPath', cfg_path,
                                   '-profile', channel_profile,
                                   '-channelID', channel_name,
                                   '-outputCreateChannelTx', tx_path],
                                  stdout=open(os.devnull, "w"),
                                  stderr=subprocess.PIPE, env=new_env)
        err = output.communicate()[1]
        if output.returncode:
            _logger.error('Failed to generate transaction file', err)
            return None
        return tx_path

    def chaincode_instantiate(self, requestor, channel_name, peer_names,
                              args, cc_name, cc_version, timeout=10):
        """
            Instantiate installed chaincode to particular peer in
            particular channel

        :param requestor: User role who issue the request
        :param channel_name: the name of the channel to send tx proposal
        :param peer_names: Names of the peers to install
        :param args (list): arguments (keys and values) for initialization
        :param cc_name: chaincode name
        :param cc_version: chaincode version
        :param timeout: Timeout to wait
        :return: True or False
        """
        peers = []
        for peer_name in peer_names:
            peer = self.get_peer(peer_name)
            peers.append(peer)

        tran_prop_req_dep = create_tx_prop_req(
            prop_type=CC_INSTANTIATE,
            cc_type=CC_TYPE_GOLANG,
            cc_name=cc_name,
            cc_version=cc_version,
            fcn='init',
            args=args
        )

        tx_context_dep = create_tx_context(
            requestor,
            ecies(),
            tran_prop_req_dep
        )

        res = self.send_instantiate_proposal(
            tx_context_dep, peers, channel_name)

        tx_context = create_tx_context(requestor,
                                       ecies(),
                                       TXProposalRequest())
        tran_req = utils.build_tx_req(res)
        responses = utils.send_transaction(self.orderers, tran_req, tx_context)

        if not (tran_req.responses[0].response.status == 200
                and responses[0].status == 200):
            return False

        # Wait until chaincode is really instantiated
        # Note : we will remove this part when we have channel event hub
        starttime = int(time.time())
        while int(time.time()) - starttime < timeout:
            try:
                response = self.query_transaction(
                    requestor=requestor,
                    channel_name=channel_name,
                    peer_names=peer_names,
                    tx_id=tx_context_dep.tx_id,
                    decode=False
                )

                if response.response.status == 200:
                    return True

                time.sleep(1)
            except Exception:
                time.sleep(1)

        return False

    def chaincode_invoke(self, requestor, channel_name, peer_names, args,
                         cc_name, cc_version, cc_type=CC_TYPE_GOLANG,
                         fcn='invoke', timeout=10):
        """
        Invoke chaincode for ledger update

        :param requestor: User role who issue the request
        :param channel_name: the name of the channel to send tx proposal
        :param peer_names: Names of the peers to install
        :param args (list): arguments (keys and values) for initialization
        :param cc_name: chaincode name
        :param cc_version: chaincode version
        :param cc_type: chaincode type language
        :param fcn: chaincode function
        :param timeout: Timeout to wait
        :return: True or False
        """
        peers = []
        for peer_name in peer_names:
            peer = self.get_peer(peer_name)
            peers.append(peer)

        tran_prop_req = create_tx_prop_req(
            prop_type=CC_INVOKE,
            cc_name=cc_name,
            cc_version=cc_version,
            cc_type=cc_type,
            fcn=fcn,
            args=args
        )

        tx_context = create_tx_context(
            requestor,
            ecies(),
            tran_prop_req
        )

        res = self.get_channel(
            channel_name).send_tx_proposal(tx_context, peers)

        tran_req = utils.build_tx_req(res)

        tx_context_tx = create_tx_context(
            requestor,
            ecies(),
            tran_req
        )

        responses = utils.send_transaction(
            self.orderers, tran_req, tx_context_tx)

        res = tran_req.responses[0].response
        if not (res.status == 200 and responses[0].status == 200):
            return res.message

        # Wait until chaincode invoke is really effective
        # Note : we will remove this part when we have channel event hub
        starttime = int(time.time())
        payload = None
        while int(time.time()) - starttime < timeout:
            try:
                response = self.query_transaction(
                    requestor=requestor,
                    channel_name=channel_name,
                    peer_names=peer_names,
                    tx_id=tx_context.tx_id,
                    decode=False
                )

                if response.response.status == 200:
                    payload = tran_req.responses[0].response.payload
                    return payload.decode('utf-8')

                time.sleep(1)
            except Exception:
                time.sleep(1)

        msg = 'Failed to invoke chaincode. Query check returned: %s'
        return msg % payload.message

    def chaincode_query(self, requestor, channel_name, peer_names, args,
                        cc_name, cc_version, cc_type=CC_TYPE_GOLANG,
                        fcn='query'):
        """
        Query chaincode

        :param requestor: User role who issue the request
        :param channel_name: the name of the channel to send tx proposal
        :param peer_names: Names of the peers to install
        :param args (list): arguments (keys and values) for initialization
        :param cc_name: chaincode name
        :param cc_version: chaincode version
        :param cc_type: chaincode type language
        :param fcn: chaincode function
        :return: True or False
        """
        peers = []
        for peer_name in peer_names:
            peer = self.get_peer(peer_name)
            peers.append(peer)

        tran_prop_req = create_tx_prop_req(
            prop_type=CC_QUERY,
            cc_name=cc_name,
            cc_version=cc_version,
            cc_type=cc_type,
            fcn=fcn,
            args=args
        )

        tx_context = create_tx_context(
            requestor,
            ecies(),
            tran_prop_req
        )

        res = self.get_channel(
            channel_name).send_tx_proposal(tx_context, peers)

        tran_req = utils.build_tx_req(res)
        res = tran_req.responses[0].response
        if res.status == 200:
            return res.payload.decode('utf-8')

        return res.message

    def query_installed_chaincodes(self, requestor, peer_names, decode=True):
        """
        Queries installed chaincode, returns all chaincodes installed on a peer

        :param requestor: User role who issue the request
        :param peer_names: Names of the peers to query
        :param deocode: Decode the response payload
        :return: A `ChaincodeQueryResponse` or `ProposalResponse`
        """
        peers = []
        for peer_name in peer_names:
            peer = self.get_peer(peer_name)
            peers.append(peer)

        request = create_tx_prop_req(
            prop_type=CC_QUERY,
            fcn='getinstalledchaincodes',
            cc_name='lscc',
            cc_type=CC_TYPE_GOLANG,
            args=[]
        )

        tx_context = create_tx_context(requestor, ecies(), TXProposalRequest())
        tx_context.tx_prop_req = request

        responses = Channel._send_tx_proposal('', tx_context, peers)

        try:
            if responses[0][0].response and decode:
                query_trans = query_pb2.ChaincodeQueryResponse()
                query_trans.ParseFromString(responses[0][0].response.payload)
                for cc in query_trans.chaincodes:
                    _logger.debug('cc name {}, version {}, path {}'.format(
                        cc.name, cc.version, cc.path))
                return query_trans
            return responses[0][0]

        except Exception:
            _logger.error(
                "Failed to query installed chaincodes: {}", sys.exc_info()[0])
            raise

    def query_channels(self, requestor, peer_names, decode=True):
        """
        Queries channel name joined by a peer

        :param requestor: User role who issue the request
        :param peer_names: Names of the peers to install
        :param deocode: Decode the response payload
        :return: A `ChannelQueryResponse` or `ProposalResponse`
        """

        peers = []
        for peer_name in peer_names:
            peer = self.get_peer(peer_name)
            peers.append(peer)

        request = create_tx_prop_req(
            prop_type=CC_QUERY,
            fcn='GetChannels',
            cc_name='cscc',
            cc_type=CC_TYPE_GOLANG,
            args=[]
        )

        tx_context = create_tx_context(requestor, ecies(), TXProposalRequest())
        tx_context.tx_prop_req = request

        responses = Channel._send_tx_proposal('', tx_context, peers)

        try:
            if responses[0][0].response and decode:
                query_trans = query_pb2.ChannelQueryResponse()
                query_trans.ParseFromString(responses[0][0].response.payload)
                for ch in query_trans.channels:
                    _logger.debug('channel id {}'.format(
                        ch.channel_id))
                return query_trans
            return responses[0][0]

        except Exception:
            _logger.error(
                "Failed to query channel: {}", sys.exc_info()[0])
            raise

    def query_info(self, requestor, channel_name,
                   peer_names, decode=True):
        """
        Queries information of a channel

        :param requestor: User role who issue the request
        :param channel_name: Name of channel to query
        :param peer_names: Names of the peers to install
        :param deocode: Decode the response payload
        :return: A `BlockchainInfo` or `ProposalResponse`
        """

        peers = []
        for peer_name in peer_names:
            peer = self.get_peer(peer_name)
            peers.append(peer)

        channel = self.get_channel(channel_name)
        tx_context = create_tx_context(requestor, ecies(), TXProposalRequest())

        responses = channel.query_info(tx_context, peers)

        try:
            if responses[0][0].response and decode:
                chain_info = ledger_pb2.BlockchainInfo()
                chain_info.ParseFromString(responses[0][0].response.payload)
                _logger.debug('response status {}'.format(
                    responses[0][0].response.status))
                return chain_info
            return responses[0][0]

        except Exception:
            _logger.error(
                "Failed to query info: {}", sys.exc_info()[0])
            raise

    def query_block_by_txid(self, requestor, channel_name,
                            peer_names, tx_id, decode=True):
        """
        Queries block by tx id

        :param requestor: User role who issue the request
        :param channel_name: Name of channel to query
        :param peer_names: Names of the peers to install
        :param tx_id: Transaction ID
        :param deocode: Decode the response payload
        :return: A `BlockDecoder` or `ProposalResponse`
        """

        peers = []
        for peer_name in peer_names:
            peer = self.get_peer(peer_name)
            peers.append(peer)

        channel = self.get_channel(channel_name)
        tx_context = create_tx_context(requestor, ecies(), TXProposalRequest())

        responses = channel.query_block_by_txid(tx_context, peers, tx_id)

        try:
            if responses[0][0].response and decode:
                _logger.debug('response status {}'.format(
                    responses[0][0].response.status))
                block = BlockDecoder().decode(responses[0][0].response.payload)
                _logger.debug('looking at block {}'.format(
                    block['header']['number']))
                return block
            return responses[0][0]

        except Exception:
            _logger.error(
                "Failed to query block: {}", sys.exc_info()[0])
            raise

    def query_block_by_hash(self, requestor, channel_name,
                            peer_names, block_hash, decode=True):
        """
        Queries block by hash

        :param requestor: User role who issue the request
        :param channel_name: Name of channel to query
        :param peer_names: Names of the peers to install
        :param block_hash: Hash of a block
        :param deocode: Decode the response payload
        :return: A `BlockDecoder` or `ProposalResponse`
        """

        peers = []
        for peer_name in peer_names:
            peer = self.get_peer(peer_name)
            peers.append(peer)

        channel = self.get_channel(channel_name)
        tx_context = create_tx_context(requestor, ecies(), TXProposalRequest())

        responses = channel.query_block_by_hash(tx_context, peers, block_hash)

        try:
            if responses[0][0].response and decode:
                _logger.debug('response status {}'.format(
                    responses[0][0].response.status))
                block = BlockDecoder().decode(responses[0][0].response.payload)
                _logger.debug('looking at block {}'.format(
                    block['header']['number']))
                return block
            return responses[0][0]

        except Exception:
            _logger.error(
                "Failed to query block: {}", sys.exc_info()[0])
            raise

    def query_block(self, requestor, channel_name,
                    peer_names, block_number, decode=True):
        """
        Queries block by number

        :param requestor: User role who issue the request
        :param channel_name: name of channel to query
        :param peer_names: Names of the peers to install
        :param block_number: Number of a block
        :param deocode: Decode the response payload
        :return: A `BlockDecoder` or `ProposalResponse`
        """

        peers = []
        for peer_name in peer_names:
            peer = self.get_peer(peer_name)
            peers.append(peer)

        channel = self.get_channel(channel_name)
        tx_context = create_tx_context(requestor, ecies(), TXProposalRequest())

        responses = channel.query_block(tx_context, peers, block_number)

        try:
            if responses[0][0].response and decode:
                _logger.debug('response status {}'.format(
                    responses[0][0].response.status))
                block = BlockDecoder().decode(responses[0][0].response.payload)
                _logger.debug('looking at block {}'.format(
                    block['header']['number']))
                return block
            return responses[0][0]

        except Exception:
            _logger.error(
                "Failed to query block: {}", sys.exc_info()[0])
            raise

    def query_transaction(self, requestor, channel_name,
                          peer_names, tx_id, decode=True):
        """
        Queries block by number

        :param requestor: User role who issue the request
        :param channel_name: name of channel to query
        :param peer_names: Names of the peers to install
        :param tx_id: The id of the transaction
        :param deocode: Decode the response payload
        :return:  A `BlockDecoder` or `ProposalResponse`
        """

        peers = []
        for peer_name in peer_names:
            peer = self.get_peer(peer_name)
            peers.append(peer)

        channel = self.get_channel(channel_name)
        tx_context = create_tx_context(requestor, ecies(), TXProposalRequest())

        responses = channel.query_transaction(tx_context, peers, tx_id)

        try:
            if responses[0][0].response and decode:
                _logger.debug('response status {}'.format(
                    responses[0][0].response.status))
                process_trans = BlockDecoder().decode_transaction(
                    responses[0][0].response.payload)
                return process_trans

            return responses[0][0]

        except Exception:
            _logger.error(
                "Failed to query block: {}", sys.exc_info()[0])
            raise

    def query_instantiated_chaincodes(self, requestor, channel_name,
                                      peer_names, decode=True):
        """
        Queries instantiated chaincode

        :param requestor: User role who issue the request
        :param channel_name: name of channel to query
        :param peer_names: Names of the peers to query
        :param deocode: Decode the response payload
        :return: A `ChaincodeQueryResponse` or `ProposalResponse`
        """
        peers = []
        for peer_name in peer_names:
            peer = self.get_peer(peer_name)
            peers.append(peer)

        channel = self.get_channel(channel_name)
        tx_context = create_tx_context(requestor, ecies(), TXProposalRequest())

        responses = channel.query_instantiated_chaincodes(tx_context, peers)

        try:
            if responses[0][0].response and decode:
                query_trans = query_pb2.ChaincodeQueryResponse()
                query_trans.ParseFromString(responses[0][0].response.payload)
                for cc in query_trans.chaincodes:
                    _logger.debug('cc name {}, version {}, path {}'.format(
                        cc.name, cc.version, cc.path))
                return query_trans
            return responses[0][0]

        except Exception:
            _logger.error(
                "Failed to query instantiated chaincodes: {}",
                sys.exc_info()[0])
            raise

    def get_channel_config(self, requestor, channel_name,
                           peer_names, decode=True):
        """
        Get configuration block for the channel

        :param requestor: User role who issue the request
        :param channel_name: name of channel to query
        :param peer_names: Names of the peers to query
        :param deocode: Decode the response payload
        :return: A `ChaincodeQueryResponse` or `ProposalResponse`
        """
        peers = []
        for peer_name in peer_names:
            peer = self.get_peer(peer_name)
            peers.append(peer)

        channel = self.get_channel(channel_name)
        tx_context = create_tx_context(requestor, ecies(), TXProposalRequest())

        responses = channel.get_channel_config(tx_context, peers)

        try:
            if responses[0][0].response and decode:
                _logger.debug('response status {}'.format(
                    responses[0][0].response.status))
                block = common_pb2.Block()
                block.ParseFromString(responses[0][0].response.payload)
                envelope = common_pb2.Envelope()
                envelope.ParseFromString(block.data.data[0])
                payload = common_pb2.Payload()
                payload.ParseFromString(envelope.payload)
                config_envelope = configtx_pb2.ConfigEnvelope()
                config_envelope.ParseFromString(payload.data)
                return config_envelope

            return responses[0][0]

        except Exception:
            _logger.error(
                "Failed to get channel config block: {}", sys.exc_info()[0])
            raise

    def query_peers(self, requestor, target_peer,
                    crypto=ecies(), decode=True):
        """Queries peers with discovery api

        :param requestor: User role who issue the request
        :param target_peer: Name of the peers to send request
        :param crypto: crypto method to sign the request
        :param deocode: Decode the response payload
        :return result: a nested dict of query result
        """

        dummy_channel = self.new_channel('discover-local')

        response = dummy_channel._discovery(
            requestor, target_peer, crypto, local=True)

        try:
            results = {}
            if response and decode:
                for index in range(len(response.results)):
                    result = response.results[index]
                    if not result:
                        raise Exception("Discovery results are missing")
                    if hasattr(result, 'error'):
                        _logger.error(
                            "Channel {} received discovery error: {}".format(
                                dummy_channel.name, result.error.content))
                    if hasattr(result, 'members'):
                        results['local_peers'] =  \
                            self._process_discovery_membership_result(
                                result.members)
            return results

        except Exception:
            _logger.error(
                "Failed to query instantiated chaincodes: {}",
                sys.exc_info()[0])
            raise

    def _process_discovery_membership_result(self, q_members):
        peers_by_org = {}
        if hasattr(q_members, 'peers_by_org'):
            for mspid in q_members.peers_by_org:
                peers_by_org[mspid] = {}
                peers_by_org[mspid]['peers'] = self._process_peers(
                    q_members.peers_by_org[mspid].peers)

        return peers_by_org

    def _process_peers(self, q_peers):
        peers = []
        for q_peer in q_peers:
            peer = {}

            # IDENTITY
            q_identity = identities_pb2.SerializedIdentity()
            q_identity.ParseFromString(q_peer.identity)
            peer['mspid'] = q_identity.mspid

            # MEMBERSHIP
            q_membership_msg = message_pb2.GossipMessage()
            q_membership_msg.ParseFromString(q_peer.membership_info.payload)
            peer['endpoint'] = q_membership_msg.alive_msg.membership.endpoint

            # STATE
            if hasattr(q_peer, 'state_info'):
                message_s = message_pb2.GossipMessage()
                message_s.ParseFromString(
                    q_peer.state_info.payload)
                try:
                    peer['ledger_height'] = int(
                        message_s.state_info.properties.ledger_height)
                except AttributeError as e:
                    peer['ledger_height'] = 0
                    _logger.debug(
                        'missing ledger_height: {}'.format(e))

                peer['chaincodes'] = []
                for index in message_s.state_info.properties.chaincodes:
                    q_cc = message_s.info.properties.chaincodes[index]
                    cc = {}
                    cc['name'] = q_cc.name
                    cc['version'] = q_cc.version
                    peer['chaincodes'].append(cc)

            peers.append(peer)

        return sorted(peers, key=lambda k: k['endpoint'])
