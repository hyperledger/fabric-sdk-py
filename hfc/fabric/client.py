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

import asyncio
import logging
import json
import sys
import os
import subprocess
import shutil
from _sha256 import sha256

from hfc.fabric.channel.channel import Channel
from hfc.fabric.orderer import Orderer
from hfc.fabric.peer import Peer
from hfc.fabric.user import User
from hfc.fabric.organization import create_org
from hfc.fabric.certificateAuthority import create_ca
from hfc.fabric.transaction.tx_context import TXContext, create_tx_context
from hfc.fabric.transaction.tx_proposal_request import TXProposalRequest, \
    create_tx_prop_req, CC_INSTALL, CC_TYPE_GOLANG, CC_INSTANTIATE, \
    CC_INVOKE, CC_QUERY, CC_UPGRADE
from hfc.protos.common import common_pb2, configtx_pb2, ledger_pb2
from hfc.protos.peer import query_pb2
from hfc.protos.peer.chaincode_pb2 import ChaincodeData
from hfc.fabric.block_decoder import BlockDecoder, \
    decode_fabric_peers_info, decode_fabric_MSP_config, \
    decode_fabric_endpoints, decode_proposal_response_payload, \
    decode_signature_policy_envelope
from hfc.util import utils
from hfc.util.keyvaluestore import FileKeyValueStore

# inject global default config
from hfc.fabric.config.default import DEFAULT
from hfc.util.utils import pem_to_der

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
        self.kv_store_path = None
        self._state_store = None
        self._is_dev_mode = False
        self._client_key_path = None
        self._client_cert_path = None
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
        cas = self.get_net_info('certificateAuthorities')
        for name in cas:
            _logger.debug("create ca with name={}".format(name))
            ca = create_ca(name, cas[name])
            self._CAs[name] = ca

        # Init orderer nodes
        orderers = self.get_net_info('orderers')
        _logger.debug("Import orderers = {}".format(orderers.keys()))
        for name in orderers:
            orderer = Orderer(name=name, endpoint=orderers[name]['url'])
            orderer.init_with_bundle(orderers[name])
            self._orderers[name] = orderer

        # Init peer nodes
        peers = self.get_net_info('peers')
        _logger.debug("Import peers = {}".format(peers.keys()))
        for name in peers:
            peer = Peer(name=name)
            peer.init_with_bundle(peers[name])
            self._peers[name] = peer

    async def init_with_discovery(self, requestor, peer_target,
                                  channel_name=None):
        """
        Load the connection profile from discover.

        Init the handlers for orgs, peers, orderers, ca nodes

        :return:
        """

        if not isinstance(requestor, User):
            return

        if not isinstance(peer_target, Peer):
            return
        else:
            self._peers[peer_target._name] = peer_target

        # read kv store path from requestor
        self.kv_store_path = requestor._state_store.path
        if self.kv_store_path:
            self._state_store = FileKeyValueStore(self.kv_store_path)
        else:
            _logger.warning('No kv store path exists in requestor {}'.format(
                requestor))

        # Init from Local Config
        if channel_name is None:
            response = await Channel('discovery', '')._discovery(
                requestor,
                peer_target,
                config=False,
                local=True)

            members = response.results[0].members
            config_result = None
        else:
            self.new_channel(channel_name)
            channel = self.get_channel(channel_name)
            response = await channel._discovery(requestor,
                                                peer_target,
                                                config=True,
                                                local=False)

            members = response.results[0].members
            config_result = response.results[1].config_result

        # Members parsing
        peers = []
        for msp_name in members.peers_by_org:
            peers.append(decode_fabric_peers_info(
                members.peers_by_org[msp_name].peers))

        # Config parsing
        if config_result is not None:
            results = {'msps': {},
                       'orderers': {}}

            for msp_name in config_result.msps:
                results['msps'][msp_name] = decode_fabric_MSP_config(
                    config_result.msps[msp_name].SerializeToString())

            for orderer_msp in config_result.orderers:
                results['orderers'][orderer_msp] = decode_fabric_endpoints(
                    config_result.orderers[orderer_msp].endpoint)

        # # Init organizations
        for msp_name in results['msps']:

            _logger.debug("create org with name={}".format(msp_name))

            info = {
                "mspid": msp_name
            }

            org_peers = [peer_info['endpoint'].split(':')[0]
                         for peers_by_org in peers
                         for peer_info in peers_by_org
                         if peer_info['mspid'] == msp_name]

            if org_peers:
                info['peers'] = org_peers

            if msp_name in results['orderers']:
                org_orderers = [orderer_info['host']
                                for orderer_info in results[
                                    'orderers'][msp_name]]

                info['orderers'] = org_orderers

            org = create_org(msp_name, info, self._state_store)
            if msp_name not in self._organizations:
                self._organizations[msp_name] = org

        # Init orderer nodes
        _logger.debug("Import orderers = {}".format(results[
                                                    'orderers'].keys()))
        for orderer_msp in results['orderers']:
            for orderer_info in results['orderers'][orderer_msp]:
                orderer_endpoint = '%s:%s' % (orderer_info['host'],
                                              orderer_info['port'])
                info = {'url': orderer_endpoint,
                        'tlsCACerts': {'path': results['msps'][
                            orderer_msp]['tls_root_certs'][0].encode()},
                        'grpcOptions': {
                            'grpc.ssl_target_name_override': orderer_info[
                                'host']}
                        }

                orderer = Orderer(name=orderer_info['host'],
                                  endpoint=orderer_endpoint)
                orderer.init_with_bundle(info)

                if orderer_info['host'] not in self._orderers:
                    self._orderers[orderer_info['host']] = orderer

        # Init peer nodes
        peers_name = [peer_info['endpoint'].split(':')[0]
                      for peers_by_org in peers
                      for peer_info in peers_by_org]

        _logger.debug("Import peers = {}".format(peers_name))

        for peers_by_org in peers:
            for peer_info in peers_by_org:
                target_name = peer_info['endpoint'].split(':')[0]
                info = {'url': peer_info['endpoint'],
                        'grpcOptions': {
                            'grpc.ssl_target_name_override': target_name}
                        }

                if config_result:
                    tlsCACerts = results['msps'][
                        peer_info['mspid']]['tls_root_certs'][0].encode()
                    info['tlsCACerts'] = {'path': tlsCACerts}

                peer = Peer(name=target_name)
                peer.init_with_bundle(info)

                if target_name not in self._peers:
                    self._peers[target_name] = peer

    def set_tls_client_cert_and_key(self, client_key_file=None,
                                    client_cert_file=None):

        """
        Set tls client certificate and key for mutual tls for all peers
        and orderers

        Args:
            client_key (str): file path for Private key used for TLS when
                making client connections
            client_cert (str): file path for X.509 certificate used for TLS
                when making client connections

        Returns:
            bool: set success value
        """

        self._client_key_path = client_key_file
        self._client_cert_path = client_cert_file

        res = []

        for orderer_name in self._orderers:
            set_tls = self._orderers[orderer_name].set_tls_client_cert_and_key(
                self._client_key_path,
                self._client_cert_path
            )
            res.append(set_tls)

        for peer_name in self._peers:
            set_tls = self._peers[peer_name].set_tls_client_cert_and_key(
                self._client_key_path,
                self._client_cert_path
            )
            res.append(set_tls)

        return not res or all(res)

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
            _logger.warning(f"Cannot find orderer with name {name}")
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
            _logger.warning(f"Cannot find peer with name {name}")
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
                    _logger.warning(f'No key path {key_path} exists'
                                    f' in net info')
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

    # TODO pass enveloppe directly
    # TODO channel_create and channel_update are almost the same, refacto
    async def channel_create(self, orderer, channel_name, requestor,
                             config_yaml=None, channel_profile=None,
                             config_tx=None):
        """
        Create a channel, send request to orderer, and check the response

        :param orderer: Name or Orderer instance of orderer to get
        genesis block from
        :param channel_name: Name of channel to create
        :param requestor: Name of creator
        :param config_yaml: Directory path of config yaml to be set for FABRIC_
        CFG_PATH variable
        :param channel_profile: Name of the channel profile defined inside
        config yaml file
        :param config_tx: Path of the configtx file of createchannel generated
        with configtxgen
        :return: True (creation succeeds) or False (creation failed)
        """
        if self.get_channel(channel_name):
            msg = f"channel {channel_name} already existed when creating"
            _logger.warning(msg)
            raise Exception(msg)

        target_orderer = None
        if isinstance(orderer, Orderer):
            target_orderer = orderer
        elif isinstance(orderer, str):
            target_orderer = self.get_orderer(orderer)

        if not target_orderer:
            _logger.error(f"No orderer instance found with name {orderer}")
            return False

        if config_tx is not None:
            config_tx = config_tx if os.path.isabs(config_tx) else \
                os.getcwd() + "/" + config_tx
            with open(config_tx, 'rb') as f:
                envelope = f.read()
                config = utils.extract_channel_config(envelope)
        elif config_yaml is not None and channel_profile is not None:
            tx = self.generate_channel_tx(channel_name, config_yaml,
                                          channel_profile)
            if tx is None:
                _logger.error('Configtx is empty')
                return False
            _logger.info("Configtx file successfully created in current \
            directory")

            with open(tx, 'rb') as f:
                envelope = f.read()
                config = utils.extract_channel_config(envelope)
        else:
            _logger.error('Configtx or (config_yaml + channel) \
            profile must be provided.')
            return False

        # convert envelope to config
        self.tx_context = TXContext(requestor, requestor.cryptoSuite, {})
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
            'orderer': target_orderer,
            'channel_name': channel_name
        }
        responses = await self._create_or_update_channel(request)

        if not all([x.status == 200 for x in responses]):
            raise Exception(responses)

        self.new_channel(channel_name)
        return True

    # TODO pass envelope directly if possible
    # TODO support passing config as a python object directly
    async def channel_update(self, orderer, channel_name, requestor,
                             config_yaml=None, channel_profile=None,
                             config_tx=None, signatures=None):
        """
        Update a channel, send request to orderer, and check the response

        :param orderer: Name or Orderer instance of orderer to get
        genesis block from
        :param channel_name: Name of channel to create
        :param requestor: Name of creator
        :param config_tx: Path of the configtx file of createchannel generated
        with configtxgen
        :return: True (creation succeeds) or False (creation failed)
        """
        if signatures is None:
            signatures = []

        channel = self.get_channel(channel_name)
        if not channel:
            _logger.warning(f"channel {channel_name} does not exist")
            return False

        target_orderer = None
        if isinstance(orderer, Orderer):
            target_orderer = orderer
        elif isinstance(orderer, str):
            target_orderer = self.get_orderer(orderer)

        if not target_orderer:
            _logger.error(f"No orderer instance found with name {orderer}")
            return False

        if config_tx is not None:
            config_tx = config_tx if os.path.isabs(config_tx) else \
                os.path.join(os.getcwd(), config_tx)
            with open(config_tx, 'rb') as f:
                envelope = f.read()
                config = utils.extract_channel_config(envelope)
        elif config_yaml is not None and channel_profile is not None:
            tx = self.generate_channel_tx(channel_name, config_yaml,
                                          channel_profile)
            if tx is None:
                _logger.error('Configtx is empty')
                return False
            _logger.info("Configtx file successfully created in current \
            directory")

            with open(tx, 'rb') as f:
                envelope = f.read()
                config = utils.extract_channel_config(envelope)
        else:
            _logger.error('Configtx must be provided.')
            return False

        # convert envelope to config
        self.tx_context = TXContext(requestor, requestor.cryptoSuite, {})
        tx_id = self.tx_context.tx_id
        nonce = self.tx_context.nonce

        # sign it
        org1_admin_signature = self.sign_channel_config(config)
        # append org1_admin_signature to signatures
        signatures.append(org1_admin_signature)

        request = {
            'tx_id': tx_id,
            'nonce': nonce,
            'signatures': signatures,
            'config': config,
            'orderer': target_orderer,
            'channel_name': channel_name
        }
        responses = await self._create_or_update_channel(request)

        if not all([x.status == 200 for x in responses]):
            raise Exception(responses)

        return True

    async def channel_join(self, requestor, channel_name, peers,
                           orderer):
        """
        Join a channel.
        Get genesis block from orderer, then send request to peer

        :param requestor: User to send the request
        :param channel_name: Name of channel to create
        :param peers: List of peers to join to the channel
        :param orderer: Name or Orderer instance of orderer to get
        genesis block from

        :return: True (creation succeeds) or False (creation failed)
        """
        channel = self.get_channel(channel_name)
        if not channel:
            _logger.warning(f"channel {channel_name} not existed when join")
            print(f"channel {channel_name} not existed when join")
            return False

        target_orderer = None
        if isinstance(orderer, Orderer):
            target_orderer = orderer
        elif isinstance(orderer, str):
            target_orderer = self.get_orderer(orderer)

        if not target_orderer:
            _logger.warning(f"orderer {orderer} not existed when channel join")
            print(f"orderer {orderer} not existed when channel join")
            return False

        tx_prop_req = TXProposalRequest()

        # get the genesis block
        tx_context = TXContext(requestor, requestor.cryptoSuite,
                               tx_prop_req)

        genesis_block = None
        stream = target_orderer.get_genesis_block(tx_context, channel.name)

        async for v in stream:
            block = v.block.SerializeToString()
            if block is None or block == b'':
                msg = "fail to get genesis block"
                _logger.error(msg)
                raise Exception(msg)

            _logger.info("get genesis block successfully, block=%s",
                         v.block.header)
            genesis_block = block
            break

        if genesis_block is None:
            msg = "fail to get genesis block"
            _logger.error(msg)
            raise Exception(msg)

        # create the peer
        tx_context = TXContext(requestor, requestor.cryptoSuite, tx_prop_req)

        target_peers = []
        for peer in peers:
            if isinstance(peer, Peer):
                target_peers.append(peer)
            elif isinstance(peer, str):
                peer = self.get_peer(peer)
                target_peers.append(peer)
            else:
                _logger.error('{} should be a peer name or a Peer instance'.
                              format(peer))

        if not target_peers:
            err_msg = "Failed to query block: no functional peer provided"
            _logger.error(err_msg)
            raise Exception(err_msg)

        request = {
            "targets": target_peers,
            "block": genesis_block,
            "tx_context": tx_context,
            "transient_map": {}
        }

        responses = channel.join_channel(request)
        res = await asyncio.gather(*responses)

        if not all([x.response.status == 200 for x in res]):
            return res[0].response.message

        return res

    async def get_channel_config(self, requestor, channel_name,
                                 peers, decode=True):
        """
        Get configuration block for the channel

        :param requestor: User role who issue the request
        :param channel_name: name of channel to query
        :param peers: Names or Instance of the peers to query
        :param deocode: Decode the response payload
        :return: A `ChaincodeQueryResponse` or `ProposalResponse`
        """
        target_peers = []
        for peer in peers:
            if isinstance(peer, Peer):
                target_peers.append(peer)
            elif isinstance(peer, str):
                peer = self.get_peer(peer)
                target_peers.append(peer)
            else:
                _logger.error(f'{peer} should be a peer name or'
                              f' a Peer instance')

        if not target_peers:
            err_msg = "Failed to query block: no functional peer provided"
            _logger.error(err_msg)
            raise Exception(err_msg)

        channel = self.get_channel(channel_name)
        tx_context = create_tx_context(requestor, requestor.cryptoSuite,
                                       TXProposalRequest())

        responses, proposal, header = channel.get_channel_config(tx_context,
                                                                 target_peers)

        responses = await asyncio.gather(*responses)

        results = []
        for pplResponse in responses:
            try:
                if pplResponse.response and decode:
                    msg = f'response status {pplResponse.response.status}'
                    _logger.debug(msg)
                    block = common_pb2.Block()
                    block.ParseFromString(pplResponse.response.payload)
                    envelope = common_pb2.Envelope()
                    envelope.ParseFromString(block.data.data[0])
                    payload = common_pb2.Payload()
                    payload.ParseFromString(envelope.payload)
                    config_envelope = configtx_pb2.ConfigEnvelope()
                    config_envelope.ParseFromString(payload.data)
                    results.append(config_envelope)
                else:
                    results.append(pplResponse)

            except Exception:
                _logger.error(
                    "Failed to query instantiated chaincodes: {}",
                    sys.exc_info()[0])
                raise

        return results

    async def get_channel_config_with_orderer(self, requestor,
                                              channel_name,
                                              orderer=None):
        """
        Get configuration block for the channel with the orderer

        :param requestor: User role who issue the request
        :param channel_name: name of channel to query
        :param orderer: Names or Instance of the orderer to query
        :return: A ConfigEnveloppe
        """
        target_orderer = None
        if isinstance(orderer, Orderer):
            target_orderer = orderer
        elif isinstance(orderer, str):
            target_orderer = self.get_orderer(orderer)

        if not target_orderer:
            err_msg = "Failed to get_channel_config_with_orderer:" \
                      " no functional orderer provided"
            _logger.error(err_msg)
            raise Exception(err_msg)

        channel = self.get_channel(channel_name)
        tx_context = create_tx_context(requestor, requestor.cryptoSuite,
                                       TXProposalRequest())

        config_envelope = await channel.get_channel_config_with_orderer(
            tx_context,
            target_orderer)

        return config_envelope

    def extract_channel_config(self, config_envelope):
        """Extracts the protobuf 'ConfigUpdate' out of
        the 'ConfigEnvelope' that is produced by the configtxgen tool

        The returned object may then be signed using sign_channel_config()
        method.

        Once all the signatures have been collected, the 'ConfigUpdate' object
        and the signatures may be used on create_channel() or update_channel()
        calls

        Args:
            config_envelope (bytes): encoded bytes of the ConfigEnvelope
            protobuf

        Returns:
            config_update (bytes): encoded bytes of ConfigUpdate protobuf,
            ready to be signed
        """
        _logger.debug('extract_channel_config start')

        envelope = common_pb2.Envelope()
        envelope.ParseFromString(config_envelope)
        payload = common_pb2.Payload()
        payload.ParseFromString(envelope.payload)
        configtx = configtx_pb2.ConfigUpdateEnvelope()
        configtx.ParseFromString(payload.data)
        config_update = configtx.ConfigUpdate

        return config_update.SerializeToString()

    def sign_channel_config(self, config, to_string=True):
        """This method uses the client instance's current signing identity to
         sign over the configuration bytes passed in.

        Args:
            config: The configuration update in bytes form.
            tx_context: Transaction Context
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

    def channel_signconfigtx(self, config_tx_file, requestor):
        with open(config_tx_file, 'rb') as f:
            envelope = f.read()
            config = utils.extract_channel_config(envelope)
        self.tx_context = TXContext(requestor, requestor.cryptoSuite, {})
        return self.sign_channel_config(config)

    async def _create_or_update_channel(self, request):
        """Calls the orderer to start building the new channel.

        Args:
            request (dct): The create channel request.

        Returns:
            OrdererResponse or an error.

        """
        have_envelope = False
        _logger.debug(request)
        if request and 'envelope' in request:
            _logger.debug('_create_or_update_channel - have envelope')
            have_envelope = True

        res = []
        async for v in self._create_or_update_channel_request(request,
                                                              have_envelope):
            res.append(v)
        return res

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

        orderer = request['orderer']

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

            kwargs = {}
            if orderer._client_cert_path:
                with open(orderer._client_cert_path, 'rb') as f:
                    b64der = pem_to_der(f.read())
                    kwargs['tls_cert_hash'] = sha256(b64der).digest()

            proto_channel_header = utils.build_channel_header(
                common_pb2.HeaderType.Value('CONFIG_UPDATE'),
                request['tx_id'],
                request['channel_name'],
                utils.current_timestamp(),
                **kwargs
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

        return orderer.broadcast(out_envelope)

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

    def send_upgrade_proposal(self, tx_context, peers,
                              channel_name):
        """ Send upgrade proposal

        Args:
            tx_context: transaction context
            peers: peers
            channel_name: the name of channel

        Returns: A set of proposal_response

        """
        app_channel = self.get_channel(channel_name)
        _logger.debug("context {}".format(tx_context))
        return app_channel.send_upgrade_proposal(tx_context, peers)

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
        if 'fabric-bin/bin' not in os.environ['PATH']:
            executable_path = os.path.join(
                os.path.dirname(__file__).rsplit('/', 2)[0], 'fabric-bin/bin')
            os.environ['PATH'] += os.pathsep + executable_path

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

    async def chaincode_install(self, requestor, peers, cc_path, cc_name,
                                cc_version, packaged_cc=None,
                                transient_map=None):
        """
        Install chaincode to given peers by requestor role

        :param requestor: User role who issue the request
        :param peers: List of  peer name and/or Peer to install
        :param cc_path: chaincode path
        :param cc_name: chaincode name
        :param cc_version: chaincode version
        :param packaged_cc: packaged chaincode
        :param transient_map: transient map
        :return: True or False
        """
        target_peers = []
        for peer in peers:
            if isinstance(peer, Peer):
                target_peers.append(peer)
            elif isinstance(peer, str):
                peer = self.get_peer(peer)
                target_peers.append(peer)
            else:
                _logger.error('{} should be a peer name or a Peer instance'.
                              format(peer))

        if not target_peers:
            err_msg = "Failed to install chaincode: no functional" \
                      " peer provided"
            _logger.error(err_msg)
            raise Exception(err_msg)

        tran_prop_req = create_tx_prop_req(CC_INSTALL, cc_path, CC_TYPE_GOLANG,
                                           cc_name, cc_version,
                                           packaged_cc=packaged_cc,
                                           transient_map=transient_map)
        tx_context = create_tx_context(requestor, requestor.cryptoSuite,
                                       tran_prop_req)

        responses, proposal, header = self.send_install_proposal(tx_context,
                                                                 target_peers)
        res = await asyncio.gather(*responses)
        return res

    async def chaincode_instantiate(self, requestor, channel_name, peers,
                                    args, cc_name, cc_version,
                                    cc_endorsement_policy=None,
                                    transient_map=None,
                                    collections_config=None,
                                    wait_for_event=False,
                                    wait_for_event_timeout=30):
        """
            Instantiate installed chaincode to particular peer in
            particular channel

        :param requestor: User role who issue the request
        :param channel_name: the name of the channel to send tx proposal
        :param peers: List of  peer name and/or Peer to install
        :param args (list): arguments (keys and values) for initialization
        :param cc_name: chaincode name
        :param cc_version: chaincode version
        :param cc_endorsement_policy: chaincode endorsement policy
        :param transient_map: transient map
        :param collection_config: collection configuration
        :param wait_for_event: Whether to wait for the event from each peer's
         deliver filtered service signifying that the 'invoke' transaction has
          been committed successfully
        :param wait_for_event_timeout: Time to wait for the event from each
         peer's deliver filtered service signifying that the 'invoke'
          transaction has been committed successfully (default 30s)
        :return: chaincode data payload
        """
        target_peers = []
        for peer in peers:
            if isinstance(peer, Peer):
                target_peers.append(peer)
            elif isinstance(peer, str):
                peer = self.get_peer(peer)
                target_peers.append(peer)
            else:
                _logger.error('{} should be a peer name or a Peer instance'.
                              format(peer))

        if not target_peers:
            err_msg = "Failed to query block: no functional peer provided"
            _logger.error(err_msg)
            raise Exception(err_msg)

        tran_prop_req_dep = create_tx_prop_req(
            prop_type=CC_INSTANTIATE,
            cc_type=CC_TYPE_GOLANG,
            cc_name=cc_name,
            cc_version=cc_version,
            cc_endorsement_policy=cc_endorsement_policy,
            fcn='init',
            args=args,
            transient_map=transient_map,
            collections_config=collections_config
        )

        tx_context_dep = create_tx_context(
            requestor,
            requestor.cryptoSuite,
            tran_prop_req_dep
        )

        channel = self.get_channel(channel_name)

        responses, proposal, header = self.send_instantiate_proposal(
            tx_context_dep, target_peers, channel_name)
        res = await asyncio.gather(*responses)
        # if proposal was not good, return
        if not all([x.response.status == 200 for x in res]):
            return res[0].response.message

        tran_req = utils.build_tx_req((res, proposal, header))

        tx_context = create_tx_context(requestor,
                                       requestor.cryptoSuite,
                                       TXProposalRequest())
        responses = utils.send_transaction(self.orderers, tran_req, tx_context)

        # responses will be a stream
        async for v in responses:
            if not v.status == 200:
                return v.message

        res = decode_proposal_response_payload(res[0].payload)

        # wait for transaction id proposal available in ledger and block
        # commited
        if wait_for_event:
            channelEventsHubs = {}
            event_stream = []
            for target_peer in target_peers:
                channel_event_hub = channel.newChannelEventHub(target_peer,
                                                               requestor)
                stream = channel_event_hub.connect()
                txid = channel_event_hub.registerTxEvent(tx_context_dep.tx_id)
                event_stream.append(stream)
                channelEventsHubs[txid] = channel_event_hub
            try:
                r = await asyncio.wait_for(asyncio.gather(*event_stream),
                                           timeout=wait_for_event_timeout)
            except asyncio.TimeoutError:
                for k, v in channelEventsHubs.items():
                    v.unregisterTxEvent(k)
                raise TimeoutError('waitForEvent timed out')
            except Exception as e:
                return str(e)
            else:
                # check if all events are not None
                if not all([x is True for x in r]):
                    msg = 'One or more peers did not validate the events'
                    raise Exception(msg)
            finally:
                # disconnect channel_event_hubs
                for channel_event_hub in channelEventsHubs.values():
                    channel_event_hub.disconnect()

        ccd = ChaincodeData()
        payload = res['extension']['response']['payload']
        ccd.ParseFromString(payload)

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
                'hash': ccd.data.hash,
                'metadatahash': ccd.data.metadatahash,
            },
            'id': ccd.id,
            'instantiation_policy': instantiation_policy,
        }
        return chaincode

    async def chaincode_upgrade(self, requestor, channel_name, peers,
                                cc_name, cc_version,
                                cc_endorsement_policy=None,
                                fcn='init', args=None,
                                transient_map=None,
                                collections_config=None,
                                wait_for_event=False,
                                wait_for_event_timeout=30):
        """
            Upgrade installed chaincode to particular peer in
            particular channel

        :param requestor: User role who issue the request
        :param channel_name: the name of the channel to send tx proposal
        :param peers: List of  peer name and/or Peer to install
        :param args (list): arguments (keys and values) for initialization
        :param cc_name: chaincode name
        :param cc_version: chaincode version
        :param cc_endorsement_policy: chaincode endorsement policy
        :param fcn: chaincode function to send
        :param args: chaincode function arguments
        :param transient_map: transient map
        :param collection_config: collection configuration
        :param wait_for_event: Whether to wait for the event from each peer's
         deliver filtered service signifying that the 'invoke' transaction has
          been committed successfully
        :param wait_for_event_timeout: Time to wait for the event from each
         peer's deliver filtered service signifying that the 'invoke'
          transaction has been committed successfully (default 30s)
        :return: chaincode data payload
        """
        target_peers = []
        for peer in peers:
            if isinstance(peer, Peer):
                target_peers.append(peer)
            elif isinstance(peer, str):
                peer = self.get_peer(peer)
                target_peers.append(peer)
            else:
                _logger.error('{} should be a peer name or a Peer instance'.
                              format(peer))

        if not target_peers:
            err_msg = "Failed to query block: no functional peer provided"
            _logger.error(err_msg)
            raise Exception(err_msg)

        tran_prop_req_dep = create_tx_prop_req(
            prop_type=CC_UPGRADE,
            cc_type=CC_TYPE_GOLANG,
            cc_name=cc_name,
            cc_version=cc_version,
            cc_endorsement_policy=cc_endorsement_policy,
            fcn=fcn,
            args=args,
            transient_map=transient_map,
            collections_config=collections_config,
        )

        tx_context_dep = create_tx_context(
            requestor,
            requestor.cryptoSuite,
            tran_prop_req_dep
        )

        channel = self.get_channel(channel_name)

        responses, proposal, header = self.send_upgrade_proposal(
            tx_context_dep, target_peers, channel_name)
        res = await asyncio.gather(*responses)
        # if proposal was not good, return
        if not all([x.response.status == 200 for x in res]):
            return res[0].response.message

        tran_req = utils.build_tx_req((res, proposal, header))

        tx_context = create_tx_context(requestor,
                                       requestor.cryptoSuite,
                                       TXProposalRequest())
        responses = utils.send_transaction(self.orderers, tran_req, tx_context)

        # responses will be a stream
        async for v in responses:
            if not v.status == 200:
                return v.message

        res = decode_proposal_response_payload(res[0].payload)

        # wait for transaction id proposal available in ledger and block
        # commited
        if wait_for_event:
            channelEventsHubs = {}
            event_stream = []
            for target_peer in target_peers:
                channel_event_hub = channel.newChannelEventHub(target_peer,
                                                               requestor)
                stream = channel_event_hub.connect()
                txid = channel_event_hub.registerTxEvent(tx_context_dep.tx_id)
                event_stream.append(stream)
                channelEventsHubs[txid] = channel_event_hub
            try:
                r = await asyncio.wait_for(asyncio.gather(*event_stream),
                                           timeout=wait_for_event_timeout)
            except asyncio.TimeoutError:
                for k, v in channelEventsHubs.items():
                    v.unregisterTxEvent(k)
                raise TimeoutError('waitForEvent timed out')
            except Exception as e:
                return str(e)
            else:
                # check if all events are not None
                if not all([x is True for x in r]):
                    msg = 'One or more peers did not validate the events'
                    raise Exception(msg)
            finally:
                # disconnect channel_event_hubs
                for channel_event_hub in channelEventsHubs.values():
                    channel_event_hub.disconnect()

        ccd = ChaincodeData()
        payload = res['extension']['response']['payload']
        ccd.ParseFromString(payload)

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
                'hash': ccd.data.hash,
                'metadatahash': ccd.data.metadatahash,
            },
            'id': ccd.id,
            'instantiation_policy': instantiation_policy,
        }
        return chaincode

    async def chaincode_invoke(self, requestor, channel_name, peers, args,
                               cc_name, cc_type=CC_TYPE_GOLANG,
                               fcn='invoke', cc_pattern=None,
                               transient_map=None,
                               wait_for_event=False,
                               wait_for_event_timeout=30):
        """
        Invoke chaincode for ledger update

        :param requestor: User role who issue the request
        :param channel_name: the name of the channel to send tx proposal
        :param peers: List of  peer name and/or Peer to install
        :param args (list): arguments (keys and values) for initialization
        :param cc_name: chaincode name
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
        :return: True or False
        """
        target_peers = []
        for peer in peers:
            if isinstance(peer, Peer):
                target_peers.append(peer)
            elif isinstance(peer, str):
                peer = self.get_peer(peer)
                target_peers.append(peer)
            else:
                _logger.error('{} should be a peer name or a Peer instance'.
                              format(peer))

        if not target_peers:
            err_msg = "Failed to query block: no functional peer provided"
            _logger.error(err_msg)
            raise Exception(err_msg)

        tran_prop_req = create_tx_prop_req(
            prop_type=CC_INVOKE,
            cc_name=cc_name,
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

        channel = self.get_channel(channel_name)

        # send proposal
        responses, proposal, header = channel.send_tx_proposal(tx_context,
                                                               target_peers)

        # The proposal return does not contain the transient map
        # because we do not sent it in the real transaction later
        res = await asyncio.gather(*responses)

        # if proposal was not good, return
        if not all([x.response.status == 200 for x in res]):
            return res[0].response.message

        tran_req = utils.build_tx_req((res, proposal, header))
        tx_context_tx = create_tx_context(
            requestor,
            requestor.cryptoSuite,
            tran_req
        )

        # response is a stream
        response = utils.send_transaction(self.orderers, tran_req,
                                          tx_context_tx)

        async for v in response:
            if not v.status == 200:
                return v.message
        # wait for transaction id proposal available in ledger and block
        # commited
        if wait_for_event:
            # wait for chaincode event
            channelEventsHubs = {}
            event_stream = []
            for target_peer in target_peers:
                channel_event_hub = channel.newChannelEventHub(target_peer,
                                                               requestor)
                stream = channel_event_hub.connect()
                event_stream.append(stream)
                # use chaincode event
                if cc_pattern is not None:
                    # unregister when first block got this cc_pattern
                    # with right tx_id
                    # it prevents previous block if batch Timeout is too long
                    reg_id = channel_event_hub.registerChaincodeEvent(
                        cc_name, cc_pattern, tx_id=tx_context.tx_id,
                        unregister=True)
                    channelEventsHubs[reg_id] = channel_event_hub
                # use transaction event
                else:
                    txid = channel_event_hub.registerTxEvent(tx_context.tx_id)
                    channelEventsHubs[txid] = channel_event_hub

            try:
                r = await asyncio.wait_for(asyncio.gather(*event_stream),
                                           timeout=wait_for_event_timeout)
            except asyncio.TimeoutError:
                for k, v in channelEventsHubs.items():
                    if cc_pattern is not None:
                        v.unregisterChaincodeEvent(k)
                    else:
                        v.unregisterTxEvent(k)
                raise TimeoutError('waitForEvent timed out.')
            except Exception as e:
                return str(e)
            else:
                # check if all events are not None
                if not all([x is True for x in r]):
                    msg = 'One or more peers did not validate the events'
                    raise Exception(msg)
            finally:
                # disconnect channel_event_hubs
                for channel_event_hub in channelEventsHubs.values():
                    channel_event_hub.disconnect()

        res = decode_proposal_response_payload(res[0].payload)
        return res['extension']['response']['payload'].decode('utf-8')

    async def chaincode_query(self, requestor, channel_name, peers, args,
                              cc_name, cc_type=CC_TYPE_GOLANG,
                              fcn='query', transient_map=None):
        """
        Query chaincode

        :param requestor: User role who issue the request
        :param channel_name: the name of the channel to send tx proposal
        :param peers: List of  peer name and/or Peer to install
        :param args (list): arguments (keys and values) for initialization
        :param cc_name: chaincode name
        :param cc_type: chaincode type language
        :param fcn: chaincode function
        :param transient_map: transient map
        :return: True or False
        """
        target_peers = []
        for peer in peers:
            if isinstance(peer, Peer):
                target_peers.append(peer)
            elif isinstance(peer, str):
                peer = self.get_peer(peer)
                target_peers.append(peer)
            else:
                _logger.error('{} should be a peer name or a Peer instance'.
                              format(peer))

        if not target_peers:
            err_msg = "Failed to query block: no functional peer provided"
            _logger.error(err_msg)
            raise Exception(err_msg)

        tran_prop_req = create_tx_prop_req(
            prop_type=CC_QUERY,
            cc_name=cc_name,
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

        responses, proposal, header = self.get_channel(
            channel_name).send_tx_proposal(tx_context, target_peers)
        res = await asyncio.gather(*responses)
        tran_req = utils.build_tx_req((res, proposal, header))

        if not all([x.response.status == 200 for x in tran_req.responses]):
            raise Exception(res)

        return res[0].response.payload.decode('utf-8')

    async def query_channels(self, requestor, peers, transient_map=None,
                             decode=True):
        """
        Queries channel name joined by a peer

        :param requestor: User role who issue the request
        :param peers: List of  peer name and/or Peer to install
        :param transient_map: transient map
        :param decode: Decode the response payload
        :return: A `ChannelQueryResponse` or `ProposalResponse`
        """

        target_peers = []
        for peer in peers:
            if isinstance(peer, Peer):
                target_peers.append(peer)
            elif isinstance(peer, str):
                peer = self.get_peer(peer)
                target_peers.append(peer)
            else:
                _logger.error('{} should be a peer name or a Peer instance'.
                              format(peer))

        if not target_peers:
            err_msg = "Failed to query block: no functional peer provided"
            _logger.error(err_msg)
            raise Exception(err_msg)

        request = create_tx_prop_req(
            prop_type=CC_QUERY,
            fcn='GetChannels',
            cc_name='cscc',
            cc_type=CC_TYPE_GOLANG,
            args=[],
            transient_map=transient_map
        )

        tx_context = create_tx_context(requestor, requestor.cryptoSuite,
                                       TXProposalRequest())
        tx_context.tx_prop_req = request

        responses, proposal, header = Channel._send_tx_proposal('', tx_context,
                                                                target_peers)

        res = await asyncio.gather(*responses)
        r = []
        for v in res:
            try:
                if v.response and decode:
                    query_trans = query_pb2.ChannelQueryResponse()
                    query_trans.ParseFromString(v.response.payload)
                    for ch in query_trans.channels:
                        _logger.debug('channel id {}'.format(
                            ch.channel_id))
                    return query_trans
                r.append(v)

            except Exception:
                _logger.error(
                    "Failed to query channel: {}", sys.exc_info()[0])
                raise
            else:
                raise Exception(r)

    async def query_info(self, requestor, channel_name, peers, decode=True):
        """
        Queries information of a channel

        :param requestor: User role who issue the request
        :param channel_name: Name of channel to query
        :param peers: List of  peer name and/or Peer to install
        :param deocode: Decode the response payload
        :return: A `BlockchainInfo` or `ProposalResponse`
        """

        target_peers = []
        for peer in peers:
            if isinstance(peer, Peer):
                target_peers.append(peer)
            elif isinstance(peer, str):
                peer = self.get_peer(peer)
                target_peers.append(peer)
            else:
                _logger.error('{} should be a peer name or a Peer instance'.
                              format(peer))

        if not target_peers:
            err_msg = "Failed to query block: no functional peer provided"
            _logger.error(err_msg)
            raise Exception(err_msg)

        channel = self.get_channel(channel_name)
        tx_context = create_tx_context(requestor, requestor.cryptoSuite,
                                       TXProposalRequest())

        responses, proposal, header = channel.query_info(tx_context,
                                                         target_peers)

        res = await asyncio.gather(*responses)
        r = []
        for v in res:
            try:
                if v.response and decode:
                    chain_info = ledger_pb2.BlockchainInfo()
                    chain_info.ParseFromString(v.response.payload)
                    _logger.debug('response status {}'.format(
                        v.response.status))
                    return chain_info
                r.append(v)

            except Exception:
                _logger.error(
                    "Failed to query info: {}", sys.exc_info()[0])
                raise
            else:
                raise Exception(r)

    async def query_block_by_txid(self, requestor, channel_name,
                                  peers, tx_id, decode=True):
        """
        Queries block by tx id

        :param requestor: User role who issue the request
        :param channel_name: Name of channel to query
        :param peers: List of  peer name and/or Peer to install
        :param tx_id: Transaction ID
        :param deocode: Decode the response payload
        :return: A `BlockDecoder` or `ProposalResponse`
        """

        target_peers = []
        for peer in peers:
            if isinstance(peer, Peer):
                target_peers.append(peer)
            elif isinstance(peer, str):
                peer = self.get_peer(peer)
                target_peers.append(peer)
            else:
                _logger.error('{} should be a peer name or a Peer instance'.
                              format(peer))

        if not target_peers:
            err_msg = "Failed to query block: no functional peer provided"
            _logger.error(err_msg)
            raise Exception(err_msg)

        channel = self.get_channel(channel_name)
        tx_context = create_tx_context(requestor, requestor.cryptoSuite,
                                       TXProposalRequest())

        responses, proposal, header = channel.query_block_by_txid(tx_context,
                                                                  target_peers,
                                                                  tx_id)

        res = await asyncio.gather(*responses)
        r = []
        for v in res:
            try:
                if v.response and decode:
                    _logger.debug(
                        'response status {}'.format(v.response.status))
                    block = BlockDecoder().decode(v.response.payload)
                    _logger.debug('looking at block {}'.format(
                        block['header']['number']))
                    return block
                r.append(v)

            except Exception:
                _logger.error(
                    "Failed to query block: {}", sys.exc_info()[0])
                raise
            else:
                raise Exception(r)

    async def query_block_by_hash(self, requestor, channel_name,
                                  peers, block_hash, decode=True):
        """
        Queries block by hash

        :param requestor: User role who issue the request
        :param channel_name: Name of channel to query
        :param peers: List of  peer name and/or Peer to install
        :param block_hash: Hash of a block
        :param deocode: Decode the response payload
        :return: A `BlockDecoder` or `ProposalResponse`
        """

        target_peers = []
        for peer in peers:
            if isinstance(peer, Peer):
                target_peers.append(peer)
            elif isinstance(peer, str):
                peer = self.get_peer(peer)
                target_peers.append(peer)
            else:
                _logger.error('{} should be a peer name or a Peer instance'.
                              format(peer))

        if not target_peers:
            err_msg = "Failed to query block: no functional peer provided"
            _logger.error(err_msg)
            raise Exception(err_msg)

        channel = self.get_channel(channel_name)
        tx_context = create_tx_context(requestor, requestor.cryptoSuite,
                                       TXProposalRequest())

        responses, proposal, header = channel.query_block_by_hash(tx_context,
                                                                  target_peers,
                                                                  block_hash)

        res = await asyncio.gather(*responses)
        r = []
        for v in res:
            try:
                if v.response and decode:
                    _logger.debug('response status {}'.format(
                        v.response.status))
                    block = BlockDecoder().decode(v.response.payload)
                    _logger.debug('looking at block {}'.format(
                        block['header']['number']))
                    return block
                r.append(v)

            except Exception:
                _logger.error(
                    "Failed to query block: {}", sys.exc_info()[0])
                raise
            else:
                raise Exception(r)

    async def query_block(self, requestor, channel_name,
                          peers, block_number, decode=True):
        """
        Queries block by number

        :param requestor: User role who issue the request
        :param channel_name: name of channel to query
        :param peers: List of  peer name and/or Peer to install
        :param block_number: Number of a block
        :param deocode: Decode the response payload
        :return: A `BlockDecoder` or `ProposalResponse`
        """

        target_peers = []
        for peer in peers:
            if isinstance(peer, Peer):
                target_peers.append(peer)
            elif isinstance(peer, str):
                peer = self.get_peer(peer)
                target_peers.append(peer)
            else:
                _logger.error('{} should be a peer name or a Peer instance'.
                              format(peer))

        if not target_peers:
            err_msg = "Failed to query block: no functional peer provided"
            _logger.error(err_msg)
            raise Exception(err_msg)

        channel = self.get_channel(channel_name)
        tx_context = create_tx_context(requestor, requestor.cryptoSuite,
                                       TXProposalRequest())

        responses, proposal, header = channel.query_block(tx_context,
                                                          target_peers,
                                                          block_number)

        res = await asyncio.gather(*responses)
        r = []
        for v in res:
            try:
                if v.response and decode:
                    _logger.debug('response status {}'.format(
                        v.response.status))
                    block = BlockDecoder().decode(v.response.payload)
                    _logger.debug('looking at block {}'.format(
                        block['header']['number']))
                    return block
                r.append(v)

            except Exception:
                _logger.error(
                    "Failed to query block: {}", sys.exc_info()[0])
                raise
            else:
                raise Exception(r)

    async def query_transaction(self, requestor, channel_name,
                                peers, tx_id, decode=True):
        """
        Queries block by number

        :param requestor: User role who issue the request
        :param channel_name: name of channel to query
        :param peers: List of  peer name and/or Peer to install
        :param tx_id: The id of the transaction
        :param decode: Decode the response payload
        :return:  A `BlockDecoder` or `ProposalResponse`
        """

        target_peers = []
        for peer in peers:
            if isinstance(peer, Peer):
                target_peers.append(peer)
            elif isinstance(peer, str):
                peer = self.get_peer(peer)
                target_peers.append(peer)
            else:
                _logger.error('{} should be a peer name or a Peer instance'.
                              format(peer))

        if not target_peers:
            err_msg = "Failed to query block: no functional peer provided"
            _logger.error(err_msg)
            raise Exception(err_msg)

        channel = self.get_channel(channel_name)
        tx_context = create_tx_context(requestor, requestor.cryptoSuite,
                                       TXProposalRequest())

        responses, proposal, header = channel.query_transaction(tx_context,
                                                                target_peers,
                                                                tx_id)

        res = await asyncio.gather(*responses)
        r = []
        for v in res:
            try:
                if v.response and decode:
                    _logger.debug('response status {}'.format(
                        v.response.status))
                    process_trans = BlockDecoder().decode_transaction(
                        v.response.payload)
                    return process_trans

                r.append(v)

            except Exception:
                _logger.error(
                    "Failed to query block: {}", sys.exc_info()[0])
                raise
            else:
                raise Exception(r)

    async def query_instantiated_chaincodes(self, requestor, channel_name,
                                            peers, transient_map=None,
                                            decode=True):
        """
        Queries instantiated chaincode

        :param requestor: User role who issue the request
        :param channel_name: name of channel to query
        :param peers: Names or Instance of the peers to query
        :param transient_map: transient map
        :param decode: Decode the response payload
        :return: A `ChaincodeQueryResponse` or `ProposalResponse`
        """
        target_peers = []
        for _peer in peers:
            if isinstance(_peer, Peer):
                target_peers.append(_peer)
            elif isinstance(_peer, str):
                peer = self.get_peer(_peer)
                if peer is not None:
                    target_peers.append(peer)
                else:
                    err_msg = f'Cannot find peer with name {_peer}'
                    _logger.error(err_msg)
                    raise Exception(err_msg)
            else:
                err_msg = f'{_peer} should be a peer name or a Peer instance'
                _logger.error(err_msg)
                raise Exception(err_msg)

        if not target_peers:
            err_msg = "Failed to query block: no functional peer provided"
            _logger.error(err_msg)
            raise Exception(err_msg)

        channel = self.get_channel(channel_name)
        tx_context = create_tx_context(requestor, requestor.cryptoSuite,
                                       TXProposalRequest())

        responses, proposal, header = channel.query_instantiated_chaincodes(
            tx_context, target_peers, transient_map=transient_map)

        responses = await asyncio.gather(*responses)

        results = []
        for pplResponse in responses:
            try:
                if pplResponse.response and decode:
                    query_trans = query_pb2.ChaincodeQueryResponse()
                    query_trans.ParseFromString(pplResponse.response.payload)
                    for cc in query_trans.chaincodes:
                        _logger.debug('cc name {}, version {}, path {}'.format(
                            cc.name, cc.version, cc.path))
                    results.append(query_trans)
                else:
                    results.append(pplResponse)

            except Exception:
                _logger.error("Failed to query instantiated chaincodes",
                              sys.exc_info()[0])
                raise

        return results

    async def query_installed_chaincodes(self, requestor, peers,
                                         transient_map=None, decode=True):
        """
        Queries installed chaincode, returns all chaincodes installed on a peer

        :param requestor: User role who issue the request
        :param peers: Names or Instance of the peers to query
        :param transient_map: transient map
        :param decode: Decode the response payload
        :return: A `ChaincodeQueryResponse` or `ProposalResponse`
        """
        target_peers = []
        for peer in peers:
            if isinstance(peer, Peer):
                target_peers.append(peer)
            elif isinstance(peer, str):
                peer = self.get_peer(peer)
                target_peers.append(peer)
            else:
                _logger.error('{} should be a peer name or a Peer instance'.
                              format(peer))

        if not target_peers:
            err_msg = "Failed to query block: no functional peer provided"
            _logger.error(err_msg)
            raise Exception(err_msg)

        request = create_tx_prop_req(
            prop_type=CC_QUERY,
            fcn='getinstalledchaincodes',
            cc_name='lscc',
            cc_type=CC_TYPE_GOLANG,
            args=[],
            transient_map=transient_map
        )

        tx_context = create_tx_context(requestor, requestor.cryptoSuite,
                                       TXProposalRequest())
        tx_context.tx_prop_req = request

        responses, proposal, header = Channel._send_tx_proposal('', tx_context,
                                                                target_peers)

        responses = await asyncio.gather(*responses)

        results = []
        for pplResponse in responses:
            try:
                if pplResponse.response and decode:
                    query_trans = query_pb2.ChaincodeQueryResponse()
                    query_trans.ParseFromString(pplResponse.response.payload)
                    for cc in query_trans.chaincodes:
                        _logger.debug('cc name {}, version {}, path {}'.format(
                            cc.name, cc.version, cc.path))
                    results.append(query_trans)
                else:
                    results.append(pplResponse)

            except Exception:
                _logger.error("Failed to query installed chaincodes",
                              sys.exc_info()[0])
                raise

        return results

    async def query_peers(self, requestor, peer, channel=None,
                          local=True, decode=True):
        """Queries peers with discovery api

        :param requestor: User role who issue the request
        :param peer: Name or Instance  of the peer to send request
        :param crypto: crypto method to sign the request
        :param deocode: Decode the response payload
        :return result: a nested dict of query result
        """

        if local:
            dummy_channel = self.new_channel("discover-local")
        else:
            if channel is None:
                raise Exception("Channel name must be provided \
                 if local is False")
            dummy_channel = self.new_channel(channel)

        if isinstance(peer, Peer):
            target_peer = peer
        elif isinstance(peer, str):
            target_peer = self.get_peer(peer)
        else:
            err_msg = 'Failed to query block: no functional peer provided'
            raise Exception(err_msg)

        response = await dummy_channel._discovery(requestor, target_peer,
                                                  local=local)

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
                        results['local_peers'] = \
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
                peers_by_org[mspid]['peers'] = decode_fabric_peers_info(
                    q_members.peers_by_org[mspid].peers)

        return peers_by_org
