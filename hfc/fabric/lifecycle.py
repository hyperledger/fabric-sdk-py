# SPDX-License-Identifier: Apache-2.0

import asyncio

from google.protobuf.json_format import MessageToDict

from hfc.fabric.base_chaincode import BaseChaincode
from hfc.fabric.channel.channel import Channel
from hfc.fabric.transaction.tx_context import create_tx_context
from hfc.fabric.transaction.tx_proposal_request import create_tx_prop_req, TXProposalRequest
from hfc.protos.peer import policy_pb2
from hfc.protos.peer.lifecycle import lifecycle_pb2 as lp
from hfc.util import utils
from hfc.util.archive import lifecycle_package, package_chaincode
from hfc.util.collection_config import build_collection_config_proto
from hfc.util.consts import CC_QUERY, CC_TYPE_GOLANG, SUCCESS_STATUS, LC_INSTALL, LIFECYCLE_CC, LC_APPROVE_FOR_MY_ORG, \
    LC_COMMIT, LC_QUERY_INSTALLED, LC_QUERY_APPROVED, LC_QUERY_CC_DEFINITION, LC_QUERY_CC_DEFINITIONS, \
    DEFAULT_WAIT_FOR_EVENT_TIMEOUT
from hfc.util.policies import s2d, build_policy
from hfc.util.utils import proto_str


class Lifecycle(BaseChaincode):
    def __init__(self, client, cc_name=""):
        super().__init__(cc_name)
        self._client = client

    def parse_proposal_res(self, responses, response_type=None, decode=True):
        results = []
        for entry in responses:
            if entry.response.status != SUCCESS_STATUS:
                raise RuntimeError(entry.response.message)
            if entry.response.payload and decode and response_type is not None:
                results.append(MessageToDict(response_type.FromString(entry.response.payload)))
            else:
                results.append(entry.response.payload)
        return results

    def package(self, source_path, label, dest_path=None, cc_type=CC_TYPE_GOLANG):
        """
        Package chaincode

        :param source_path: Path to the chaincode
        :param label: The package label contains a human-readable description of the package
        :param dest_path: Path with file name where package would be stored
        :param cc_type: Language the chaincode is written in (default "golang")
        :return: bytes of the packaged chaincode
        """
        metadata = {
            "path": source_path,
            "type": cc_type,
            "label": label
        }
        tar_bytes = lifecycle_package(package_chaincode(source_path, cc_type), metadata)
        if dest_path:
            with open(dest_path, "wb") as file:
                file.write(tar_bytes)
        return tar_bytes

    async def install(self, requestor, peers, packaged_cc=None):
        """
        Install chaincode to given peers by requestor role

        :param requestor: User role who issue the request
        :param peers: List of  peer name and/or Peer to install
        :param packaged_cc: packaged chaincode
        :return: A dict representation of `InstallChaincodeResult`
        """
        target_peers = self._client.get_target_peers(peers)

        tx_context = create_tx_context(requestor, requestor.cryptoSuite, TXProposalRequest())

        install_args = lp.InstallChaincodeArgs()
        install_args.chaincode_install_package = packaged_cc

        responses, proposal, header = utils.send_proposal(tx_context, target_peers, install_args, LC_INSTALL,
                                                          LIFECYCLE_CC)
        res = await asyncio.gather(*responses)
        return self.parse_proposal_res(res, lp.InstallChaincodeResult)

    async def approve_for_my_org(self, requestor, peers, channel, cc_version, package_id, signature_policy=None,
                                 channel_config_policy=None, init_required=False, sequence=1, collections_config=None,
                                 endorsement_plugin="", validation_plugin="", wait_for_event=True,
                                 wait_for_event_timeout=DEFAULT_WAIT_FOR_EVENT_TIMEOUT):
        """
        Approve chaincode definition for current org

        :param requestor: User role who issue the request
        :param peers: List of  peer name and/or Peer to install
        :param channel: channel name
        :param cc_version: chaincode version
        :param package_id: The identifier of the chaincode install package
        :param signature_policy: The endorsement policy specified as a signature policy
        :param channel_config_policy: The endorsement policy specified as a channel config policy reference
        :param init_required: Whether the chaincode requires invoking 'init'
        :param sequence: The sequence number of the chaincode definition for the channel
        :param collections_config: collection configuration
        :param validation_plugin: The name of the validation plugin to be used for this chaincode
        :param endorsement_plugin: The name of the endorsement plugin to be used for this chaincode
        :param wait_for_event: Whether to wait for the event from each peer's deliver filtered service signifying
         that the transaction has been committed successfully (default true)
        :param wait_for_event_timeout: Time to wait for the event from each peer
        """
        return await self.chaincode_definition_operation(requestor, peers, channel, cc_version, package_id=package_id,
                                                         signature_policy=signature_policy,
                                                         channel_config_policy=channel_config_policy,
                                                         init_required=init_required, sequence=sequence,
                                                         collections_config=collections_config,
                                                         validation_plugin=validation_plugin,
                                                         endorsement_plugin=endorsement_plugin,
                                                         wait_for_event=wait_for_event,
                                                         wait_for_event_timeout=wait_for_event_timeout)

    async def commit_definition(self, requestor, peers, channel, cc_version, signature_policy=None,
                                channel_config_policy=None, init_required=False, sequence=1, collections_config=None,
                                endorsement_plugin="", validation_plugin="", wait_for_event=True,
                                wait_for_event_timeout=DEFAULT_WAIT_FOR_EVENT_TIMEOUT):
        """
        Commit the chaincode definition on the channel.

        :param requestor: User role who issue the request
        :param peers: List of  peer name and/or Peer to install
        :param channel: channel name
        :param cc_version: chaincode version
        :param signature_policy: The endorsement policy specified as a signature policy
        :param channel_config_policy: The endorsement policy specified as a channel config policy reference
        :param init_required: Whether the chaincode requires invoking 'init'
        :param sequence: The sequence number of the chaincode definition for the channel
        :param collections_config: collection configuration
        :param validation_plugin: The name of the validation plugin to be used for this chaincode
        :param endorsement_plugin: The name of the endorsement plugin to be used for this chaincode
        :param wait_for_event: Whether to wait for the event from each peer's deliver filtered service signifying
         that the transaction has been committed successfully (default true)
        :param wait_for_event_timeout: Time to wait for the event from each peer
        """
        return await self.chaincode_definition_operation(requestor, peers, channel, cc_version, package_id=None,
                                                         signature_policy=signature_policy,
                                                         channel_config_policy=channel_config_policy,
                                                         init_required=init_required, sequence=sequence,
                                                         collections_config=collections_config,
                                                         validation_plugin=validation_plugin,
                                                         endorsement_plugin=endorsement_plugin,
                                                         wait_for_event=wait_for_event,
                                                         wait_for_event_timeout=wait_for_event_timeout)

    async def chaincode_definition_operation(self, requestor, peers, channel_name, cc_version, package_id=None,
                                             signature_policy=None, channel_config_policy=None, init_required=False,
                                             sequence=1, collections_config=None, endorsement_plugin="",
                                             validation_plugin="", wait_for_event=False,
                                             wait_for_event_timeout=DEFAULT_WAIT_FOR_EVENT_TIMEOUT):
        target_peers = self._client.get_target_peers(peers)

        tx_context = create_tx_context(requestor, requestor.cryptoSuite, TXProposalRequest())

        application_policy = policy_pb2.ApplicationPolicy()
        if signature_policy:
            application_policy.signature_policy.CopyFrom(build_policy(s2d().parse(signature_policy), returnProto=True))
        elif channel_config_policy:
            application_policy.channel_config_policy_reference = proto_str(channel_config_policy)

        # package_if needed only for approval operation and so can be used to differentiate between operations
        args = lp.ApproveChaincodeDefinitionForMyOrgArgs() if package_id else lp.CommitChaincodeDefinitionArgs()
        args.name = proto_str(self._name)
        args.version = proto_str(cc_version)
        args.sequence = sequence
        args.endorsement_plugin = endorsement_plugin
        args.validation_plugin = validation_plugin
        args.validation_parameter = application_policy.SerializeToString()
        method = LC_COMMIT
        if package_id:
            method = LC_APPROVE_FOR_MY_ORG
            args.source.local_package.package_id = proto_str(package_id)
        args.init_required = init_required
        if collections_config is not None:
            args.collections.collections = build_collection_config_proto(collections_config)

        responses, proposal, header = utils.send_proposal(tx_context, target_peers, args, method, LIFECYCLE_CC,
                                                          channel_name)
        res = await asyncio.gather(*responses)
        self.parse_proposal_res(res)

        tran_req = utils.build_tx_req((res, proposal, header))

        responses = utils.send_transaction(self._client.orderers, tran_req, tx_context)
        # responses will be a stream
        async for v in responses:
            if not v.status == SUCCESS_STATUS:
                raise RuntimeError(v.message)

        if wait_for_event:
            channel = self._client.get_channel(channel_name)
            await self.wait_for_event(tx_context, target_peers, channel, requestor, None, wait_for_event_timeout)
        # we don't return anything
        # because responses of ApproveChaincodeDefinitionForMyOrg and CommitChaincodeDefinition are empty
        # see ApproveChaincodeDefinitionForMyOrgResult and CommitChaincodeDefinitionResult

    async def query_lifecycle_data(self, requestor, peers, args, method, channel_name=None, response_type=None,
                                   decode=True):
        target_peers = self._client.get_target_peers(peers)

        request = create_tx_prop_req(
            prop_type=CC_QUERY,
            fcn=method,
            cc_name=LIFECYCLE_CC,
            cc_type=CC_TYPE_GOLANG,
            args=[args.SerializeToString()]
        )

        tx_context = create_tx_context(requestor, requestor.cryptoSuite, TXProposalRequest())
        tx_context.tx_prop_req = request

        responses, proposal, header = Channel._send_tx_proposal("" if channel_name is None else channel_name,
                                                                tx_context, target_peers)

        responses = await asyncio.gather(*responses)
        return self.parse_proposal_res(responses, response_type, decode)

    async def query_installed_chaincodes(self, requestor, peers, decode=True):
        """
        Queries installed chaincode, returns all chaincodes installed on a peer

        :param requestor: User role who issue the request
        :param peers: Names or Instance of the peers to query
        :param decode: Decode the response payload
        :return: A dict representation of `QueryInstalledChaincodesResult`
        """
        return await self.query_lifecycle_data(requestor, peers, lp.QueryInstalledChaincodesArgs(),
                                               LC_QUERY_INSTALLED, None, lp.QueryInstalledChaincodesResult, decode)

    async def query_approved_chaincodes(self, requestor, peers, channel, cc_name, sequence=1, decode=True):
        """
        Queries approved chaincode, returns all chaincodes installed on a peer

        :param requestor: User role who issue the request
        :param peers: Names or Instance of the peers to query
        :param channel: Channel name
        :param cc_name: Chaincode name
        :param sequence: The sequence number of the chaincode definition for the channel
        :param decode: Decode the response payload
        :return: A dict representation of `QueryApprovedChaincodeDefinitionResult`
        """
        args = lp.QueryApprovedChaincodeDefinitionArgs()
        args.name = cc_name
        args.sequence = sequence

        return await self.query_lifecycle_data(requestor, peers, args, LC_QUERY_APPROVED, channel,
                                               lp.QueryApprovedChaincodeDefinitionResult, decode)

    async def query_committed_chaincodes(self, requestor, peers, channel, cc_name=None, decode=True):
        """
        Queries committed chaincode, returns all chaincodes installed on a peer

        :param requestor: User role who issue the request
        :param peers: Names or Instance of the peers to query
        :param channel: Channel name
        :param cc_name: Chaincode name
        :param decode: Decode the response payload
       :return: A dict representation of `QueryChaincodeDefinitionsResult` or `QueryChaincodeDefinitionResult`
        """
        args = lp.QueryChaincodeDefinitionsArgs()
        method = LC_QUERY_CC_DEFINITIONS
        response_type = lp.QueryChaincodeDefinitionsResult

        if cc_name:
            method = LC_QUERY_CC_DEFINITION
            response_type = lp.QueryChaincodeDefinitionResult
            args = lp.QueryChaincodeDefinitionArgs()
            args.name = cc_name

        return await self.query_lifecycle_data(requestor, peers, args, method, channel, response_type, decode)
