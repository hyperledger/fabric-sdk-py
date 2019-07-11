# Copyright sudheesh.info 2018 All Rights Reserved.
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
import binascii
import datetime
from base64 import b64encode
from datetime import timezone

# Import required Peer Protos
from hfc.protos.peer import chaincode_event_pb2
from hfc.protos.peer import transaction_pb2
from hfc.protos.peer import proposal_pb2
from hfc.protos.peer import proposal_response_pb2
from hfc.protos.peer import configuration_pb2 as peer_configuration_pb2
from hfc.protos.peer import events_pb2

# Import required MSP Protos
from hfc.protos.msp import msp_principal_pb2
from hfc.protos.msp import msp_config_pb2
from hfc.protos.msp import identities_pb2

# Import required Common Protos
from hfc.protos.common import common_pb2
from hfc.protos.common import configtx_pb2
from hfc.protos.common import policies_pb2
from hfc.protos.common import configuration_pb2 as common_configuration_pb2

# Import required Orderer Protos
from hfc.protos.orderer import configuration_pb2 as orderer_configuration_pb2

# Import required Ledger Protos
from hfc.protos.ledger.rwset import rwset_pb2
from hfc.protos.ledger.rwset.kvrwset import kv_rwset_pb2

# Import required Gossip Protos
from hfc.protos.gossip import message_pb2

_logger = logging.getLogger(__name__ + ".block_decoder")


class BlockDecoder(object):
    """
        An object of a fully decoded protobuf message "Block"
    """

    @staticmethod
    def decode(block_bytes):
        """
        Constructs a JSON Object containing all decoded values from
        protobuf encoded `Block` bytes.

        Args:
            block_bytes (bytes): Block instance

        Returns: Dictionary containing decoded Block instance.
        """
        block = {}
        try:
            proto_block = common_pb2.Block()
            proto_block.ParseFromString(block_bytes)
            block['header'] = decode_block_header(proto_block.header)
            block['data'] = decode_block_data(proto_block.data, True)
            block['metadata'] = decode_block_metadata(proto_block.metadata)
        except Exception as e:
            raise ValueError("BlockDecoder :: decode failed", e)
        return block

    @staticmethod
    def decode_transaction(processed_tx_bytes):
        """
        Decodes a transaction proto and constructs a deserialized object

        Args:
            processed_tx_bytes {str} -- Binary content of tx

        Returns: Dictionary containing tx block information

        Raises:
            ValueError -- If data is not passed to the method
        """
        if not processed_tx_bytes:
            raise ValueError("BlockDecoder :: decode_transaction \
                doesnot have processed transaction bytes")
        processed_tx = {}
        pr_processed_tx = transaction_pb2.ProcessedTransaction()
        pr_processed_tx.ParseFromString(processed_tx_bytes)
        if pr_processed_tx:
            processed_tx['validation_code'] = \
                pr_processed_tx.validationCode
            processed_tx['transaction_envelope'] = \
                decode_block_data_envelope(pr_processed_tx.transactionEnvelope)
        return processed_tx


class FilteredBlockDecoder(object):
    """
        An object of a fully decoded protobuf message "FilteredBlock"
    """

    @staticmethod
    def decode(block_bytes):
        """
        Constructs a JSON Object containing all decoded values from
        protobuf encoded `FilteredBlock` bytes.

        Args:
            block_bytes (bytes): FilteredBlock instance

        Returns: Dictionary containing decoded Filtered Block instance.
        """

        filtered_block = {}

        try:
            proto_block = events_pb2.FilteredBlock()
            proto_block.ParseFromString(block_bytes)
            filtered_block['channel_id'] = proto_block.channel_id
            filtered_block['number'] = proto_block.number
            filtered_block['filtered_transactions'] = []
            fts = proto_block.filtered_transactions

            for ft in fts:
                code = tx_validation_code.get(ft.tx_validation_code,
                                              'UNKNOWN_VALIDATION_CODE')
                ft_decoded = {
                    'txid': ft.txid,
                    'type': HeaderType.convert_to_string(ft.type),
                    'tx_validation_code': code
                }

                if hasattr(ft, 'transaction_actions'):
                    for ca in ft.transaction_actions.chaincode_actions:
                        ft_decoded[
                            'transaction_actions'] = decode_chaincode_events(
                            ca.chaincode_event.SerializeToString())
                filtered_block['filtered_transactions'].append(ft_decoded)

        except Exception as e:
            raise ValueError("FilteredBlockDecoder :: decode failed", e)
        return filtered_block


tx_validation_code = {
    0: 'VALID',
    1: 'NIL_ENVELOPE',
    2: 'BAD_PAYLOAD',
    3: 'BAD_COMMON_HEADER',
    4: 'BAD_CREATOR_SIGNATURE',
    5: 'INVALID_ENDORSER_TRANSACTION',
    6: 'INVALID_CONFIG_TRANSACTION',
    7: 'UNSUPPORTED_TX_PAYLOAD',
    8: 'BAD_PROPOSAL_TXID',
    9: 'DUPLICATE_TXID',
    10: 'ENDORSEMENT_POLICY_FAILURE',
    11: 'MVCC_READ_CONFLICT',
    12: 'PHANTOM_READ_CONFLICT',
    13: 'UNKNOWN_TX_TYPE',
    14: 'TARGET_CHAIN_NOT_FOUND',
    15: 'MARSHAL_TX_ERROR',
    16: 'NIL_TXACTION',
    17: 'EXPIRED_CHAINCODE',
    18: 'CHAINCODE_VERSION_CONFLICT',
    19: 'BAD_HEADER_EXTENSION',
    20: 'BAD_CHANNEL_HEADER',
    21: 'BAD_RESPONSE_PAYLOAD',
    22: 'BAD_RWSET',
    23: 'ILLEGAL_WRITESET',
    24: 'INVALID_WRITESET',
    254: 'NOT_VALIDATED',
    255: 'INVALID_OTHER_REASON',
}

type_as_string = {
    0: 'MESSAGE',  # Used for messages which are signed but opaque
    1: 'CONFIG',  # Used for messages which express the channel config
    2: 'CONFIG_UPDATE',  # Used for transactions that update the channel config
    3: 'ENDORSER_TRANSACTION',  # Used to submit endorser based transactions
    4: 'ORDERER_TRANSACTION',  # Used internally by the orderer for management
    5: 'DELIVER_SEEK_INFO',  # Used to instruct the Deliver API to seek
    6: 'CHAINCODE_PACKAGE'  # Used to packaging chaincode artifacts for install
}

implicit_metapolicy_rule = ['ANY', 'ALL', 'MAJORITY']

policy_policy_type = ['UNKNOWN', 'SIGNATURE', 'MSP', 'IMPLICIT_META']


class HeaderType(object):
    """
        HeaderType class having decodePayload and convertToString methods
    """

    @staticmethod
    def convert_to_string(type_value):
        return type_as_string.get(type_value, 'UNKNOWN_TYPE')

    @staticmethod
    def decode_payload_based_on_type(proto_data, type_value):
        result = None
        if type_value == 1:
            result = decode_config_envelope(proto_data)
        elif type_value == 2:
            result = decode_config_update_envelope(proto_data)
        elif type_value == 3:
            result = decode_endorser_transaction(proto_data)
        else:
            msg = f'HeaderType :: decode_payload found a header type of' \
                f' {type_value} :: {HeaderType.convert_to_string(type_value)}'
            _logger.debug(msg)
            result = {}
        return result


def decode_block_header(proto_block_header):
    """
    Decodes the header of Block

    Args:
        proto_block_header (str): Block Header proto

    Returns: Decoded BlockHeader inside Block instance.
    """
    block_header = {}
    block_header['number'] = proto_block_header.number
    block_header['previous_hash'] = \
        binascii.b2a_hex(proto_block_header.previous_hash)
    block_header['data_hash'] = binascii.b2a_hex(proto_block_header.data_hash)
    return block_header


def decode_block_data(proto_block_data, not_proto=False):
    """Decodes the data of Block.

    Args:
        proto_block_data (str): Block Data proto.
        not_proto (bool): Boolean for if proto.

    Returns: deserialized block_data
    """
    data = {}
    data['data'] = []
    for i in proto_block_data.data:
        proto_envelope = None
        if not_proto:
            proto_envelope = common_pb2.Envelope()
            proto_envelope.ParseFromString(i)
        if proto_envelope:
            envelope = decode_block_data_envelope(proto_envelope)
            data['data'].append(envelope)
    return data


def decode_block_metadata(proto_block_metadata):
    """Decodes block metadata from block

    Args:
        proto_block_metadata (bytes): Block metadata proto content

    Returns: deserialized metadata contents
    """
    metadata = {}
    metadata['metadata'] = []
    if proto_block_metadata and proto_block_metadata.metadata:
        signatures = decode_metadata_signatures(
            proto_block_metadata.metadata[common_pb2.SIGNATURES])
        metadata['metadata'].append(signatures)

        last_config = decode_last_config_sequence_number(
            proto_block_metadata.metadata[common_pb2.LAST_CONFIG])
        metadata['metadata'].append(last_config)

        transaction_filter = decode_transaction_filter(
            proto_block_metadata.metadata[common_pb2.TRANSACTIONS_FILTER])
        metadata['metadata'].append(transaction_filter)

    return metadata


def decode_block_data_envelope(proto_envelope):
    """Decodes the envelope contents of Block

    Args:
        proto_envelope (str): Envelope proto

    Returns: deserialized block envelope
    """
    envelope = {}
    envelope['signature'] = proto_envelope.signature
    envelope['payload'] = {}
    proto_payload = common_pb2.Payload()
    proto_payload.ParseFromString(proto_envelope.payload)
    envelope['payload']['header'] = decode_header(proto_payload.header)
    envelope['payload']['data'] = \
        HeaderType.decode_payload_based_on_type(
            proto_payload.data,
            envelope['payload']['header']['channel_header']['type'])
    envelope['payload']['header']['channel_header']['type_string'] = \
        HeaderType.convert_to_string(
            envelope['payload']['header']['channel_header']['type'])
    return envelope


def decode_header(proto_header):
    """Decodes the Payload header in envelope

    Args:
        proto_header (str): Envelope Payload

    Returns: deserialized envelope header
    """
    header = {}
    header['channel_header'] = \
        decode_channel_header(proto_header.channel_header)
    header['signature_header'] = \
        decode_signature_header(proto_header.signature_header)
    return header


def decode_channel_header(header_bytes):
    """Decodes channel header for Payload channel header

    Args:
        header_bytes (str): Bytes channel header

    Return: deserialized payload channel_header
    """
    channel_header = {}
    proto_channel_header = common_pb2.ChannelHeader()
    proto_channel_header.ParseFromString(header_bytes)
    channel_header['type'] = proto_channel_header.type
    channel_header['version'] = decode_version(proto_channel_header.version)
    channel_header['timestamp'] = \
        timestamp_to_date(proto_channel_header.timestamp)
    channel_header['channel_id'] = proto_channel_header.channel_id
    channel_header['tx_id'] = proto_channel_header.tx_id
    channel_header['epoch'] = proto_channel_header.epoch
    channel_header['extension'] = proto_channel_header.extension
    return channel_header


def timestamp_to_date(timestamp):
    """Converts timestamp to current date

    Args:
        timestamp: Timestamp value

    Returns: String formatted date in %Y-%m-%d %H:%M:%S
    """
    if not timestamp:
        return None
    # WARNING: this will break on Windows because of the fromtimestamp()
    # restriction of values by C `localtime()` or `gmtime()` calls.
    millis = timestamp.seconds * 1000 + timestamp.nanos / 1000000
    date = datetime.datetime.fromtimestamp(millis / 1e3, tz=timezone.utc)
    return date.strftime("%Y-%m-%d %H:%M:%S")


def decode_version(version_long):
    """Takes version proto object and returns version

    Args:
        version_long

    Returns: integer value of version_long
    """
    return int(version_long)


def decode_signature_header(signature_header_bytes):
    """Decode signature header

    Args:
        signature_header_bytes: signature header bytes

    Returns: deserialized signature_header
    """
    signature_header = {}
    proto_signature_header = common_pb2.SignatureHeader()
    proto_signature_header.ParseFromString(signature_header_bytes)
    signature_header['creator'] = \
        decode_identity(proto_signature_header.creator)
    signature_header['nonce'] = \
        binascii.b2a_hex(proto_signature_header.nonce)
    return signature_header


def decode_identity(id_bytes):
    """Decodes identity

    Args:
        id_bytes: byte of identity

    Returns: deserialized identity
    """
    identity = {}
    try:
        proto_identity = identities_pb2.SerializedIdentity()
        proto_identity.ParseFromString(id_bytes)
        identity['mspid'] = proto_identity.mspid
        identity['id_bytes'] = proto_identity.id_bytes.decode()
    except Exception as e:
        raise ValueError("BlockDecoder :: decode_identiy failed", e)
    return identity


def decode_metadata_signatures(metadata_bytes):
    """Decodes metadata signature from bytes

    Args:
        metadata_bytes (str): Metadata object proto

    Returns: deserialized Metadata blocks
    """
    metadata = {}
    proto_metadata = common_pb2.Metadata()
    proto_metadata.ParseFromString(metadata_bytes)
    metadata['value'] = proto_metadata.value
    metadata['signatures'] = \
        decode_metadata_value_signatures(proto_metadata.signatures)
    return metadata


def decode_metadata_value_signatures(proto_meta_signatures):
    """Decodes all signatures in metadata values

    Args:
        proto_meta_signatures (list(str)): List of value objects

    Returns: deserialized list of signatures from metadata values
    """
    signatures = []
    if proto_meta_signatures:
        for signature in proto_meta_signatures:
            metadata_signature = {}
            metadata_signature['signature_header'] = \
                decode_signature_header(signature.signature_header)
            metadata_signature['signature'] = signature.signature
            signatures.append(metadata_signature)
    return signatures


def decode_last_config_sequence_number(metadata_bytes):
    """Decodes last configuration and index for sequence number

    Args:
        metadata_bytes (str): encoded content for sequence number

    Returns: deserialized dictionary of config sequence number
    """
    last_config = {
        'value': {
            'index': 0,
            'signatures': []
        }
    }
    if metadata_bytes:
        proto_metadata = common_pb2.Metadata()
        proto_metadata.ParseFromString(metadata_bytes)
        proto_last_config = common_pb2.LastConfig()
        proto_last_config.ParseFromString(proto_metadata.value)
        last_config['value']['index'] = proto_last_config.index
        last_config['signatures'] = \
            decode_metadata_value_signatures(proto_metadata.signatures)
    return last_config


def decode_transaction_filter(metadata_bytes):
    """Decodes transaction filter from metadata bytes

    Args:
        metadata_bytes (str): Encoded list of transaction filters

    Returns: decoded transaction_filter list
    """
    transaction_filter = []
    if not metadata_bytes:
        return None

    for i in metadata_bytes:
        transaction_filter.append(int(i))
    return transaction_filter


def decode_endorser_transaction(trans_bytes):
    """Decodes

    Args:
        trans_bytes {[type]}: Serialized endorser transaction bytes

    Returns: deserialized dictionary of endorser transaction data
    """
    data = {}
    if trans_bytes:
        transaction = transaction_pb2.Transaction()
        transaction.ParseFromString(trans_bytes)
        data['actions'] = []
        if transaction and transaction.actions:
            for tx_action in transaction.actions:
                action = {}
                action['header'] = \
                    decode_signature_header(tx_action.header)
                action['payload'] = \
                    decode_chaincode_action_payload(tx_action.payload)
                data['actions'].append(action)
    return data


def decode_config_envelope(config_envelope_bytes):
    """Decodes configuration envelope

    Args:
        config_envelope_bytes: byte of config envelope

    Returns: deserialized config envelope
    """
    config_envelope = {}
    proto_config_envelope = configtx_pb2.ConfigEnvelope()
    proto_config_envelope.ParseFromString(config_envelope_bytes)
    config_envelope['config'] = decode_config(proto_config_envelope.config)
    config_envelope['last_update'] = {}
    proto_last_update = proto_config_envelope.last_update
    if proto_last_update:
        config_envelope['last_update']['payload'] = {}
        proto_payload = common_pb2.Payload()
        proto_payload.ParseFromString(proto_last_update.payload)
        config_envelope['last_update']['payload']['header'] = \
            decode_header(proto_payload.header)
        config_envelope['last_update']['payload']['data'] = \
            decode_config_update_envelope(proto_payload.data)
        config_envelope['last_update']['signature'] = \
            proto_last_update.signature
    return config_envelope


def decode_config(proto_config):
    """Decodes configuration from config envelope

    Args:
        proto_config (bytes): Config value

    Returns: deserialized config
    """
    config = {}
    config['sequence'] = str(proto_config.sequence)
    config['channel_group'] = decode_config_group(proto_config.channel_group)
    # config['type'] = proto_config.type
    # TODO: getType() equivalent
    return config


def decode_config_update_envelope(config_update_envelope_bytes):
    """Decode config update envelope

    Args:
        config_update_envelope_bytes (str): Bytes of update envelope

    Returns: deserialized config update envelope signatures
    """
    config_update_envelope = {}
    proto_config_update_envelope = configtx_pb2.ConfigUpdateEnvelope()
    proto_config_update_envelope.ParseFromString(config_update_envelope_bytes)
    config_update_envelope['config_update'] = \
        decode_config_update(proto_config_update_envelope.config_update)
    signatures = []
    for signature in proto_config_update_envelope.signatures:
        proto_config_signature = signature
        config_signature = decode_config_signature(proto_config_signature)
        signatures.append(config_signature)
    config_update_envelope['signatures'] = signatures
    return config_update_envelope


def decode_config_update(config_update_bytes):
    """Decodes update bytes in configuration

    Args:
        config_update_bytes (str): Bytes

    Returns: deserialized configuration update
    """
    config_update = {}
    proto_config_update = configtx_pb2.ConfigUpdate()
    proto_config_update.ParseFromString(config_update_bytes)
    config_update['channel_id'] = proto_config_update.channel_id
    config_update['read_set'] = \
        decode_config_group(proto_config_update.read_set)
    config_update['write_set'] = \
        decode_config_group(proto_config_update.write_set)
    # config_update['type'] = proto_config_update TODO: getType() equivalent
    return config_update


def decode_config_groups(config_group_map):
    """Decodes configuration groups inside ConfigGroup

    Args:
        config_group_map (str): Serialized ConfigGroup.groups object

    Returns: map of configuration groups.
    """
    config_groups = {}
    keys = config_group_map.keys()
    for key in keys:
        config_groups[key] = decode_config_group(config_group_map[key])
    return config_groups


def decode_config_group(proto_config_group):
    """Decodes configuration group from config protos

    Args:
        proto_config_group (str): serialized ConfigGroup() object

    Returns: deserialized config_groups dictionary
    """

    if not proto_config_group:
        return None
    config_group = {}
    config_group['version'] = decode_version(proto_config_group.version)
    config_group['groups'] = decode_config_groups(proto_config_group.groups)
    config_group['values'] = decode_config_values(proto_config_group.values)
    config_group['policies'] = \
        decode_config_policies(proto_config_group.policies)
    config_group['mod_policy'] = proto_config_group.mod_policy
    return config_group


def decode_config_values(config_value_map):
    """Decodes configuration values inside each configuration key

    Args:
        config_value_map (str): Serialized values map for each config key

    Returns: map of configuration values for each key
    """
    config_values = {}
    keys = config_value_map.keys()
    for key in keys:
        config_values[key] = decode_config_value(config_value_map[key], key)
    return config_values


def decode_config_value(proto_config_value, key):
    """Decodes ConfigValue from map with a given key

    Arguments:
        proto_config_value (str): A bytes string of config_value
        key (str): Map key for the configuration value

    Returns: config_value: Dictionary of configuration value deserialized
    """
    config_value_key = key
    config_value = {}
    config_value['version'] = decode_version(proto_config_value.version)
    config_value['mod_policy'] = proto_config_value.mod_policy
    config_value['value'] = {}
    if config_value_key == 'AnchorPeers':
        anchor_peers = []
        proto_anchor_peers = peer_configuration_pb2.AnchorPeers()
        proto_anchor_peers.ParseFromString(proto_config_value.value)
        if proto_anchor_peers and proto_anchor_peers.anchor_peers:
            for peer in proto_anchor_peers.anchor_peers:
                anchor_peer = {}
                anchor_peer['host'] = peer.host
                anchor_peer['port'] = peer.port
                anchor_peers.append(anchor_peer)
            config_value['value']['anchor_peers'] = anchor_peers
    elif config_value_key == 'MSP':
        msp_config = {}
        proto_msp_config = msp_config_pb2.MSPConfig()
        proto_msp_config.ParseFromString(proto_config_value.value)
        if proto_msp_config.type == 0:
            msp_config = decode_fabric_MSP_config(proto_msp_config.config)
        config_value['value']['type'] = proto_msp_config.type
        config_value['value']['config'] = msp_config
    elif config_value_key == 'ConsensusType':
        proto_consensus_type = orderer_configuration_pb2.ConsensusType()
        proto_consensus_type.ParseFromString(proto_config_value.value)
        config_value['value']['type'] = proto_consensus_type.type
    elif config_value_key == 'BatchSize':
        proto_batch_size = orderer_configuration_pb2.BatchSize()
        proto_batch_size.ParseFromString(proto_config_value.value)
        config_value['value']['max_message_count'] = \
            proto_batch_size.max_message_count
        config_value['value']['absolute_max_bytes'] = \
            proto_batch_size.absolute_max_bytes
        config_value['value']['preferred_max_bytes'] = \
            proto_batch_size.preferred_max_bytes
    elif config_value_key == 'BatchTimeout':
        proto_batch_timeout = orderer_configuration_pb2.BatchTimeout()
        proto_batch_timeout.ParseFromString(proto_config_value.value)
        config_value['value']['timeout'] = proto_batch_timeout.timeout
    elif config_value_key == 'ChannelRestrictions':
        proto_channel_restrictions = \
            orderer_configuration_pb2.ChannelRestrictions()
        proto_channel_restrictions.ParseFromString(proto_config_value.value)
        config_value['value']['max_count'] = \
            str(proto_channel_restrictions.max_count)
    elif config_value_key == 'Consortium':
        consortium_name = common_configuration_pb2.Consortium()
        consortium_name.ParseFromString(proto_config_value.value)
        config_value['value']['name'] = consortium_name.name
    elif config_value_key == 'HashingAlgorithm':
        proto_hashing_algorithm = common_configuration_pb2.HashingAlgorithm()
        proto_hashing_algorithm.ParseFromString(proto_config_value.value)
        config_value['value']['name'] = proto_hashing_algorithm.name
    elif config_value_key == 'BlockDataHashingStructure':
        proto_blockdata_hashing_structure = \
            common_configuration_pb2.BlockDataHashingStructure()
        proto_blockdata_hashing_structure.ParseFromString(
            proto_config_value.value)
        config_value['value']['width'] = \
            proto_blockdata_hashing_structure.width
    elif config_value_key == 'OrdererAddresses':
        orderer_addresses = common_configuration_pb2.OrdererAddresses()
        orderer_addresses.ParseFromString(proto_config_value.value)
        addresses = []
        proto_addresses = orderer_addresses.addresses
        if proto_addresses:
            for address in proto_addresses:
                addresses.append(address)
            config_value['value']['addresses'] = addresses
    else:
        pass
    return config_value


def decode_config_policies(config_policy_map):
    """Decodes list of configuration policies

    Args:
        config_policy_map (str): Serialized list of configuration policies

    Returns: deserialized map of config policies.
    """
    config_policies = {}
    keys = config_policy_map.keys()
    for key in keys:
        config_policies[key] = decode_config_policy(config_policy_map[key])
    return config_policies


def decode_config_policy(proto_config_policy):
    """Decodes config policy based on type of policy

    Args:
        proto_config_policy: Configuration policy bytes

    Returns: deserialized config_policy based on policy type.
    """
    config_policy = {}
    config_policy['version'] = decode_version(proto_config_policy.version)
    config_policy['mod_policy'] = proto_config_policy.mod_policy
    config_policy['policy'] = {}
    if proto_config_policy.policy:
        config_policy['policy']['type'] = proto_config_policy.policy.type
        if (proto_config_policy.policy.type == policies_pb2.Policy.SIGNATURE):
            config_policy['policy']['value'] = \
                decode_signature_policy_envelope(
                    proto_config_policy.policy.value)
        elif (proto_config_policy.policy.type == policies_pb2.Policy.MSP):
            proto_msp = policies_pb2.Policy()
            proto_msp.ParseFromString(proto_config_policy.policy.value)
        elif (proto_config_policy.policy.type ==
              policies_pb2.Policy.IMPLICIT_META):
            config_policy['policy']['value'] = \
                decode_implicit_meta_policy(proto_config_policy.policy.value)
        elif (proto_config_policy.policy.type == policies_pb2.Policy.UNKNOWN):
            config_policy['policy']['value'] = 'Unknown'
        else:
            raise ValueError("Unknown policy type")
    return config_policy


def decode_implicit_meta_policy(implicit_meta_policy_bytes):
    """Decodes implicit meta policy in a policy

    Args:
        implicit_meta_policy_bytes (str): Bytes of implicit meta policy

    Returns: deserialized implicit_meta_policy value.
    """
    implicit_meta_policy = {}
    proto_implicit_meta_policy = policies_pb2.ImplicitMetaPolicy()
    proto_implicit_meta_policy.ParseFromString(implicit_meta_policy_bytes)
    implicit_meta_policy['sub_policy'] = \
        proto_implicit_meta_policy.sub_policy
    implicit_meta_policy['rule'] = \
        implicit_metapolicy_rule[proto_implicit_meta_policy.rule]
    return implicit_meta_policy


def decode_signature_policy_envelope(signature_policy_envelope_bytes):
    """Decodes signature policy envelope bytes

    Args:
        signature_policy_envelope_bytes (str): Serialized signature envelope

    Returns: deserialized signature policy envelope contents.
    """
    signature_policy_envelope = {}
    proto_signature_policy_envelope = policies_pb2.SignaturePolicyEnvelope()
    proto_signature_policy_envelope.ParseFromString(
        signature_policy_envelope_bytes)
    signature_policy_envelope['version'] = \
        decode_version(proto_signature_policy_envelope.version)
    signature_policy_envelope['rule'] = \
        decode_signature_policy(proto_signature_policy_envelope.rule)
    identities = []
    proto_identities = proto_signature_policy_envelope.identities
    if proto_identities:
        for identity in proto_identities:
            msp_principal = decode_MSP_principal(identity)
            identities.append(msp_principal)
    signature_policy_envelope['identities'] = identities
    return signature_policy_envelope


def decode_signature_policy(proto_signature_policy):
    """Decodes signature policy based on field

    Args:
        proto_signature_policy: Object of SignaturePolicy()

    Returns: deserialized signature policy after decoding based on field.
    """
    signature_policy = {}
    if proto_signature_policy.HasField('n_out_of'):
        signature_policy['n_out_of'] = {}
        signature_policy['n_out_of']['n'] = proto_signature_policy.n_out_of.n
        signature_policy['n_out_of']['rules'] = []
        for rule in proto_signature_policy.n_out_of.rules:
            proto_policy = rule
            policy = decode_signature_policy(proto_policy)
            signature_policy['n_out_of']['rules'].append(policy)
    elif proto_signature_policy.HasField('signed_by'):
        signature_policy['signed_by'] = proto_signature_policy.signed_by
    else:
        raise ValueError("Unknown signature policy type")
    return signature_policy


def decode_MSP_principal(proto_msp_principal):
    """Decodes MSP Principal

    Args:
        proto_msp_principal (str): Bytes for MSP Principals

    Returns: deserialized MSP Principal based on classification.
    """
    msp_principal = {}
    msp_principal['principal_classification'] = \
        proto_msp_principal.principal_classification
    if (msp_principal['principal_classification'] ==
            msp_principal_pb2.MSPPrincipal.ROLE):
        msp_principal['principal_classification'] = 'ROLE'
        proto_principal = msp_principal_pb2.MSPRole()
        proto_principal.ParseFromString(proto_msp_principal.principal)
        msp_principal['principal'] = {}
        msp_principal['principal']['msp_identifier'] = \
            proto_principal.msp_identifier
        if proto_principal.role == 0:
            msp_principal['principal']['role'] = 'MEMBER'
        elif proto_principal.role == 1:
            msp_principal['principal']['role'] = 'ADMIN'
        else:
            pass
    elif (msp_principal['principal_classification'] ==
          msp_principal_pb2.MSPPrincipal.ORGANIZATION_UNIT):
        msp_principal['principal_classification'] = 'ORGANIZATION_UNIT'
        proto_principal = msp_principal_pb2.OrganizationUnit()
        proto_principal.ParseFromString(proto_msp_principal.principal)
        msp_principal['principal'] = {}
        msp_principal['principal']['msp_identifier'] = \
            proto_principal.msp_identifier
        msp_principal['principal']['organizational_unit_identifier'] = \
            proto_principal.organizational_unit_identifier
        msp_principal['principal']['certifiers_identifier'] = \
            proto_principal.certifiers_identifier
    else:
        # Case of IDENTITY
        msp_principal = decode_identity(proto_msp_principal.principal)
    return msp_principal


def decode_config_signature(proto_configSignature):
    """Decodes Configuration Signature

    Args:
        proto_configSignature (str): ConfigSignature() object

    Returns: deserialized config signature after header decode.
    """
    config_signature = {}
    config_signature['signature_header'] = \
        decode_signature_header(proto_configSignature.signature_header)
    config_signature['signature'] = proto_configSignature.signature
    return config_signature


def decode_fabric_MSP_config(msp_config_bytes):
    """Decodes Fabric MSP Configuration

    Args:
        msp_config_bytes (str): Serialized configuration for MSP

    Returns: Deserialized MSP configuration and certs.
    """
    msp_config = {}
    proto_msp_config = msp_config_pb2.FabricMSPConfig()
    proto_msp_config.ParseFromString(msp_config_bytes)
    msp_config['name'] = proto_msp_config.name
    msp_config['root_certs'] = to_PEM_certs(proto_msp_config.root_certs)
    msp_config['intermediate_certs'] = \
        to_PEM_certs(proto_msp_config.intermediate_certs)
    msp_config['admins'] = to_PEM_certs(proto_msp_config.admins)
    msp_config['revocation_list'] = \
        to_PEM_certs(proto_msp_config.revocation_list)
    msp_config['signing_identity'] = \
        decode_signing_identity_info(
            proto_msp_config.signing_identity.SerializeToString())
    msp_config['crypto_config'] = \
        decode_crypto_config(
            proto_msp_config.crypto_config.SerializeToString())
    ou_identifiers = [
        decode_fabric_OU_identifier(x) for x in
        proto_msp_config.organizational_unit_identifiers]
    msp_config['organizational_unit_identifiers'] = ou_identifiers
    msp_config['tls_root_certs'] = \
        to_PEM_certs(proto_msp_config.tls_root_certs)
    msp_config['tls_intermediate_certs'] = \
        to_PEM_certs(proto_msp_config.tls_intermediate_certs)
    msp_config['fabric_node_ous'] = \
        decode_fabric_Nodes_OUs(proto_msp_config.fabric_node_ous)
    return msp_config


def decode_fabric_OU_identifier(FabricOUIdentifier):
    """Decodes Fabric OU Identifier

    Args:
        FabricOUIdentifier (str): OU Identifier

    Returns: OU Identifier object.
    """

    return {
        'certificate': FabricOUIdentifier.certificate.decode(),
        'organizational_unit_identifier':
            FabricOUIdentifier.organizational_unit_identifier
    }


def decode_fabric_Nodes_OUs(proto_node_organizational_units):
    """Decodes Fabric Node OUs

    Args:
        proto_node_organizational_units (str): OUs

    Returns: deserialized list of OU Identifier objects.
    """
    node_organizational_units = {}

    if proto_node_organizational_units:
        node_organizational_units['enable'] = \
            proto_node_organizational_units.enable
        node_organizational_units['client_ou_identifier'] = \
            decode_fabric_OU_identifier(
                proto_node_organizational_units.client_ou_identifier)
        node_organizational_units['peer_ou_identifier'] = \
            decode_fabric_OU_identifier(
                proto_node_organizational_units.peer_ou_identifier)

    return node_organizational_units


def to_PEM_certs(buffer_array_in):
    """Decodes String buffer input to PEM Certs

    Args:
        buffer_array_in (str): certificate contents buffer

    Returns: Concats buffer contents and returns certs
    """
    return [b64encode(x).decode() for x in buffer_array_in]


def decode_signing_identity_info(signing_identity_info_bytes):
    """Decodes Signing identity information from MSP Configuration

    Args:
        signing_identity_info_bytes (str): Byte string of the identity info

    Returns: deserialized signing identity information.
    """
    if signing_identity_info_bytes == b'':
        return None

    signing_identity_info = {}

    if signing_identity_info_bytes is not None:
        proto_signing_identity_info = msp_config_pb2.SigningIdentityInfo()
        proto_signing_identity_info.ParseFromString(
            signing_identity_info_bytes)
        signing_identity_info['public_signer'] = \
            proto_signing_identity_info.public_signer.decode()
        signing_identity_info['private_signer'] = \
            decode_key_info(
                proto_signing_identity_info.private_signer.SerializeToString())
    return signing_identity_info


def decode_key_info(key_info_bytes):
    """Decodes Key Infor in MSP Configuration

    Args:
        key_info_bytes (str): Byte information containing KeyInfo

    Returns: deserialized key information.
    """
    key_info = {}
    if key_info_bytes:
        proto_key_info = msp_config_pb2.KeyInfo()
        proto_key_info.ParseFromString(key_info_bytes)
        key_info['key_identifier'] = proto_key_info.key_identifier
        key_info['key_material'] = 'private'
    return key_info


def decode_crypto_config(crypto_config_bytes):
    """Decodes Crypto Config in MSP Configuration

    Args:
        crypto_config_bytes (str): Byte information of FabricCyptoConfig

    Returns: deserialized key information.
    """
    crypto_config = {}
    if crypto_config_bytes:
        proto_crypto_config = msp_config_pb2.FabricCryptoConfig()
        proto_crypto_config.ParseFromString(crypto_config_bytes)
        crypto_config['signature_hash_family'] = proto_crypto_config. \
            signature_hash_family
        crypto_config['identity_identifier_hash_function'] = \
            proto_crypto_config.identity_identifier_hash_function
    return crypto_config


def decode_chaincode_action_payload(payload_bytes):
    """Decodes chaincode action payload from ChaincodeAction

    Args:
        payload_bytes (str): Bytes buffer of the payload

    Returns: deserialized payload information and action.
    """
    payload = {}
    proto_chaincode_action_payload = transaction_pb2.ChaincodeActionPayload()
    proto_chaincode_action_payload.ParseFromString(payload_bytes)
    payload['chaincode_proposal_payload'] = \
        decode_chaincode_proposal_payload(
            proto_chaincode_action_payload.chaincode_proposal_payload)
    payload['action'] = \
        decode_chaincode_endorsed_action(proto_chaincode_action_payload.action)
    return payload


def decode_chaincode_proposal_payload(chaincode_proposal_payload_bytes):
    """Decodes chaincode proposal payload from ChaincodeProposal

    Args:
        chaincode_proposal_payload_bytes (str): Bytes of chaincode proposal

    Returns: deserialized chaincode proposal payload information
    """
    chaincode_proposal_payload = {}
    proto_chaincode_proposal_payload = proposal_pb2.ChaincodeProposalPayload()
    proto_chaincode_proposal_payload.ParseFromString(
        chaincode_proposal_payload_bytes)
    chaincode_proposal_payload['input'] = \
        proto_chaincode_proposal_payload.input
    # Transient map is not allowed to be included on the ledger.
    return chaincode_proposal_payload


def decode_chaincode_endorsed_action(proto_chaincode_endorsed_action):
    """Decodes chaincode endorsed action

    Args:
        proto_chaincode_endorsed_action = Object containing endorsements

    Returns: deserialized chaincode endorsement action.
    """
    action = {}
    action['proposal_response_payload'] = \
        decode_proposal_response_payload(
            proto_chaincode_endorsed_action.proposal_response_payload)
    action['endorsements'] = []
    for endorsement in proto_chaincode_endorsed_action.endorsements:
        endorsement = decode_endorsement(endorsement)
        action['endorsements'].append(endorsement)
    return action


def decode_endorsement(proto_endorsement):
    """Decodes each endorsement

    Args:
        proto_endorsement: Object of endorsed content containing endorser
                           & related signature

    Returns: deserialized endorsement content
    """
    endorsement = {}
    endorsement['endorser'] = decode_identity(proto_endorsement.endorser)
    endorsement['signature'] = proto_endorsement.signature
    return endorsement


def decode_proposal_response_payload(proposal_response_payload_bytes):
    """Decodes response payload in the proposal

    Args:
        proposal_response_payload_bytes: Byte string of response payload

    Returns: deserialized proposal response payload.
    """
    proposal_response_payload = {}
    proto_proposal_response_payload = \
        proposal_response_pb2.ProposalResponsePayload()
    proto_proposal_response_payload.ParseFromString(
        proposal_response_payload_bytes)
    proposal_response_payload['proposal_hash'] = \
        binascii.b2a_hex(proto_proposal_response_payload.proposal_hash)
    proposal_response_payload['extension'] = \
        decode_chaincode_action(proto_proposal_response_payload.extension)
    return proposal_response_payload


def decode_chaincode_action(action_bytes):
    """Decodes chaincode actions

    Args:
        action_bytes (str): Byte buffer of the chaincode action

    Returns: deserialized chaincode action of results, events and response
    """
    chaincode_action = {}
    proto_chaincode_action = proposal_pb2.ChaincodeAction()
    proto_chaincode_action.ParseFromString(action_bytes)
    chaincode_action['results'] = \
        decode_readwrite_sets(proto_chaincode_action.results)
    chaincode_action['events'] = \
        decode_chaincode_events(proto_chaincode_action.events)
    chaincode_action['response'] = \
        decode_response(proto_chaincode_action.response)
    chaincode_action['chaincode_id'] = \
        decode_chaincode_id(proto_chaincode_action.chaincode_id)
    return chaincode_action


def decode_chaincode_events(event_bytes):
    """Decodes events in the chaincode

    Args:
        event_bytes (str): Byte buffer of event content

    Returns: deserialized event contents.
    """
    events = {}
    proto_events = chaincode_event_pb2.ChaincodeEvent()
    proto_events.ParseFromString(event_bytes)
    events['chaincode_id'] = proto_events.chaincode_id
    events['tx_id'] = proto_events.tx_id
    events['event_name'] = proto_events.event_name
    events['payload'] = proto_events.payload
    return events


def decode_chaincode_id(proto_chaincode_id):
    """Decodes chaincode ID information

    Args:
        proto_chaincode_id: Object containing chaincode details

    Returns: deserialized chaincode ID with path, name and version.
    """
    chaincode_id = {}
    if not proto_chaincode_id:
        return chaincode_id
    chaincode_id['path'] = proto_chaincode_id.path
    chaincode_id['name'] = proto_chaincode_id.name
    chaincode_id['version'] = proto_chaincode_id.version
    return chaincode_id


def decode_readwrite_sets(rw_sets_bytes):
    """Decodes read write sets from a given TxReadWriteSet

    Args:
        rw_sets_bytes (str): Byte buffer of the TxReadWriteSet

    Returns: deserialized transaction read write set contents.
    """
    proto_tx_read_write_set = rwset_pb2.TxReadWriteSet()
    proto_tx_read_write_set.ParseFromString(rw_sets_bytes)
    tx_read_write_set = {}
    tx_read_write_set['data_model'] = proto_tx_read_write_set.data_model
    if (tx_read_write_set['data_model'] == rwset_pb2.TxReadWriteSet.KV):
        tx_read_write_set['ns_rwset'] = []
        proto_ns_rwset = proto_tx_read_write_set.ns_rwset
        for rw_set in proto_ns_rwset:
            kv_rw_set = {}
            proto_kv_rw_set = rw_set
            kv_rw_set['namespace'] = proto_kv_rw_set.namespace
            kv_rw_set['rwset'] = decode_kv_rw_set(proto_kv_rw_set.rwset)
            tx_read_write_set['ns_rwset'].append(kv_rw_set)
    else:
        tx_read_write_set['ns_rwset'] = proto_tx_read_write_set.ns_rwset
    return tx_read_write_set


def decode_kv_rw_set(kv_bytes):
    """Decodes Key Value Read Write Set from KV Bytes

    Args:
        kv_bytes (str): Buffer of key value bytes

    Returns: deserialized key value read write set of reads, writes
             and range queries information.
    """
    proto_kv_rw_set = kv_rwset_pb2.KVRWSet()
    proto_kv_rw_set.ParseFromString(kv_bytes)
    kv_rw_set = {}
    # KV readwrite set has 3 arrays
    kv_rw_set['reads'] = []
    kv_rw_set['range_queries_info'] = []
    kv_rw_set['writes'] = []
    # Build reads
    reads = kv_rw_set['reads']
    proto_reads = proto_kv_rw_set.reads
    for read in proto_reads:
        reads.append(decode_kv_read(read))
    # Build range_queries_info
    range_queries_info = kv_rw_set['range_queries_info']
    proto_range_queries_info = proto_kv_rw_set.range_queries_info
    for range_query in proto_range_queries_info:
        range_queries_info.append(decode_range_query_info(range_query))
    # Build writes
    writes = kv_rw_set['writes']
    proto_writes = proto_kv_rw_set.writes
    for write in proto_writes:
        writes.append(decode_kv_write(write))

    kv_rw_set['reads'] = reads
    kv_rw_set['range_queries_info'] = range_queries_info
    kv_rw_set['writes'] = writes
    return kv_rw_set


def decode_kv_read(proto_kv_read):
    """Decodes Key Value Read

    Args:
        proto_kv_read: Object of the key value with read contents

    Returns: deserialized key value read contents with block num and tx_num
    """
    kv_read = {}
    kv_read['key'] = proto_kv_read.key
    proto_version = proto_kv_read.version
    if proto_version:
        kv_read['version'] = {}
        kv_read['version']['block_num'] = str(proto_version.block_num)
        kv_read['version']['tx_num'] = str(proto_version.tx_num)
    else:
        kv_read['version'] = None
    return kv_read


def decode_range_query_info(proto_range_query_info):
    """Decodes range query information from KV RW sets.

    Args:
        proto_range_query_info: Object of key value read write range queries

    Returns: deserialized range query information with merkle hashes.
    """
    range_query_info = {}
    range_query_info['start_key'] = proto_range_query_info.start_key
    range_query_info['end_key'] = proto_range_query_info.end_key
    range_query_info['itr_exhausted'] = proto_range_query_info.itr_exhausted

    proto_raw_reads = proto_range_query_info.raw_reads
    if proto_raw_reads:
        range_query_info['raw_reads'] = {}
        range_query_info['raw_reads']['kv_reads'] = []
        kv_read = None
        for kv_read in proto_raw_reads.kv_reads:
            kv_read = decode_kv_read(kv_read)
            range_query_info['raw_reads']['kv_reads'].append(kv_read)

    proto_reads_merkle_hashes = proto_range_query_info.reads_merkle_hashes
    if proto_reads_merkle_hashes:
        range_query_info['reads_merkle_hashes'] = {}
        range_query_info['reads_merkle_hashes']['max_degree'] = \
            proto_reads_merkle_hashes.max_degree
        range_query_info['reads_merkle_hashes']['max_level'] = \
            proto_reads_merkle_hashes.max_level
        range_query_info['reads_merkle_hashes']['max_level_hashes'] = \
            proto_reads_merkle_hashes.max_level_hashes
    return range_query_info


def decode_kv_write(proto_kv_write):
    """Decodes key value write instance

    Args:
        proto_kv_write: Object containing key value writes

    Returns: deserialized key value write contents and values.
    """
    kv_write = {}
    kv_write['key'] = proto_kv_write.key
    kv_write['is_delete'] = proto_kv_write.is_delete
    kv_write['value'] = proto_kv_write.value
    return kv_write


def decode_response(proto_response):
    """Decodes response containing status, message and payload

    Args:
        proto_response: Object containing proto responses

    Returns: deserialized response from protobuf objects
    """
    response = {}
    if proto_response:
        response['status'] = proto_response.status
        response['message'] = proto_response.message
        response['payload'] = proto_response.payload
    return response


def decode_fabric_peers_info(peers_info_bytes):
    """Decodes Fabric Peers Information

    Args:
        peer_bytes (str): Serialized information about Peer

    Returns: Deserialized Peers information and certs.
    """
    peers_info = []

    for peer_info_bytes in peers_info_bytes:
        peer = {}

        # identity
        peer_identity = identities_pb2.SerializedIdentity()
        peer_identity.ParseFromString(peer_info_bytes.identity)
        if hasattr(peer_identity, 'mspid'):
            peer['mspid'] = peer_identity.mspid
        if hasattr(peer_identity, 'id_bytes'):
            peer['id_bytes'] = peer_identity.id_bytes.decode()

        # state info
        peer_state_info = message_pb2.GossipMessage()
        peer_state_info.ParseFromString(peer_info_bytes.state_info.payload)

        if peer_state_info.state_info.properties:

            if hasattr(peer_state_info.state_info.properties, 'ledger_height'):
                peer['ledger_height'] = int(
                    peer_state_info.state_info.properties.ledger_height)

            if hasattr(peer_state_info.state_info.properties, 'chaincodes'):
                peer['chaincodes'] = []
                if peer_state_info.state_info.properties.chaincodes:
                    ccs = peer_state_info.state_info.properties.chaincodes
                    for chaincode in ccs:
                        cc = {}
                        cc['name'] = chaincode.name
                        cc['version'] = chaincode.version
                        peer['chaincodes'].append(cc)

        # membership info
        peer_membership_info = message_pb2.GossipMessage()
        membership_payload = peer_info_bytes.membership_info.payload
        peer_membership_info.ParseFromString(membership_payload)

        peer['endpoint'] = peer_membership_info.alive_msg.membership.endpoint

        peers_info.append(peer)

    return sorted(peers_info, key=lambda peer: peer['endpoint'])


def decode_fabric_endpoints(endpoints):
    """Decodes Fabric Endpoints

    Args:
        endpoints (str): Fabric Endpoints

    Returns: Deserialized endpoints.
    """

    endpoints_info = []
    for item in endpoints:
        endpoint = {}

        endpoint['host'] = item.host
        endpoint['port'] = int(item.port)

        endpoints_info.append(endpoint)
    return endpoints_info
