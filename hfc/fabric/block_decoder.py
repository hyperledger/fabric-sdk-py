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

# Import required Common Protos
from hfc.protos.common import common_pb2

# Import required MSP Protos
from hfc.protos.msp import identities_pb2

# Import required Peer Protos
from hfc.protos.peer import transaction_pb2

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
            # Add decode for data and metadata
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
        signatures = {}
        signatures = \
            decode_metadata_signatures(proto_block_metadata.metadata[0])
        metadata['metadata'].append(signatures)

        last_config = {}
        last_config = decode_last_config_sequence_number(
           proto_block_metadata.metadata[1])
        metadata['metadata'].append(last_config)

        transaction_filter = {}
        transaction_filter = \
            decode_transaction_filter(proto_block_metadata.metadata[2])
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
    # TODO: add envelope['payload']['data'] & ['payload']['header']
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
    millis = timestamp.seconds * 1000 + timestamp.nanos / 1000000
    date = datetime.datetime.fromtimestamp(millis/1e3)
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
        identity['id_bytes'] = proto_identity.id_bytes
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
    last_config = {}
    last_config['value'] = {}
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
