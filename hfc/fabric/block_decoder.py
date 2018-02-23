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

# Import required Common Protos
from hfc.protos.common import common_pb2

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

        :param block_bytes: Block instance
        :return: Dictionary containing decoded Block instance.
        """
        block = {}
        try:
            proto_block = common_pb2.Block()
            proto_block.ParseFromString(block_bytes)
            block['header'] = decode_block_header(proto_block.header)
            # Add decode for data and metadata
        except Exception as e:
            raise ValueError("BlockDecoder :: decode failed", e)
        return block


def decode_block_header(proto_block_header):
    """
    Decodes the header of Block

    :param proto_block_header: Block Header proto
    :return: Decoded BlockHeader inside Block instance.
    """
    block_header = {}
    block_header['number'] = proto_block_header.number
    block_header['previous_hash'] = \
        binascii.b2a_hex(proto_block_header.previous_hash)
    block_header['data_hash'] = binascii.b2a_hex(proto_block_header.data_hash)
    return block_header
