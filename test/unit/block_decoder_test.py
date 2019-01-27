# Copyright Sudheesh Singanamalla 2018 All Rights Reserved.
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

import os
import unittest

from hfc.fabric.block_decoder import BlockDecoder
from hfc.fabric.block_decoder import HeaderType
from hfc.fabric.block_decoder import decode_readwrite_sets

# Import required Ledger Protos
from hfc.protos.ledger.rwset import rwset_pb2
from hfc.protos.ledger.rwset.kvrwset import kv_rwset_pb2


# Load a genesis block as input to test the decoders
with open(os.path.join(os.path.dirname(__file__),
                       "../fixtures/e2e_cli/" +
                       "channel-artifacts/orderer.genesis.block"),
          'rb') as f:
    data = f.read()

with open(os.path.join(os.path.dirname(__file__),
                       "../fixtures/e2e_cli/" +
                       "channel-artifacts/channel.tx"),
          'rb') as f:
    tx_data = f.read()

with open(os.path.join(os.path.dirname(__file__),
                       "../fixtures/e2e_cli/" +
                       "channel-artifacts/businesschannel_4.block"),
          'rb') as f:
    metadata_block = f.read()


class BlockDecoderTest(unittest.TestCase):
    """Test for BlockDecoder in Fabric"""

    def setUp(self):
        self._data = data
        self._metadata_block = metadata_block
        self.decoder_instance = BlockDecoder.decode(self._data)
        self._tx_data = tx_data
        self.decode_transaction = \
            BlockDecoder.decode_transaction(self._tx_data)
        self.decoded_metadata = BlockDecoder.decode(self._metadata_block)

    def test_decode_failure(self):
        """
        Checks failure cases for decode of block.
        """
        self.assertRaises(TypeError, lambda: BlockDecoder.decode())
        self.assertRaises(ValueError, lambda: BlockDecoder.decode('test'))

    def test_decode_block_header(self):
        """
        Checks if the block header has been decoded correctly.
        """
        data_hash = \
            b'e6a8b7ca7bf9aa5123e2d72bd3d55e0e32d6cefdf001bf31944061cef24c9ad3'
        previous_hash = b''
        number = 0
        header_info = self.decoder_instance['header']
        self.assertEqual(header_info['data_hash'], data_hash)
        self.assertEqual(header_info['previous_hash'], previous_hash)
        self.assertEqual(header_info['number'], number)

    def test_decode_block_data(self):
        """
        Checks if the block data has been decoded correctly.
        This test case also verifies the results from other
        decode header and data calls while decoding the block.
        """
        sh_nonce = b'71fba48e569c9f9b3f393e5b4b803db6209cb5fb2956301e'
        channel_id = 'testchainid'
        timestamp = '2018-10-19 03:53:04'
        tx_id = \
            '094760b6a9c9fdbb5d231c3ca79fe28ba2fd62a1aa9d913d37f7938ac44ba52a'
        epoch = 0
        version = 1
        type_value = 1
        extension = b''

        data_info = self.decoder_instance['data']
        data_item = data_info['data'][0]
        data_payload_header = data_item['payload']['header']
        sh = data_payload_header['signature_header']
        ch = data_payload_header['channel_header']

        self.assertEqual(len(data_info), 1)
        self.assertEqual(len(data_info['data']), 1)
        self.assertEqual(len(data_item.keys()), 2)
        self.assertEqual(len(data_payload_header.keys()), 2)
        self.assertEqual(len(sh['creator'].keys()), 2)
        self.assertEqual(len(sh.keys()), 2)
        self.assertEqual(len(ch.keys()), 8)

        self.assertEqual(sh['nonce'], sh_nonce)
        self.assertEqual(ch['extension'], extension)
        self.assertEqual(ch['channel_id'], channel_id)
        self.assertEqual(ch['timestamp'], timestamp)
        self.assertEqual(ch['tx_id'], tx_id)
        self.assertEqual(ch['epoch'], epoch)
        self.assertEqual(ch['version'], version)
        self.assertEqual(ch['type'], type_value)

    def test_decode_transaction(self):
        """
        Checks if a transaction has been decoded correctly.
        """
        transaction_envelope = self.decode_transaction['transaction_envelope']
        validation_code = self.decode_transaction['validation_code']
        tx_payload = transaction_envelope['payload']
        tx_payload_header = tx_payload['header']
        tx_channel_header = tx_payload_header['channel_header']
        tx_signature_header = tx_payload_header['signature_header']
        self.assertEqual(type(dict()), type(transaction_envelope))
        self.assertEqual(validation_code, 0)
        self.assertIn('header', tx_payload)
        self.assertIn('channel_header', tx_payload_header)
        self.assertIn('signature_header', tx_payload_header)
        self.assertIn('channel_id', tx_channel_header)
        self.assertIn('epoch', tx_channel_header)
        self.assertIn('extension', tx_channel_header)
        self.assertIn('timestamp', tx_channel_header)
        self.assertIn('tx_id', tx_channel_header)
        self.assertIn('type', tx_channel_header)
        self.assertIn('version', tx_channel_header)
        self.assertIn('creator', tx_signature_header)
        self.assertIn('nonce', tx_signature_header)

    def test_decode_block_metadata(self):
        """
        Checks if the metadata for the block has been decoded properly.
        """
        index = 2

        decoded_metadata = self.decoded_metadata
        block_metadata = decoded_metadata['metadata']
        metadata = block_metadata['metadata']
        sample_signature = metadata[1]
        self.assertIn('metadata', decoded_metadata)
        self.assertIn('metadata', block_metadata)
        self.assertIn('value', metadata[0])
        self.assertIn('signatures', metadata[0])
        self.assertIn('signature_header', sample_signature['signatures'][0])
        self.assertIn('signature', sample_signature['signatures'][0])
        self.assertEqual(sample_signature['value']['index'], index)
        self.assertEqual(len(metadata), 3)
        self.assertEqual(len(sample_signature['signatures']), 1)

    def test_decode_read_write_sets(self):
        """
        checks if the decode read write sets have been decoded properly.
        """
        kv_read_proto = kv_rwset_pb2.KVRead()
        version_proto = kv_rwset_pb2.Version()
        version_proto.block_num = 12
        version_proto.tx_num = 21
        kv_read_proto.version.CopyFrom(version_proto)
        kv_read_proto.key = 'read key'
        reads_array = []
        reads_array.append(kv_read_proto)

        range_query_info_proto = kv_rwset_pb2.RangeQueryInfo()
        range_query_info_proto.start_key = 'start'
        range_query_info_proto.end_key = 'end'
        range_query_info_proto.itr_exhausted = False
        range_query_info_array = []
        range_query_info_array.append(range_query_info_proto)

        kv_write_proto = kv_rwset_pb2.KVWrite()
        kv_write_proto.key = 'write key'
        kv_write_proto.is_delete = False
        kv_write_proto.value = b'this is the value'
        writes_array = []
        writes_array.append(kv_write_proto)

        kvrwset_proto = kv_rwset_pb2.KVRWSet()
        kvrwset_proto.reads.extend(reads_array)
        kvrwset_proto.range_queries_info.extend(range_query_info_array)
        kvrwset_proto.writes.extend(writes_array)

        results_proto = rwset_pb2.TxReadWriteSet()
        results_proto.data_model = rwset_pb2.TxReadWriteSet.KV
        ns_rwset_array = []
        ns_rwset_proto = rwset_pb2.NsReadWriteSet()
        ns_rwset_proto.namespace = 'testnamespace'
        ns_rwset_proto.rwset = kvrwset_proto.SerializeToString()
        ns_rwset_array.append(ns_rwset_proto)
        results_proto.ns_rwset.extend(ns_rwset_array)

        results_json = decode_readwrite_sets(results_proto.SerializeToString())
        nsrwset_value = results_json['ns_rwset'][0]
        nsrwset_reads = nsrwset_value['rwset']['reads']
        nsrwset_range_queries = nsrwset_value['rwset']['range_queries_info'][0]

        self.assertEqual('testnamespace', nsrwset_value['namespace'])
        self.assertEqual('read key', nsrwset_reads[0]['key'])
        self.assertEqual('12', nsrwset_reads[0]['version']['block_num'])
        self.assertEqual('21', nsrwset_reads[0]['version']['tx_num'])

        self.assertIn('range_queries_info', nsrwset_value['rwset'])
        self.assertEqual('end', nsrwset_range_queries['end_key'])
        self.assertEqual('start', nsrwset_range_queries['start_key'])
        self.assertIn('reads_merkle_hashes', nsrwset_range_queries)
        self.assertIn('raw_reads', nsrwset_range_queries)

        self.assertIn('writes', nsrwset_value['rwset'])
        self.assertEqual('write key',
                         nsrwset_value['rwset']['writes'][0]['key'])
        self.assertEqual(b'this is the value',
                         nsrwset_value['rwset']['writes'][0]['value'])

    def test_decode_header_type(self):
        """
        Test cases for decoding headertype
        """
        self.assertEqual('MESSAGE', HeaderType.convert_to_string(0))
        self.assertEqual('CONFIG', HeaderType.convert_to_string(1))
        self.assertEqual('CONFIG_UPDATE', HeaderType.convert_to_string(2))
        self.assertEqual('ENDORSER_TRANSACTION',
                         HeaderType.convert_to_string(3))
        self.assertEqual('ORDERER_TRANSACTION',
                         HeaderType.convert_to_string(4))
        self.assertEqual('DELIVER_SEEK_INFO', HeaderType.convert_to_string(5))
        self.assertEqual('CHAINCODE_PACKAGE', HeaderType.convert_to_string(6))
        self.assertEqual('UNKNOWN_TYPE', HeaderType.convert_to_string(99))


if __name__ == '__main__':
    unittest.main()
