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


# Load a genesis block as input to test the decoders
with open(os.path.join(os.path.dirname(__file__),
          "../fixtures/e2e_cli/channel-artifacts/orderer.genesis.block"),
          'rb') as f:
    data = f.read()

with open(os.path.join(os.path.dirname(__file__),
          "../fixtures/e2e_cli/channel-artifacts/channel.tx"),
          'rb') as f:
    tx_data = f.read()

with open(os.path.join(os.path.dirname(__file__),
          "../fixtures/e2e_cli/channel-artifacts/businesschannel_4.block"),
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

    def test_decode_block_header(self):
        """
        Checks if the block header has been decoded correctly.
        """
        data_hash = \
            b'f2dabae6cbc541c519234b3a8a7cf17b885ac83d5a18807abdd2ce431573f53c'
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
        sh_nonce = b'cfa064bebe2a846b8f89a4fc82da2f652b9edb69eac65426'
        channel_id = 'testchainid'
        timestamp = '2017-06-23 09:45:18'
        tx_id = \
            '70add6a845ab8a90d97d402a6c0de665e717ed1bb74d37c6bf32232d8339194f'
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
        self.assertEqual(len(ch.keys()), 7)

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


if __name__ == '__main__':
    unittest.main()
