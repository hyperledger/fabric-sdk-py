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


class BlockDecoderTest(unittest.TestCase):
    """Test for BlockDecoder in Fabric"""
    def setUp(self):
        self._data = data

    def test_decode_block_header(self):
        """
        Checks if the block header has been decoded correctly.
        """
        data_hash = \
            b'f2dabae6cbc541c519234b3a8a7cf17b885ac83d5a18807abdd2ce431573f53c'
        previous_hash = b''
        number = 0
        decoder_instance = BlockDecoder.decode(self._data)
        header_info = decoder_instance['header']
        self.assertEqual(header_info['data_hash'], data_hash)
        self.assertEqual(header_info['previous_hash'], previous_hash)
        self.assertEqual(header_info['number'], number)


if __name__ == '__main__':
    unittest.main()
