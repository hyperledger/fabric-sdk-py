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

import unittest

from hfc.fabric.chain.transactionproposals import check_tran_prop_request, \
    TransactionProposalRequest,\
    CC_INSTALL, CC_INSTANTIATE, CC_INVOKE


CHAINCODE_ID = 'mytestchaincode'


class TransactionProposalTest(unittest.TestCase):

    def setUp(self):
        self.chaincode_id = CHAINCODE_ID

    def test_verify_transaction_constants(self):
        self.assertEqual(CC_INSTALL, 'install')
        self.assertEqual(CC_INSTANTIATE, 'deploy')
        self.assertEqual(CC_INVOKE, 'invoke')

    def test_create_transaction_proposal_requests(self):

        proposal = TransactionProposalRequest(self.chaincode_id,
                                              CC_INSTANTIATE)
        self.assertTrue(isinstance(proposal, TransactionProposalRequest))

    def test_check_tran_prop_request(self):

        tran_prop_requ = TransactionProposalRequest(self.chaincode_id,
                                                    CC_INSTANTIATE)

        # missing chaincode path
        with self.assertRaisesRegexp(ValueError, 'chaincode_path'):
            check_tran_prop_request(tran_prop_requ)
        tran_prop_requ.chaincode_path = '/chaincode.go'

        # missing chaincode version
        with self.assertRaisesRegexp(ValueError, 'chaincode_version'):
            check_tran_prop_request(tran_prop_requ)

        tran_prop_requ.chaincode_version = '1.0'

        # missing fcn param
        with self.assertRaisesRegexp(ValueError, 'fcn'):
            check_tran_prop_request(tran_prop_requ)

        tran_prop_requ.fcn = 'init'

        # missing args param
        tran_prop_requ.prop_type = CC_INVOKE
        with self.assertRaisesRegexp(ValueError, 'args'):
            check_tran_prop_request(tran_prop_requ)

        tran_prop_requ.add_args('args')

        # final test
        self.assertEqual(tran_prop_requ, check_tran_prop_request(
            tran_prop_requ))

    @unittest.expectedFailure
    def test_build_header(self):
        # TODO impl
        # header = build_header()
        self.fail()

    @unittest.expectedFailure
    def test_build_proposal(self):
        # TODO impl
        # proposal = build_proposal()
        # self.asserTrue(isinstance(proposal))
        self.fail()

    @unittest.expectedFailure
    def test_sign_proposal(self):
        # TODO impl
        # signing_identity = None
        # proposal = build_proposal()
        # signed_proposal = sign_proposal(signing_identity, proposal)
        self.fail()

    @unittest.expectedFailure
    def test_sign_tran_payload(self):
        # TODO impl
        # signing_identity = None
        # tran_payload = None
        # envelope = sign_tran_payload(signing_identity, tran_payload)
        self.fail()

    @unittest.expectedFailure
    def test_create_transaction_request(self):
        # TODO impl
        # responses = None
        # proposal = None
        # header = None
        # request = TransactionRequest(responses, proposal, header)
        self.fail()


if __name__ == '__main__':
    unittest()
