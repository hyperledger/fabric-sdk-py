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

from hfc.fabric.channel.installment import Installment, \
    create_installment_proposal_req, chaincode_installment
from hfc.fabric.channel.transactionproposals import TransactionProposalRequest


class InstallmentTest(unittest.TestCase):
    """ Chaincode related Test cases
    """

    @unittest.expectedFailure
    def test_create_installment(self):
        # TODO Impl
        installment = Installment()
        installment.handle()
        self.fail()

    def test_create_inst_prop_req(self):
        chaincode_id = ''
        chaincode_path = ''
        chaincode_version = ''
        trans_prop_req = create_installment_proposal_req(chaincode_id,
                                                         chaincode_path,
                                                         chaincode_version)

        self.assertTrue(isinstance(
            trans_prop_req, TransactionProposalRequest))

    def test_chaincode_installment(self):
        chain = None
        installment = chaincode_installment(chain)
        self.assertTrue(isinstance(installment, Installment))


if __name__ == '__main__':
    unittest.main()
