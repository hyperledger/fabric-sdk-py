import unittest

from hfc.util.policies import s2d, d2s


class PoliciesTest(unittest.TestCase):

    def setUp(self):
        self.outof_or = "OutOf(1, 'Org1.member', 'Org2.member')"
        # is equivalent to
        self.or_ = "OR('Org1.member', 'Org2.member')"
        self.or_d = {'identities': [
            {'role': {'mspId': 'Org1', 'name': 'member'}},
            {'role': {'mspId': 'Org2', 'name': 'member'}}
        ],
            'policy': {'1-of': [{'signed-by': 0}, {'signed-by': 1}]}}

        self.outof_and = "OutOf(2, 'Org1.member', 'Org2.member')"
        # is equivalent to
        self.and_ = "AND('Org1.member', 'Org2.member')"
        self.and_d = {'identities': [
            {'role': {'mspId': 'Org1', 'name': 'member'}},
            {'role': {'mspId': 'Org2', 'name': 'member'}}
        ],
            'policy': {'2-of': [{'signed-by': 0}, {'signed-by': 1}]}}

        self.outof_complex = \
            "OutOf(2, 'Org1.member', 'Org2.member', 'Org3.member')"
        self.outof_complex_d = {'identities': [
            {'role': {'mspId': 'Org1', 'name': 'member'}},
            {'role': {'mspId': 'Org2', 'name': 'member'}},
            {'role': {'mspId': 'Org3', 'name': 'member'}}
        ],
            'policy': {'2-of': [
                {'signed-by': 0}, {'signed-by': 1}, {'signed-by': 2}
            ]}}
        # is equivalent to
        self.complex = "OR(AND('Org1.member', 'Org2.member')," \
                       " AND('Org1.member', 'Org3.member')," \
                       " AND('Org2.member', 'Org3.member'))"
        self.complex_d = {'identities': [
            {'role': {'mspId': 'Org1', 'name': 'member'}},
            {'role': {'mspId': 'Org2', 'name': 'member'}},
            {'role': {'mspId': 'Org3', 'name': 'member'}}
        ],
            'policy': {'1-of': [
                {'2-of': [{'signed-by': 0}, {'signed-by': 1}]},
                {'2-of': [{'signed-by': 0}, {'signed-by': 2}]},
                {'2-of': [{'signed-by': 1}, {'signed-by': 2}]}
            ]}}

        self._1ofAny = "OR('Org1.member', 'Org2.member'," \
                       " 'Org1.admin', 'Org2.admin')"
        self._1AdminOr2Other = "OR(AND('Org1.member', 'Org2.member')," \
                               " 'Org1.admin', 'Org2.admin')"
        self._2ofAny = "OutOf(2, 'Org1.member', 'Org2.member'," \
                       " 'Org1.admin', 'Org2.admin')"

        self.dumb_policy = {'identities': [
            {'role': {'name': 'member', 'mspId': 'chu-nantesMSP'}}
        ],
            'policy': {'signed-by': 0}}

    def test_s2d_outof_or(self):
        self.assertEqual(self.or_d, s2d().parse(self.outof_or))

    def test_s2d_or(self):
        self.assertEqual(self.or_d, s2d().parse(self.or_))

    def test_s2d_outof_and(self):
        self.assertEqual(self.and_d, s2d().parse(self.outof_and))

    def test_s2d_and_(self):
        self.assertEqual(self.and_d, s2d().parse(self.and_))

    def test_s2d_outof_complex(self):
        self.assertEqual(self.outof_complex_d, s2d().parse(
            self.outof_complex))

    def test_s2d_complex(self):
        self.assertEqual(self.complex_d, s2d().parse(self.complex))

    def test_s2d_1ofAny(self):
        self.assertEqual({'identities': [
            {'role': {'mspId': 'Org1', 'name': 'member'}},
            {'role': {'mspId': 'Org2', 'name': 'member'}},
            {'role': {'mspId': 'Org1', 'name': 'admin'}},
            {'role': {'mspId': 'Org2', 'name': 'admin'}}
        ],
            'policy': {'1-of': [
                {'signed-by': 0},
                {'signed-by': 1},
                {'signed-by': 2},
                {'signed-by': 3}
            ]}},
            s2d().parse(self._1ofAny))

    def test_s2d_1AdminOr2Other(self):
        self.assertEqual({'identities': [
            {'role': {'mspId': 'Org1', 'name': 'member'}},
            {'role': {'mspId': 'Org2', 'name': 'member'}},
            {'role': {'mspId': 'Org1', 'name': 'admin'}},
            {'role': {'mspId': 'Org2', 'name': 'admin'}}
        ],
            'policy': {
                '1-of': [
                    {'2-of': [{'signed-by': 0}, {'signed-by': 1}]},
                    {'signed-by': 2},
                    {'signed-by': 3}
                ]}},
            s2d().parse(self._1AdminOr2Other))

    def test_s2d_2ofAny(self):
        self.assertEqual({'identities': [
            {'role': {'mspId': 'Org1', 'name': 'member'}},
            {'role': {'mspId': 'Org2', 'name': 'member'}},
            {'role': {'mspId': 'Org1', 'name': 'admin'}},
            {'role': {'mspId': 'Org2', 'name': 'admin'}}
        ],
            'policy': {'2-of': [{'signed-by': 0},
                                {'signed-by': 1},
                                {'signed-by': 2},
                                {'signed-by': 3}]}},
            s2d().parse(self._2ofAny))

    def test_d2s_dumb_policy(self):
        self.assertEqual("OutOf(1, 'chu-nantesMSP.member')",
                         d2s.parse(self.dumb_policy))

    def test_d2s_outof_or(self):
        self.assertEqual(self.outof_or, d2s.parse(self.or_d))

    def test_d2s_outof_and(self):
        self.assertEqual(self.outof_and, d2s.parse(self.and_d))

    def test_d2s_s2d_outof_or(self):
        self.assertEqual(self.outof_or, d2s.parse(
            s2d().parse(self.outof_or)))

    def test_d2s_s2d_or(self):
        self.assertEqual(self.outof_or, d2s.parse(
            s2d().parse(self.or_)))

    def test_d2s_s2d_outof_complex(self):
        self.assertEqual(self.outof_complex, d2s.parse(
            s2d().parse(self.outof_complex)))


if __name__ == '__main__':
    unittest.main()
