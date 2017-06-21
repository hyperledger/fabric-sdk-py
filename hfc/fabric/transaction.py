TransactionType = {
    'deploy': 0,
    'invoke': 1,
}


class Transaction(object):
    """ A Transaction.

    """

    def __init__(self, trans_type):
        """

        :param trans_type: Transaction Type include Deploy or Invoke
        """
        self.type = trans_type
