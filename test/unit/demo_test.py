import unittest


def add_one(x):
    return x + 1


class DemoTest(unittest.TestCase):
    """ Demo a simple test case.
    """
    def setUp(self):
        """ setUP will be called before each test method.

        Returns:

        """
        self.name = b'Hello world!'

    def tearDown(self):
        """ tearDown will be called after each test method.

        Usually can add some clean up work here.

        Returns:

        """
        pass

    def test_add_one(self):
        """ The test method to call.

        Here can call the external methods we want to test against.

        Assert failure will cause exception to break the testing.

        Returns:

        """
        self.assertEqual(add_one(3), 4)


if __name__ == '__main__':
    unittest.main()
