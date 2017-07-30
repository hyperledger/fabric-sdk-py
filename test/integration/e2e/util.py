"""
Some paragraph here.

"""

def get_submitter():
    def get_submitter(client, org, name):

    user = User(name, org, client.state_store)
    user.enroll()
    client.user_context(user)
    return user

def load_msp(name, mspdir):
    msp = {}
    msp['id'] = name
    msp.root_certs = open(os.path.join(os.path.dirname(__file__), mspdir, 'cacerts')).read()
    msp.admins = open(os.path.join(os.path.dirname(__file__), mspdir, 'admins')).read()

    return msp

def get_nonce():
    pass
