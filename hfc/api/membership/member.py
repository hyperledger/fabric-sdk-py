# Copyright esse.io 2016 All Rights Reserved.
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


class Member(object):
    """ Fabric Member object

    A member is an entity that transacts on a chain.
    Types of members include end users, peers, etc.
    """

    def __init__(self, chain, kwargs):
        """Constructor for a member.

        :param chain: the chain instance that the member belong to
        :param kwargs: includes name=,roles=,acount=,affiliation= ...
        """
        pass

    def get_name(self):
        """Get the member name.

        :return: The member name
        """
        pass

    def get_chain(self):
        """Get the chain.

        :return: The chain instance
        """
        pass

    def get_member_services(self):
        """Get the member services.

        :return: The member services
        """
        pass

    def get_roles(self):
        """Get the roles.

        :return: The roles.
        """
        pass

    def set_roles(self, roles):
        """Set the roles.

        :param roles: The roles.
        """
        pass

    def get_account(self):
        """Get the account

        :return: The account
        """
        pass

    def set_account(self, account):
        """Set the account

        :param account: The account
        """
        pass

    def get_affiliation(self):
        """Get the affiliation

        :return: The affiliation
        """
        pass

    def set_affiliation(self, affiliation):
        """Set the affiliation

        :param affiliation: The affiliation
        """
        pass

    def get_enrollment(self):
        """Get the enrollment info.

        :return: The enrollment info
        """
        pass

    def is_registered(self):
        """Determine if this member name has been registered.

        :return: True if registered; otherwise, false
        """
        pass

    def is_enrolled(self):
        """Determine if this member has been enrolled.

        :return: True if enrolled; otherwise, false
        """
        pass

    def register(self, reginfo):
        """Register the member.

        :param reginfo: register user request
        :return: the enrollment secrect
        """
        pass

    def enroll(self, enrollment_secret):
        """Enroll the member and return the enrollment results.

        Exchange the enrollment secret (one-time password) for
        enrollment certificate (ECert) and save it in the secure
        key/value store.

        :param enrollment_secret: user password
        :return: enrollment
                 ECert is included in the enrollment instance.
        """
        pass

    def register_enroll(self, reginfo):
        """Register and enroll a user

        Perform both registration and enrollment.
        :param reginfo: user register request
        :return: enrollment and enrollment secret
                 ECert is included in the enrollment instance.
        """
        pass

    def deploy(self, deploy_request):
        """Issue a deploy request on behalf of this member.

        :param deploy_request: deploy request
        :return: TransactionContext Emits 'submitted',
                 'complete', and 'error' events.
        """
        pass

    def send_transaction(self, trans_request):
        """Issue a transaction request on behalf of this member.

        :param trans_request: transaction request
        :return: TransactionContext Emits 'submitted',
                 'complete', and 'error' events.
        """
        pass

    def query(self, query_request):
        """Issue a query request on behalf of this member.

        :param query_request: query request
        :return: TransactionContext Emits 'submitted',
                 'complete', and 'error' events.
        """
        pass

    def to_json_string(self):
        """Save the current state of this member as a json string

        :return: The state of this member as a json string
        """
        pass

    def from_json_string(self, json_str):
        """Get the current state of this member from a json string

        :param json_str: The state of this member as a json string
        """
        pass
