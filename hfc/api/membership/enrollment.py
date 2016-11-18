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


class Enrollment(object):
    """Enrollment Object

    Enrollment contains the enrollment information of a chain member,
    which includes enrollment ID, privatekey, ECert, chainkey etc.
    After a member been enrolled, enrollment information will be cached
    to the local kvstore.
    """

    def __init__(self, enrollment_id, kwargs):
        """ Constructor for the Enrollment

        :param enrollment_id: member's enrollment id (name)
        :param kwargs: includes priv_key=,ecert=,chain_key= ...
        """
        pass

    def get_enrollment_id(self):
        """Get the enrollment ID.

        :return: The enrollment ID
        """
        pass

    def get_priv_key(self):
        """Get the enrollment private key.

        :return: The enrollment private key
        """
        pass

    def set_priv_key(self, priv_key):
        """Set the enrollment private key.

        :param priv_key: The enrollment private key
        """
        pass

    def get_ecert(self):
        """Get the enrollment certificate.

        :return: The enrollment certificate
        """
        pass

    def set_ecert(self, ecert):
        """Set the enrollment certificate.

        :param ecert: The enrollment certificate
        """
        pass

    def get_chainkey(self):
        """Get the chain key.

        :return: The chain key
        """

    def set_chainkey(self, chainkey):
        """Set the chain key.

        :param chainkey: The chain key
        """

    def to_json_string(self):
        """Save the current state of this enrollment as a json string

        :return: The state of this enrollment as a json string
        """
        pass

    def from_json_string(self, json_str):
        """Get the current state of this enrollment from a json string

        :param json_str: The state of this enrollment as a json string
        """
        pass
