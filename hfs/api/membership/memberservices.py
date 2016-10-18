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

import grpc
from ....protos import ca_pb2


DEFAULT_MEMBERSRVC_GRPC_ADDR = "localhost:7054"


class MemberServices(object):
    """Fabric member services client
    """

    def __init__(self, name, grpc_addr=DEFAULT_MEMBERSRVC_GRPC_ADDR):
        """MemberServices constructor

        :param name: name of the MemberService
        :param grpc_addr: grpc address of the membersrvc
        """
        self._name = name
        self._logger = logging.getLogger(__name__)
        self._channel = grpc.insecure_channel(grpc_addr)
        self._ecaa_stub = ca_pb2.ECAAStub(self.channel)
        self._ecap_stub = ca_pb2.ECAPStub(self.channel)
        self._tcap_stub = ca_pb2.TCAPStub(self.channel)
        self._tlscap_stub = ca_pb2.TLSCAPStub(self.channel)

    def get_name(self):
        """Get MemberService instance name

        :return: MemberService instance name
        """
        return self._name

    def get_security_level(self):
        """Get the security level

        :return: The security level
        """
        pass

    def set_security_level(self, security_level):
        """Set the security level

        :param security_level: the security level
        """
        pass

    def get_hash_algorithm(self):
        """Get the hash algorithm

        :return: the hash algorithm
        """
        pass

    def set_hash_algorithm(self, hash_algorithm):
        """Set the hash algorithm

        :param hash_algorithm: The hash algorithm ('SHA2' or 'SHA3')
        """
        pass

    def register_user(self, reginfo, registrar):
        """Register a user.

        Add a new user entry to the user registry in member service.
        :param reginfo: user register request
        :param registrar: registrar to register the new user
        :return: member instance and enrollment secret
        """
        pass

    def is_registered(self, name):
        """Determine if this user has been registered

        :param name: the name of the user
        :return: the result (True of False)
        """
        pass

    def enroll(self, name, secret):
        """Enroll a member

        Exchange the one-time user enrollment secret for a user certificate
        :param name: user name
        :param secret: user password
        :return: The enrolled member instance or None.
                 ECert is included in the member instance.
        """
        pass

    def is_enrolled(self, name):
        """Determine if this name has been enrolled

        :param name: the user name to check
        :return: the result (True of False)
        """
        pass

    def register_enroll(self, reginfo, registrar):
        """Register and enroll a user

        :param reginfo: user register request
        :param registrar: registrar to register the new user
        :return: member instance and enrollment secret
                 ECert is included in the member instance.
        """
        pass

    def get_tcert_batch(self, member, num):
        """Get an array of transaction certificates (tcerts)

        :param member: the member instance to get tcerts
        :param num: the number of tcerts to request
        :return: an array of transaction certificates (tcerts)
        """
        pass
