# Copyright IBM Corp. 2016 All Rights Reserved.
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


def channel(target, pem=None, opts=None):
    """Construct a grpc channel.

    Args:
        target: url of target include host:port
        pem: ssl/tls pem file as bytes
        opts: grpc channel options
                grpc.default_authority: default authority
                grpc.ssl_target_name_override: ssl target name override

    Returns:
        grpc channel

    """
    if pem is None:
        return grpc.insecure_channel(target, opts)
    else:
        creds = grpc.ssl_channel_credentials(pem)
        return grpc.secure_channel(target, creds, opts)
