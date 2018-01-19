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


def create_grpc_channel(target, cert_file=None, opts=None):
    """Construct a grpc channel.

    Args:
        target: server address include host:port
        cert_file: ssl/tls root cert file for the connection
        opts: grpc channel options
                grpc.default_authority: default authority
                grpc.ssl_target_name_override: ssl target name override

    Returns:
        grpc channel

    """

    root_cert = None
    if cert_file:
        with open(cert_file, 'rb') as f:
            root_cert = f.read()

    if root_cert is None:
        return grpc.insecure_channel(target, opts)
    else:
        creds = grpc.ssl_channel_credentials(root_cert)
        return grpc.secure_channel(target, creds, opts)
