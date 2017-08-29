# Copyright 2009-2017 SAP SE or an SAP affiliate company.
# All Rights Reserved.
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
import os

DEFAULT = {
    'GRPC_SSL_CIPHER_SUITES': 'ECDHE-RSA-AES128-GCM-SHA256:'
                              'ECDHE-RSA-AES128-SHA256:'
                              'ECDHE-RSA-AES256-SHA384:'
                              'ECDHE-RSA-AES256-GCM-SHA384:'
                              'ECDHE-ECDSA-AES128-GCM-SHA256:'
                              'ECDHE-ECDSA-AES128-SHA256:'
                              'ECDHE-ECDSA-AES256-SHA384:'
                              'ECDHE-ECDSA-AES256-GCM-SHA384',
    'GRPC_MAX_RECEIVE_MESSAGE_LENGTH': 0,
    'GRPC_MAX_SEND_MESSAGE_LENGTH': 0
}

# set the environment variables for grpc - convert all integers to strings
for key in DEFAULT.keys():
    os.environ[key] = str(DEFAULT[key])
