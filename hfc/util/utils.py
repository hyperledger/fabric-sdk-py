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
import sys

from google.protobuf.timestamp_pb2 import Timestamp


def proto_str(x):
    return proto_b(x).decode("utf-8")


proto_b = \
    sys.version_info[0] < 3 and (lambda x: x) or (lambda x: x.encode('latin1'))


def current_timestamp():
    """Get current timestamp

    Returns: current timestamp

    """
    timestamp = Timestamp()
    timestamp.GetCurrentTime()
    return timestamp
