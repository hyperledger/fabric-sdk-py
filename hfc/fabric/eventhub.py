# Copyright arxanfintech.com 2016 All Rights Reserved.
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


class EventHub(object):
    """
        The EventHub object is responsible for connection to the fabric event
        source(s) and dissemination of events internally to the sdk and to
        clients of the sdk. Transactional events, which are generated for
        deploy and invoke operations, are directly consumed by the sdk which
        generates "complete" and "error" events based on them (see
        send_transaction in Member object for deploy and invoke operations).
        Clients of the sdk can register for Block and Chaincode events using
        the EventHub object. Clients can access the EventHub object created for
        a chain using the get_event_hub member of the Chain object or may
        create an EventHub object of their own. Each EventHub object created
        will create its own connection to the event source(usually a fabric
        peer).
    """

    def __init__(self):
        pass

    def set_peer_addr(self, peer_addr):
        """
            Set fabric event source (peer)

            Args:
                address (str): peer-id:peer-port
        """
        pass

    def connect(self):
        """
            Form connection to fabric event source.

        """
        pass

    def disconnect(self):
        """
            Drop active connection to fabric event source.

        """
        pass

    def register_chaincode_event(self, ccid, event_name, callback):
        """
            Register for chaincode events.

            Args:
                ccid (str): Chaincode id
                event_name (str): regex filter for event name
                callback (function): callback function to receive events

            Returns:
                callback_index: Callback index object
        """
        pass

    def unregister_chaincode_event(self, callback_index):
        """
            Unregister a prior chaincode event registration.

            Args:
                Callback index object
        """
        pass

    def register_block_event(self, callback):
        """
            Register for block events.

            Args:
                Callback (function): callback function to receive events
        """
        pass

    def unregister_block_event(self, callback):
        """
            Unregister a prior block event registration.

            Args:
                Callback (function): callback function to unregister
        """
        pass

    def register_tx_event(self, txid, callback):
        """
            Register for transaction events.

            Args:
                txid (str): transaction id
                Callback (function): callback function to receive events
        """
        pass

    def unregister_tx_event(self, txid):
        """
            Unregister a prior transaction event registration.

            Args:
                txid (str): transaction id
        """
        pass
