import asyncio
import uuid


class BaseChaincode:
    def __init__(self, cc_name):
        self.evts = {}
        self._name = cc_name

    def create_onCcEvent(self, _uuid, tx_id):
        class CCEvent(object):
            def __init__(self, _uuid, evts, evt_tx_id):
                self.uuid = _uuid
                self.evts = evts  # keep reference, no copy
                self.evt_tx_id = evt_tx_id

            def cc_event(self, cc_event, block_number, tx_id, tx_status):
                if tx_id in self.evts:
                    if 'txEvents' not in self.evts[tx_id]:
                        self.evts[tx_id]['txEvents'] = []
                    self.evts[tx_id]['txEvents'] += [{
                        'cc_event': cc_event,
                        'tx_status': tx_status,
                        'block_number': block_number,
                    }]

                # unregister chaincode event if same tx_id
                # and disconnect as chaincode evt are unregister False
                if tx_id == self.evt_tx_id:
                    for x in self.evts[tx_id]['peer']:
                        if x['uuid'] == self.uuid:
                            x['channel_event_hub']. \
                                unregisterChaincodeEvent(x['cr'])
                            x['channel_event_hub'].disconnect()

        o = CCEvent(_uuid, self.evts, tx_id)
        return o.cc_event

    def txEvent(self, tx_id, tx_status, block_number):
        if tx_id in self.evts:
            if 'txEvents' not in self.evts[tx_id]:
                self.evts[tx_id]['txEvents'] = []
            self.evts[tx_id]['txEvents'] += [{
                'tx_status': tx_status,
                'block_number': block_number,
            }]

    async def wait_for_event(self, tx_context, target_peers, channel, requestor, cc_pattern, wait_for_event_timeout):
        event_stream = []

        for target_peer in target_peers:
            channel_event_hub = channel.newChannelEventHub(target_peer,
                                                           requestor)
            stream = channel_event_hub.connect()
            event_stream.append(stream)
            # use chaincode event
            if cc_pattern is not None:

                # needed in callback for ref in callback
                _uuid = uuid.uuid4().hex

                cr = channel_event_hub.registerChaincodeEvent(
                    self._name,
                    cc_pattern,
                    onEvent=self.create_onCcEvent(_uuid, tx_context.tx_id))

                if tx_context.tx_id not in self.evts:
                    self.evts[tx_context.tx_id] = {'peer': []}

                self.evts[tx_context.tx_id]['peer'] += [
                    {
                        'uuid': _uuid,
                        'channel_event_hub': channel_event_hub,
                        'cr': cr
                    }
                ]
            # use transaction event
            else:
                txid = channel_event_hub.registerTxEvent(
                    tx_context.tx_id,
                    unregister=True,
                    disconnect=True,
                    onEvent=self.txEvent)

                if txid not in self.evts:
                    self.evts[txid] = {'channel_event_hubs': []}

                self.evts[txid]['channel_event_hubs'] += [channel_event_hub]

        try:
            await asyncio.wait_for(asyncio.gather(*event_stream,
                                                  return_exceptions=True),
                                   timeout=wait_for_event_timeout)
        except asyncio.TimeoutError:
            for k, v in self.evts.items():
                if cc_pattern is not None:
                    for x in v['peer']:
                        x['channel_event_hub']. \
                            unregisterChaincodeEvent(x['cr'])
                else:
                    for x in v['channel_event_hubs']:
                        x.unregisterTxEvent(k)
            raise TimeoutError('waitForEvent timed out.')
        except Exception as e:
            raise e
        else:
            # check if all tx are valids
            txEvents = self.evts[tx_context.tx_id]['txEvents']
            statuses = [x['tx_status'] for x in txEvents]
            if not all([x == 'VALID' for x in statuses]):
                raise Exception(statuses)
        finally:
            # disconnect channel_event_hubs
            if cc_pattern is not None:
                for x in self.evts[tx_context.tx_id]['peer']:
                    x['channel_event_hub'].disconnect()
            else:
                cehs = self.evts[tx_context.tx_id]['channel_event_hubs']
                for x in cehs:
                    x.disconnect()
            del self.evts[tx_context.tx_id]
