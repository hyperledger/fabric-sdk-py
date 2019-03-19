#
# SPDX-License-Identifier: Apache-2.0

from hfc.protos.orderer import ab_pb2
from hfc.protos.common import common_pb2
from hfc.protos.peer import chaincode_pb2, transaction_pb2


def create_seek_info(start=None, stop=None, behavior="BLOCK_UNTIL_READY"):

    # build start
    if start is not None:
        seek_specified_start = ab_pb2.SeekSpecified()
        seek_specified_start.number = start
        seek_start = ab_pb2.SeekPosition()
        seek_start.specified.CopyFrom(seek_specified_start)
    else:
        seek_start = ab_pb2.SeekPosition()
        seek_start.newest.CopyFrom(ab_pb2.SeekNewest())

    # build stop
    if stop is not None:
        seek_specified_stop = ab_pb2.SeekSpecified()
        seek_specified_stop.number = stop
        seek_stop = ab_pb2.SeekPosition()
        seek_stop.specified.CopyFrom(seek_specified_stop)
    else:
        seek_stop = ab_pb2.SeekPosition()
        seek_stop.newest.CopyFrom(ab_pb2.SeekNewest())

    # seek info with all parts
    seek_info = ab_pb2.SeekInfo()
    seek_info.start.CopyFrom(seek_start)
    seek_info.stop.CopyFrom(seek_stop)

    seek_info.behavior = \
        ab_pb2.SeekInfo.SeekBehavior.Value(behavior)

    return seek_info


def create_seek_payload(seek_header, seek_info):

    seek_payload = common_pb2.Payload()
    seek_payload.header.CopyFrom(seek_header)
    seek_payload.data = seek_info.SerializeToString()
    seek_payload_bytes = seek_payload.SerializeToString()

    return seek_payload_bytes


def create_cc_spec(chaincode_input, chaincode_id, type):

    chaincode_spec = chaincode_pb2.ChaincodeSpec()
    chaincode_spec.type = chaincode_pb2.ChaincodeSpec.Type.Value(type)
    chaincode_spec.chaincode_id.CopyFrom(chaincode_id)
    chaincode_spec.input.CopyFrom(chaincode_input)

    return chaincode_spec


def create_tx_payload(endorsements, tran_req):

    cc_action_payload = transaction_pb2.ChaincodeActionPayload()
    response = tran_req.responses[0]
    cc_action_payload.action.proposal_response_payload = \
        response.payload
    cc_action_payload.action.endorsements.extend(endorsements)
    cc_action_payload.chaincode_proposal_payload = tran_req.proposal.payload

    tran = transaction_pb2.Transaction()
    cc_tran_action = tran.actions.add()
    cc_tran_action.header = tran_req.header.signature_header
    cc_tran_action.payload = cc_action_payload.SerializeToString()
    tran_payload = common_pb2.Payload()
    tran_payload.header.channel_header = tran_req.header.channel_header
    tran_payload.header.signature_header = tran_req.header.signature_header
    tran_payload.data = tran.SerializeToString()

    tran_payload_bytes = tran_payload.SerializeToString()
    return tran_payload_bytes


def create_envelope(seek_payload_sig, seek_payload_bytes):

    envelope = common_pb2.Envelope()
    envelope.signature = seek_payload_sig
    envelope.payload = seek_payload_bytes

    return envelope
