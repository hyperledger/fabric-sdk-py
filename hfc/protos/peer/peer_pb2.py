# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: hfc/protos/peer/peer.proto
# Protobuf Python Version: 4.25.1
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from hfc.protos.peer import proposal_pb2 as hfc_dot_protos_dot_peer_dot_proposal__pb2
from hfc.protos.peer import proposal_response_pb2 as hfc_dot_protos_dot_peer_dot_proposal__response__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x1ahfc/protos/peer/peer.proto\x12\x06protos\x1a\x1ehfc/protos/peer/proposal.proto\x1a\'hfc/protos/peer/proposal_response.proto2O\n\x08\x45ndorser\x12\x43\n\x0fProcessProposal\x12\x16.protos.SignedProposal\x1a\x18.protos.ProposalResponseBR\n\"org.hyperledger.fabric.protos.peerZ,github.com/hyperledger/fabric-protos-go/peerb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'hfc.protos.peer.peer_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
  _globals['DESCRIPTOR']._options = None
  _globals['DESCRIPTOR']._serialized_options = b'\n\"org.hyperledger.fabric.protos.peerZ,github.com/hyperledger/fabric-protos-go/peer'
  _globals['_ENDORSER']._serialized_start=111
  _globals['_ENDORSER']._serialized_end=190
# @@protoc_insertion_point(module_scope)
