# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: hfc/protos/orderer/etcdraft/configuration.proto
# Protobuf Python Version: 4.25.1
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n/hfc/protos/orderer/etcdraft/configuration.proto\x12\x08\x65tcdraft\"]\n\x0e\x43onfigMetadata\x12\'\n\nconsenters\x18\x01 \x03(\x0b\x32\x13.etcdraft.Consenter\x12\"\n\x07options\x18\x02 \x01(\x0b\x32\x11.etcdraft.Options\"Y\n\tConsenter\x12\x0c\n\x04host\x18\x01 \x01(\t\x12\x0c\n\x04port\x18\x02 \x01(\r\x12\x17\n\x0f\x63lient_tls_cert\x18\x03 \x01(\x0c\x12\x17\n\x0fserver_tls_cert\x18\x04 \x01(\x0c\"\x8c\x01\n\x07Options\x12\x15\n\rtick_interval\x18\x01 \x01(\t\x12\x15\n\relection_tick\x18\x02 \x01(\r\x12\x16\n\x0eheartbeat_tick\x18\x03 \x01(\r\x12\x1b\n\x13max_inflight_blocks\x18\x04 \x01(\r\x12\x1e\n\x16snapshot_interval_size\x18\x05 \x01(\rBj\n.org.hyperledger.fabric.protos.orderer.etcdraftZ8github.com/hyperledger/fabric-protos-go/orderer/etcdraftb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'hfc.protos.orderer.etcdraft.configuration_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
  _globals['DESCRIPTOR']._options = None
  _globals['DESCRIPTOR']._serialized_options = b'\n.org.hyperledger.fabric.protos.orderer.etcdraftZ8github.com/hyperledger/fabric-protos-go/orderer/etcdraft'
  _globals['_CONFIGMETADATA']._serialized_start=61
  _globals['_CONFIGMETADATA']._serialized_end=154
  _globals['_CONSENTER']._serialized_start=156
  _globals['_CONSENTER']._serialized_end=245
  _globals['_OPTIONS']._serialized_start=248
  _globals['_OPTIONS']._serialized_end=388
# @@protoc_insertion_point(module_scope)
