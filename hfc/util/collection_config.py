from hfc.protos.peer import collection_pb2
from hfc.util.policies import build_policy


def build_collection_config_proto(collections_config):
    collections_configs_res = []

    for config in collections_config:
        static_config = collection_pb2.StaticCollectionConfig()
        static_config.name = config['name']
        static_config.member_orgs_policy.signature_policy.CopyFrom(build_policy(config['policy'], returnProto=True))
        static_config.maximum_peer_count = config['maxPeerCount']
        static_config.required_peer_count = config.get('requiredPeerCount', 0)
        static_config.block_to_live = config.get('blockToLive', 0)
        static_config.member_only_read = config.get('memberOnlyRead',
                                                    False)

        collections_config = collection_pb2.CollectionConfig()
        collections_config.static_collection_config.CopyFrom(
            static_config
        )

        collections_configs_res.append(collections_config)

    cc_coll_cfg = collection_pb2.CollectionConfigPackage()
    cc_coll_cfg.config.extend(collections_configs_res)
    return cc_coll_cfg
