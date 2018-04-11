# Copyright. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

import logging

from hfc.fabric.user import create_user


_logger = logging.getLogger(__name__ + ".organization")


class Organization(object):
    """ An organization in the network.

    It contains several members.
    """

    def __init__(self, name='org', state_store=None):
        """
        :param name: Name of the organization
        """
        self._name = name
        self._mspid = None
        self._peers = []
        self._orderers = []
        self._CAs = []
        self._state_store = state_store
        self._users = dict()

    def init_with_bundle(self, info):
        """
        Init the peer with given info dict
        :param info: Dict including all info, e.g., endpoint, grpc option
        :return: True or False
        """
        if 'mspid' in info:
            self._mspid = info['mspid']
        if 'peers' in info:
            self._peers = info['peers']
        if 'orderers' in info:
            self._orderers = info['orderers']
        if 'certificateAuthorities' in info:
            self._CAs = info['certificateAuthorities']
        if 'users' in info:
            users = info['users']
            for name in users:
                user = create_user(name, self._name, self._state_store,
                                   self._mspid, users[name].get('private_key'),
                                   users[name].get('cert'))
                self._users[name] = user
        return True

    def get_user(self, name):
        """
        Return user instance with the name.
        :param name: Name of the user
        :return: User instance or None
        """
        if name in self._users:
            return self._users[name]
        return None


def create_org(name, info, state_store):
    """ Factory method to construct an organization instance

    Args:
        name: Name of the organization
        info: Info dict for initialization
        state_store: State store for data cache

    Returns: an organization instance
    """
    org = Organization(name=name, state_store=state_store)
    org.init_with_bundle(info)
    return org
