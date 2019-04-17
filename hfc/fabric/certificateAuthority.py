# Copyright. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

import logging


_logger = logging.getLogger(__name__ + ".certificateAuthority")


class certificateAuthority(object):
    """ An organization in the network.

    It contains several members.
    """

    def __init__(self, name='ca'):
        """
        :param name: Name of the organization
        """
        self._name = name
        self._url = None
        self._grpc_options = dict()
        self._tlsCACerts = dict()
        self._registrar = []

    def init_with_bundle(self, info):
        """
        Init the peer with given info dict
        :param info: Dict including all info, e.g.,
        :return: True or False
        """
        if 'url' in info:
            self._url = info['url']
        if 'grpc_options' in info:
            self._grpc_options = info['grpc_options']
        if 'tlsCACerts' in info:
            self._tlsCACerts = info['tlsCACerts']
        if 'registrar' in info:
            self._registrar = info['registrar']
        return True


def create_ca(name, info):
    """ Factory method to construct a ca instance

    Args:
        name: Name of the ca
        info: Info dict for initialization

    Returns: an organization instance
    """
    ca = certificateAuthority(name=name)
    ca.init_with_bundle(info)
    return ca
