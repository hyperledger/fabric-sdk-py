# Copyright 281165273@qq.com. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

CC_INSTALL = "install"
CC_INSTANTIATE = "deploy"
CC_INVOKE = "invoke"
CC_UPGRADE = "upgrade"
CC_QUERY = "query"

CC_TYPE_GOLANG = "GOLANG"
CC_TYPE_JAVA = "JAVA"
CC_TYPE_NODE = "NODE"
CC_TYPE_CAR = "CAR"


class TXProposalRequest(object):
    """ Class represents transaction proposal request."""

    def __init__(self, prop_type=None, cc_path=None,
                 cc_type=CC_TYPE_GOLANG, cc_name=None,
                 cc_version=None, fcn=None, args=None,
                 cc_endorsement_policy=None,
                 transient_map=None, packaged_cc=None,
                 collections_config=None):
        """ Construct transaction proposal request

        Args:
            cc_type (str): chaincode type
            prop_type (str): proposal type
            packaged_cc (bytearray): chaincode gz.tar bytes
            transient_map (list): transient data map
            cc_endorsement_policy (bytearray): chaincode endorsement policy
            args (list): function arguments
            fcn (str): function name
            cc_version (str): chaincode version
            cc_name (str): chaincode name
            cc_path (str): chaincode path
            collections_config: collection config

        """
        self._cc_type = cc_type
        self._prop_type = prop_type
        self._cc_path = cc_path
        self._cc_name = cc_name
        self._cc_version = cc_version
        self._fcn = fcn
        if args is None:
            self._args = []
        else:
            self._args = args
        self._packaged_cc = packaged_cc
        self._cc_endorsement_policy = cc_endorsement_policy
        self._collections_config = collections_config
        if transient_map is None:
            self._transient_map = []
        else:
            self._transient_map = transient_map

    @property
    def cc_type(self):
        """Get chaincode type

        Returns: return chaincode type

        """
        return self._cc_type

    @cc_type.setter
    def cc_type(self, cc_type):
        """Set chaincode type

        Args:
            cc_type: chaincode type

        """
        self._cc_type = cc_type

    @property
    def prop_type(self):
        """Get proposal type

        Returns: return proposal type

        """
        return self._prop_type

    @prop_type.setter
    def prop_type(self, prop_type):
        """Set proposal type

        Args:
            prop_type: proposal type

        """
        self._prop_type = prop_type

    @property
    def cc_path(self):
        """Get chaincode path

        Returns: return chaincode path

        """
        return self._cc_path

    @cc_path.setter
    def cc_path(self, cc_path):
        """Set chaincode path

        Args:
            cc_path: chaincode path

        """
        self._cc_path = cc_path

    @property
    def cc_name(self):
        """Get chaincode name

        Returns: return chaincode name

        """
        return self._cc_name

    @cc_name.setter
    def cc_name(self, cc_name):
        """Set chaincode name

        Args:
            cc_name: chaincode name

        """
        self._cc_name = cc_name

    @property
    def cc_version(self):
        """Get chaincode version

        Returns: return chaincode version

        """
        return self._cc_version

    @cc_version.setter
    def cc_version(self, cc_version):
        """Set chaincode version

        Args:
            cc_version: chaincode version

        """
        self._cc_version = cc_version

    @property
    def fcn(self):
        """Get function name

        Returns: return function name

        """
        return self._fcn

    @fcn.setter
    def fcn(self, fcn):
        """Set function name

        Args:
            fcn: function name

        """
        self._fcn = fcn

    @property
    def args(self):
        """Get function arguments

        Returns: return function arguments

        """
        return self._args

    @args.setter
    def args(self, args):
        """Set function arguments

        Args:
            args: function arguments

        """
        self._args = args

    @property
    def packaged_cc(self):
        """Get packaged chaincode

        Returns: return packaged chaincode

        """
        return self._packaged_cc

    @packaged_cc.setter
    def packaged_cc(self, packaged_cc):
        """Set packaged chaincode

        Args:
            packaged_cc: packaged chaincode

        """
        self._packaged_cc = packaged_cc

    @property
    def cc_endorsement_policy(self):
        """Get endorsement policy

        Returns: return endorsement policy

        """
        return self._cc_endorsement_policy

    @cc_endorsement_policy.setter
    def cc_endorsement_policy(self, cc_endorsement_policy):
        """Set endorsement policy

        Args:
            cc_endorsement_policy: endorsement policy

        """
        self._cc_endorsement_policy = cc_endorsement_policy

    @property
    def transient_map(self):
        """Get transient map

        Returns: return transient map

        """
        return self._transient_map

    @transient_map.setter
    def transient_map(self, transient_map):
        """Set transient map

        Args:
            transient_map: transient map

        """
        self._transient_map = transient_map

    @property
    def collections_config(self):
        """Get collections config

        Returns: return collections config

        """
        return self._collections_config

    @collections_config.setter
    def collections_config(self, collections_config):
        """Set collections config

        Args:
            collections_config: collections config

        """
        self._collections_config = collections_config


def validate(tx_prop_req):
    """Check transaction proposal request.

    Args:
        tx_prop_req: see TXProposalRequest

    Returns: transaction proposal request if no error

    Raises:
            ValueError: Invalid transaction proposal request

    """
    if not tx_prop_req:
        raise ValueError("Missing proposal request object")

    if not tx_prop_req.cc_name:
        raise ValueError("Missing 'cc_name' parameter "
                         "in the proposal request")

    if tx_prop_req.prop_type == CC_INSTALL:
        if not tx_prop_req.cc_path:
            raise ValueError("Missing 'cc_path' parameter "
                             "in the proposal request")

    if not tx_prop_req.cc_version and tx_prop_req.prop_type not in (CC_QUERY,
                                                                    CC_INVOKE):
        raise ValueError("Missing 'cc_version' parameter "
                         "in the proposal request")

    if tx_prop_req.prop_type != CC_INSTALL:
        if not tx_prop_req.fcn:
            raise ValueError("Missing 'fcn' parameter "
                             "in the proposal request")

    if tx_prop_req.prop_type == CC_INVOKE:
        if not tx_prop_req.args and not tx_prop_req.transient_map:
            raise ValueError("Missing 'args' or 'transient_map'"
                             "parameter in the proposal request")
    return tx_prop_req


def create_tx_prop_req(prop_type=None, cc_path=None, cc_type=CC_TYPE_GOLANG,
                       cc_name=None, cc_version=None, fcn=None, args=None,
                       cc_endorsement_policy=None,
                       transient_map=None, packaged_cc=None,
                       collections_config=None):
    """Create a transaction proposal request

    Args:
        prop_type: proposal request type
        cc_path: chaincode path
        cc_name: chaincode name
        cc_version: chaincode version
        fcn: function name
        args: function arguments
        cc_endorsement_policy: chaincode endorsement policy
        transient_map: transient data map
        packaged_cc: packaged chaincode source

    Returns: a transaction proposal request

    """
    tx_prop_req = TXProposalRequest(
        prop_type, cc_path, cc_type, cc_name, cc_version, fcn,
        args, cc_endorsement_policy, transient_map,
        packaged_cc, collections_config)
    return validate(tx_prop_req)
