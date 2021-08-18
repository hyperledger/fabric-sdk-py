# Copyright 281165273@qq.com. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

# import these constants for backwards compatibility in case someone uses them from here
from hfc.util.consts import CC_INSTALL, CC_INSTANTIATE, CC_UPGRADE, CC_INVOKE, CC_QUERY, \
    CC_TYPE_GOLANG, CC_TYPE_NODE, CC_TYPE_JAVA, CC_TYPE_CAR  # noqa: F401 # lgtm[py/unused-import]


class TXProposalRequest(object):
    """Class represents transaction proposal request."""

    def __init__(self, prop_type=None, cc_path=None,
                 cc_type=CC_TYPE_GOLANG, cc_name=None,
                 cc_version=None, fcn=None, args=None,
                 cc_endorsement_policy=None,
                 transient_map=None, packaged_cc=None,
                 collections_config=None, package_id=None, is_init=False):
        """ Construct transaction proposal request

        :param cc_type: chaincode type
        :param prop_type: proposal type
        :param packaged_cc: chaincode gz.tar bytes
        :param transient_map: transient data map
        :param cc_endorsement_policy: chaincode endorsement policy
        :param args: function arguments
        :param fcn: function name
        :param cc_version: chaincode version
        :param cc_name: chaincode name
        :param cc_path: chaincode path
        :param collections_config: collection config
        :return: An instance of TXProposalRequest or None

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
        self._package_id = package_id
        self._is_init = is_init
        if transient_map is None:
            self._transient_map = []
        else:
            self._transient_map = transient_map

    @property
    def cc_type(self):
        """Get chaincode type

        :return: return chaincode type

        """
        return self._cc_type

    @cc_type.setter
    def cc_type(self, cc_type):
        """Set chaincode type

        :param cc_type: chaincode type

        """
        self._cc_type = cc_type

    @property
    def prop_type(self):
        """Get proposal type

        :return: return proposal type

        """
        return self._prop_type

    @prop_type.setter
    def prop_type(self, prop_type):
        """Set proposal type

        :param prop_type: proposal type
        :return:

        """
        self._prop_type = prop_type

    @property
    def cc_path(self):
        """Get chaincode path

        :return: return chaincode path

        """
        return self._cc_path

    @cc_path.setter
    def cc_path(self, cc_path):
        """Set chaincode path

        :param cc_path: chaincode path
        :return:

        """
        self._cc_path = cc_path

    @property
    def cc_name(self):
        """Get chaincode name

        :return: return chaincode name

        """
        return self._cc_name

    @cc_name.setter
    def cc_name(self, cc_name):
        """Set chaincode name

        :param cc_name: chaincode name
        :return:

        """
        self._cc_name = cc_name

    @property
    def cc_version(self):
        """Get chaincode version

        :return: return chaincode version

        """
        return self._cc_version

    @cc_version.setter
    def cc_version(self, cc_version):
        """Set chaincode version

        :param cc_version: chaincode version
        :return:

        """
        self._cc_version = cc_version

    @property
    def fcn(self):
        """Get function name

        :return: return function name

        """
        return self._fcn

    @fcn.setter
    def fcn(self, fcn):
        """Set function name

        :param fcn: function name
        :return:

        """
        self._fcn = fcn

    @property
    def args(self):
        """Get function arguments

        :return: return function arguments

        """
        return self._args

    @args.setter
    def args(self, args):
        """Set function arguments

        :param args: function arguments
        :return:

        """
        self._args = args

    @property
    def packaged_cc(self):
        """Get packaged chaincode

        :return: return packaged chaincode

        """
        return self._packaged_cc

    @packaged_cc.setter
    def packaged_cc(self, packaged_cc):
        """Set packaged chaincode

        :param packaged_cc: packaged chaincode
        :return:

        """
        self._packaged_cc = packaged_cc

    @property
    def cc_endorsement_policy(self):
        """Get endorsement policy

        :return: return endorsement policy

        """
        return self._cc_endorsement_policy

    @cc_endorsement_policy.setter
    def cc_endorsement_policy(self, cc_endorsement_policy):
        """Set endorsement policy

        :param cc_endorsement_policy: endorsement policy
        :return:

        """
        self._cc_endorsement_policy = cc_endorsement_policy

    @property
    def transient_map(self):
        """Get transient map

        :return: return transient map

        """
        return self._transient_map

    @transient_map.setter
    def transient_map(self, transient_map):
        """Set transient map

        :param transient_map: transient map
        :return:

        """
        self._transient_map = transient_map

    @property
    def collections_config(self):
        """Get collections config

        :return: return collections config

        """
        return self._collections_config

    @collections_config.setter
    def collections_config(self, collections_config):
        """Set collections config

        :param collections_config: collections config
        :return:

        """
        self._collections_config = collections_config

    @property
    def package_id(self):
        """Get package_id

        :return: return package_id

        """
        return self._package_id

    @package_id.setter
    def package_id(self, package_id):
        """Set package_id

        :param package_id: package_id
        :return:

        """
        self._package_id = package_id

    @property
    def is_init(self):
        """Get package_id

        :return: return package_id

        """
        return self._is_init

    @is_init.setter
    def is_init(self, is_init):
        """Set package_id

        :param package_id: package_id
        :return:

        """
        self._is_init = is_init


def validate(tx_prop_req):
    """Check transaction proposal request.

    :param tx_prop_req: see TXProposalRequest
    :return: transaction proposal request if no error
    :raises ValueError: Invalid transaction proposal request

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
        if tx_prop_req.args is None and not tx_prop_req.transient_map:
            raise ValueError("Missing 'args' or 'transient_map'"
                             "parameter in the proposal request")
    return tx_prop_req


def create_tx_prop_req(prop_type=None, cc_path=None, cc_type=CC_TYPE_GOLANG,
                       cc_name=None, cc_version=None, fcn=None, args=None,
                       cc_endorsement_policy=None,
                       transient_map=None, packaged_cc=None,
                       collections_config=None, package_id=None, is_init=False):
    """Create a transaction proposal request

    :param prop_type: proposal request type (Default value = None)
    :param cc_path: chaincode path (Default value = None)
    :param cc_name: chaincode name (Default value = None)
    :param cc_version: chaincode version (Default value = None)
    :param fcn: function name (Default value = None)
    :param args: function arguments (Default value = None)
    :param cc_endorsement_policy: chaincode endorsement policy (Default value = None)
    :param transient_map: transient data map (Default value = None)
    :param packaged_cc: packaged chaincode source
    :param cc_type:  (Default value = CC_TYPE_GOLANG)
    :param collections_config:  (Default value = None)
    :return: a transaction proposal request (Default value = None)

    """
    tx_prop_req = TXProposalRequest(
        prop_type, cc_path, cc_type, cc_name, cc_version, fcn,
        args, cc_endorsement_policy, transient_map,
        packaged_cc, collections_config, package_id, is_init)
    return validate(tx_prop_req)
