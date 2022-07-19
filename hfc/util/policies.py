import copy

from lark import Lark
from lark import Transformer

from hfc.protos.common import policies_pb2
from hfc.protos.msp import msp_principal_pb2
from hfc.util.utils import proto_b

s2d_grammar = r"""
    ?value: e
          | role
          | DIGIT -> number

    dot: "."
    dash: "-"
    name: /[\w\d\-\$\&\+\,\:\;\=\?\@\#\|\<\>\^\*\(\)\%\!]+/
    mspid: WORD
    role: "'" name dot mspid "'"
    or: "OR"
    and: "AND"
    outof: "OutOf"
    logic: or | and | outof
    e : logic "(" [value ("," value)*] ")"

    %import common.WORD
    %import common.LETTER
    %import common.DIGIT
    %import common.WS
    %ignore WS

    """


class String2Dict(Transformer):

    def __init__(self):
        self.id = 0
        self.roles = []

    def unique_list_of_dict(self, list_of_dict):
        unique_l = []

        for item in list_of_dict:
            if item not in unique_l:
                unique_l.append(item)

        return unique_l

    def get_logic(self, args, n):

        identities = []
        policies = []

        for i, v in enumerate(args):
            if 'policy' in v:
                identities += v['identities']
                policies.append(v['policy'])
            else:
                identities.append({"role": {
                    'name': v['name'],
                    'mspId': v['mspId']
                }})
                policies.append({"signed-by": v['id']})

        return {
            "identities": self.unique_list_of_dict(identities),
            "policy": {
                f"{n}-of": policies
            }
        }

    def get_outof(self, items):
        digit, *args = items
        return self.get_logic(args, digit)

    def name(self, items):
        return ''.join(items)

    def role(self, items):
        mspId, dot, name = items

        # check if identity already exists in self.identities
        for role in self.roles:
            if role['name'] == name \
                    and role['mspId'] == mspId:
                break
        else:
            role = {"name": name,
                    "mspId": mspId,
                    "id": self.id}
            self.id += 1
            self.roles.append(role)

        return role

    def logic(self, items):
        logic, = items
        return logic.data

    def dot(self, *args):
        return '.'

    def dash(self, *args):
        return '-'

    def mspid(self, items):
        return str(items[0])

    def number(self, items):
        return int(items[0])

    def e(self, items):
        logic, *args = items

        if logic == 'or':
            return self.get_logic(args, 1)
        elif logic == 'and':
            return self.get_logic(args, len(args))
        elif logic == 'outof':
            return self.get_outof(args)

        return items


class Dict2String(object):
    roles = []

    def get_policy(self, policy):
        policy_key = list(policy.keys())[0]
        n = policy_key.split('-of')[0]

        roles = []
        subpolicies = []

        if isinstance(policy[policy_key], list):
            for p in policy[policy_key]:
                key = list(p.keys())[0]
                if key == 'signed-by':
                    r = self.roles[p[key]]
                    roles.append(r)
                else:
                    p = self.get_policy(p)
                    subpolicies.append(p)
        else:
            n = 1
            subpolicies = [self.roles[policy[policy_key]]]

        return f"OutOf({n}, {', '.join(roles)}{', '.join(subpolicies)})"

    def parse(self, policy):
        p = copy.deepcopy(policy)

        self.roles = [f"'{x['role']['mspId']}.{x['role']['name']}'"
                      for x in p['identities']]

        return self.get_policy(p['policy'])


def s2d():
    # new instance for resetting local variables on each call
    transformer = String2Dict()
    return Lark(s2d_grammar, start='value', parser='lalr',
                transformer=transformer)


d2s = Dict2String()


def build_principal(identity):
    if 'role' not in identity:
        raise Exception('NOT IMPLEMENTED')

    newPrincipal = msp_principal_pb2.MSPPrincipal()

    newPrincipal.principal_classification = \
        msp_principal_pb2.MSPPrincipal.ROLE

    newRole = msp_principal_pb2.MSPRole()

    roleName = identity['role']['name']
    if roleName == 'peer':
        newRole.role = msp_principal_pb2.MSPRole.PEER
    elif roleName == 'member':
        newRole.role = msp_principal_pb2.MSPRole.MEMBER
    elif roleName == 'admin':
        newRole.role = msp_principal_pb2.MSPRole.ADMIN
    else:
        raise Exception(f'Invalid role name found: must'
                        f' be one of "peer", "member" or'
                        f' "admin", but found "{roleName}"')

    mspid = identity['role']['mspId']
    if not mspid or not isinstance(mspid, str):
        raise Exception(f'Invalid mspid found: "{mspid}"')
    newRole.msp_identifier = mspid.encode()

    newPrincipal.principal = newRole.SerializeToString()

    return newPrincipal


def get_policy(policy):
    type = list(policy.keys())[0]
    # signed-by case
    if type == 'signed-by':
        signedBy = policies_pb2.SignaturePolicy()
        signedBy.signed_by = policy['signed-by']
        return signedBy
    # n-of case
    else:
        n = int(type.split('-of')[0])

        nOutOf = policies_pb2.SignaturePolicy.NOutOf()
        nOutOf.n = n
        subs = []
        for sub in policy[type]:
            subPolicy = get_policy(sub)
            subs.append(subPolicy)

        nOutOf.rules.extend(subs)

        nOf = policies_pb2.SignaturePolicy()
        nOf.n_out_of.CopyFrom(nOutOf)

        return nOf


def check_policy(policy):
    if not policy:
        raise Exception('Missing Required Param "policy"')

    if 'identities' not in policy \
            or policy['identities'] == '' \
            or not len(policy['identities']):
        raise Exception('Invalid policy, missing'
                        ' the "identities" property')
    elif not isinstance(policy['identities'], list):
        raise Exception('Invalid policy, the "identities"'
                        ' property must be an array')

    if 'policy' not in policy \
            or policy['policy'] == '' \
            or not len(policy['policy']):
        raise Exception('Invalid policy, missing the'
                        ' "policy" property')


def build_policy(policy, msps=None, returnProto=False):
    proto_signature_policy_envelope = policies_pb2.SignaturePolicyEnvelope()

    if policy:
        check_policy(policy)
        proto_signature_policy_envelope.version = 0
        proto_signature_policy_envelope.rule.CopyFrom(get_policy(policy['policy']))
        proto_signature_policy_envelope.identities.extend([build_principal(x) for x in policy['identities']])
    else:
        # TODO need to support MSPManager
        # no policy was passed in, construct a 'Signed By any member
        # of an organization by mspid' policy
        # construct a list of msp principals to select from using the
        # 'n out of' operator

        # for not making it fail with current code
        return proto_b('')

        principals = []
        signedBys = []
        index = 0

        if msps is None:
            msps = []

        for msp in msps:
            onePrn = msp_principal_pb2.MSPPrincipal()
            onePrn.principal_classification = \
                msp_principal_pb2.MSPPrincipal.ROLE

            memberRole = msp_principal_pb2.MSPRole()
            memberRole.role = msp_principal_pb2.MSPRole.MEMBER
            memberRole.msp_identifier = msp

            onePrn.principal = memberRole.SerializeToString()

            principals.append(onePrn)

            signedBy = policies_pb2.SignaturePolicy()
            index += 1
            signedBy.signed_by = index
            signedBys.append(signedBy)

        if len(principals) == 0:
            raise Exception('Verifying MSPs not found in the'
                            ' channel object, make sure'
                            ' "initialize()" is called first.')

        oneOfAny = policies_pb2.SignaturePolicy.NOutOf()
        oneOfAny.n = 1
        oneOfAny.rules.extend(signedBys)

        noutof = policies_pb2.SignaturePolicy()
        noutof.n_out_of.CopyFrom(oneOfAny)

        proto_signature_policy_envelope.version = 0
        proto_signature_policy_envelope.rule.CopyFrom(noutof)
        proto_signature_policy_envelope.identities.extend(principals)

    if returnProto:
        return proto_signature_policy_envelope

    return proto_signature_policy_envelope.SerializeToString()
