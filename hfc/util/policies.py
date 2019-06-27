import copy

from lark import Lark
from lark import Transformer

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

    def unique_list_of_dict(self, l):
        unique_l = []

        for item in l:
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
