# Copyright IBM Corp. 2017 All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from hfc.protos.msp import identities_pb2


class Identity(object):
    """ MSP Identity.

    Use by client to validate certificates from endorser's sign, and also
    verify the endorser's signature.
    """

    def __init__(self, name, certificate, public_key, msp):
        """ Init.

        Args:
            name: id of this object
            certificate: certificate HEX string for the PEM encoded certificate
            public_key: The public key represented by the certificate
            msp: The associated MSP that manages this identity
        """
        self._id = name
        self._certificate = certificate
        self._public_key = public_key
        self._msp = msp

    @property
    def msp(self):
        """Get msp

        Returns: msp instance

        """
        return self._msp

    @property
    def name(self):
        """ Get the id

        Returns: id string
        """
        return self._id

    def is_valid(self):
        """This uses the rules that govern this identity to validate it.
        E.g.,if it is a fabric TCert implemented as identity,validate will
        check the TCert signature against the assumed root certificate
         authority.

        Returns: true/false

        """
        return self._msp.validate(self)

    def get_organization_units(self):
        """Returns the organization units this identity is related to
        as long as this is public information. In certain implementations
        this could be implemented by certain attributes that are publicly
        associated to that identity, or the identifier of the root certificate
        authority that has provided signatures on this certificate.

        Examples:
            - OrganizationUnit of a fabric-tcert that was signed by TCA
             under name "Organization 1", would be "Organization 1".
            - OrganizationUnit of an alternative implementation of tcert
             signed by a public CA used by organization "Organization 1",
              could be provided in the clear as part of that tcert
              structure that this call would be able to return.

        Returns: units string

        """
        pass

    def verify(self, msg, signature):
        """ Verify a signagure on the msg

        Args:
            msg: Message to be verified
            signature: Message signature to match

        Returns: Boolean

        """
        return self._msp.crypto_suite.verify(self._public_key,
                                             msg, signature)

    def verify_attribute(self, proof, attribute_proof_spec):
        """Verify attributes against the given attribute spec

        Args:
            proof: proof
            attribute_proof_spec: attribute proof spec

        Returns: true/false

        """
        pass

    def serialize(self):
        """Serialize this identity to a binary string.

        Returns:
            A binary string representation of this identity.
        """
        serialized_identity = identities_pb2.SerializedIdentity()
        serialized_identity.Mspid = self._msp.identity
        serialized_identity.IdBytes = self._certificate
        return serialized_identity.SerializeToString()


class Signer(object):
    """ To help sign with crypto algorithms.
    """

    def __init__(self, crypto_suite, key):
        """ Init.

        Args:
            crypto_suite: signature algorithms
            key:  private key
        """
        self._cryto_suite = crypto_suite
        self._key = key

    def get_public_key(self):
        """ Get the public key

        Returns: The public key

        """
        return self._key.public_key()

    def sign(self, digest):
        """ sign a digest

        Args:
            digest: message digest

        Returns: The public key
        """

        return self._cryto_suite.sign(self._key, digest)


class SigningIdentity(Identity):
    """ Extended identity to support signing operations.
    """

    def __init__(self, name, certificate, public_key, msp, signer):
        """ Init.

        Args:
            name: id of this object
            certificate: certificate HEX string for the PEM encoded certificate
            public_key: The public key represented by the certificate
            msp: The associated MSP that manages this identity
            signer: Signer
        """
        super(SigningIdentity, self) \
            .__init__(name, certificate, public_key, msp)
        self.signer = signer

    def sign(self, msg):
        """ Sign a message

        Args:
            msg: message to sign

        Returns: signed results
        """

        digest = self._msp.crypto_suite.hash(msg)
        return self.signer.sign(digest.hexdigest().encode('utf-8'))
