import json
import time
from base64 import b64decode
from enum import Enum
from typing import Dict, List, Optional

import cbor2
import cose.algorithms
import cose.headers
import cose.keys.curves
import cose.keys.keyops
import cryptojwt.exception
from cose.keys.cosekey import CoseKey
from cose.keys.ec2 import EC2Key
from cose.keys.rsa import RSAKey
from cose.messages import CoseMessage
from cose.messages.sign1message import Sign1Message
from cose.messages.signer import CoseSignature
from cose.messages.signmessage import SignMessage
from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.x509 import (
    import_private_key_from_pem_file,
    import_public_key_from_cert_file,
)
from cryptojwt.utils import b64d


class CoseContentTypes(Enum):
    CWT = 61


class CwtClaims(Enum):
    ISS = 1
    SUB = 2
    AUD = 3
    EXP = 4
    NBF = 5
    IAT = 6
    CTI = 7
    HCERT = -260


def read_cosekey(filename: str, private: bool = True) -> CoseKey:
    """Read key and return CoseKey"""
    if filename.endswith(".json"):
        with open(filename, "rt") as jwk_file:
            jwk_dict = json.load(jwk_file)
    elif filename.endswith(".key"):
        key = import_private_key_from_pem_file(filename)
        jwk = ECKey()
        jwk.load_key(key)
        jwk_dict = jwk.serialize(private=private)
    elif filename.endswith(".crt"):
        if private:
            raise ValueError("No private keys in certificates")
        key = import_public_key_from_cert_file(filename)
        jwk = ECKey()
        jwk.load_key(key)
        jwk_dict = jwk.serialize(private=private)
    else:
        raise ValueError("Unknown key format")
    return cosekey_from_jwk_dict(jwk_dict, private)


def cosekey_from_jwk_dict(jwk_dict: Dict, private: bool = True) -> CoseKey:
    """Read key and return CoseKey"""

    if jwk_dict["kty"] == "EC":

        if jwk_dict["crv"] != "P-256":
            raise ValueError("Only P-256 supported")

        if private:
            key = EC2Key(
                crv=cose.keys.curves.P256,
                x=b64d(jwk_dict["x"].encode()),
                y=b64d(jwk_dict["y"].encode()),
                d=b64d(jwk_dict["d"].encode()),
            )
        else:
            key = EC2Key(
                crv=cose.keys.curves.P256,
                x=b64d(jwk_dict["x"].encode()),
                y=b64d(jwk_dict["y"].encode()),
            )

    elif jwk_dict["kty"] == "RSA":

        if private:
            key = RSAKey(
                e=b64d(jwk_dict["e"].encode()),
                n=b64d(jwk_dict["n"].encode()),
                p=b64d(jwk_dict["p"].encode()),
                q=b64d(jwk_dict["q"].encode()),
                d=b64d(jwk_dict["d"].encode()),
            )
        else:
            key = RSAKey(
                e=b64d(jwk_dict["e"].encode()),
                n=b64d(jwk_dict["n"].encode()),
            )

    else:
        raise ValueError("Unsupport key type: " + jwk_dict["kty"])

    if private:
        key.key_ops = [cose.keys.keyops.SignOp, cose.keys.keyops.VerifyOp]
    else:
        key.key_ops = [cose.keys.keyops.VerifyOp]

    if "kid" in jwk_dict:
        kid = jwk_dict["kid"]
        try:
            key.kid = b64d(kid.encode())
        except cryptojwt.exception.BadSyntax:
            key.kid = b64decode(kid.encode())

    return key


class CWT(object):

    claims_map = CwtClaims

    def __init__(self, *args, **kwargs) -> None:
        self.protected_header = kwargs.get("protected_header", {})
        self.unprotected_header = kwargs.get("unprotected_header", {})
        self.claims = kwargs.get("claims", {})
        self.key = kwargs.get("key")

    def sign(
        self,
        private_key: CoseKey,
        alg: cose.algorithms.CoseAlgorithm,
        kid_protected: bool = True,
        sign1: bool = True,
    ) -> bytes:
        self.protected_header.update(
            {
                cose.headers.Algorithm: alg,
                cose.headers.ContentType: CoseContentTypes.CWT.value,
            }
        )
        if kid_protected:
            self.protected_header[cose.headers.KID] = private_key.kid
        else:
            self.unprotected_header[cose.headers.KID] = private_key.kid
        if sign1:
            cose_msg = Sign1Message(
                phdr=self.protected_header if len(self.protected_header) else None,
                uhdr=self.unprotected_header if len(self.unprotected_header) else None,
                payload=cbor2.dumps(self.claims),
            )
            cose_msg.key = private_key
        else:
            signers = [
                CoseSignature(
                    phdr=self.protected_header if len(self.protected_header) else None,
                    uhdr=self.unprotected_header
                    if len(self.unprotected_header)
                    else None,
                    key=private_key,
                )
            ]
            cose_msg = SignMessage(
                phdr={cose.headers.ContentType: CoseContentTypes.CWT.value},
                uhdr=self.unprotected_header
                if len(self.unprotected_header)
                else None,
                payload=cbor2.dumps(self.claims),
                signers=signers,
            )
        return cose_msg.encode()

    @classmethod
    def from_dict(
        cls, claims: Dict = {}, issuer: Optional[str] = None, ttl: Optional[int] = None
    ):

        now = int(time.time())
        cwt_claims = {CwtClaims.IAT.value: now}
        if ttl is not None:
            cwt_claims[CwtClaims.EXP.value] = now + ttl
        if issuer is not None:
            cwt_claims[CwtClaims.ISS.value] = issuer
        for k, v in claims.items():
            if isinstance(k, str):
                k = cls.claims_map[k.upper()].value
            cwt_claims[k] = v
        return cls(claims=cwt_claims)

    @classmethod
    def from_bytes(cls, signed_data: bytes, public_keys: List[CoseKey]):
        cose_msg = CoseMessage.decode(signed_data)

        if isinstance(cose_msg, Sign1Message):
            messages = [cose_msg]
        elif isinstance(cose_msg, SignMessage):
            messages = cose_msg.signers
        else:
            raise RuntimeError("Unsupported COSE message format")

        signers = []
        for msg in messages:
            kid = msg.phdr.get(cose.headers.KID)
            if kid is None:
                kid = msg.uhdr.get(cose.headers.KID)
            signers.append((kid, msg))

        verified_key = None
        for key in public_keys:
            for kid, msg in signers:
                if key.kid == kid:
                    msg.key = key
                    if msg.verify_signature():
                        verified_key = key
                        break
            if verified_key:
                break
        else:
            raise RuntimeError("Bad signature")

        return cls(
            protected_header=cose_msg.phdr,
            unprotected_header=cose_msg.uhdr,
            claims=cbor2.loads(cose_msg.payload),
            key=verified_key,
        )
