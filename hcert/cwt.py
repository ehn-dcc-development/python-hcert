import json
import time
from enum import Enum
from typing import Dict, List, Optional

import cbor2
import cose.algorithms
import cose.curves
import cose.headers
import cose.keys.keyops
from cose.keys.cosekey import CoseKey
from cose.keys.ec2 import EC2
from cose.messages import CoseMessage
from cose.messages.sign1message import Sign1Message
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

    if jwk_dict["kty"] != "EC":
        raise ValueError("Only EC keys supported")

    if jwk_dict["crv"] != "P-256":
        raise ValueError("Only P-256 supported")

    if private:
        key = EC2(
            crv=cose.curves.P256,
            x=b64d(jwk_dict["x"].encode()),
            y=b64d(jwk_dict["y"].encode()),
            d=b64d(jwk_dict["d"].encode()),
        )
        key.key_ops = [cose.keys.keyops.SignOp, cose.keys.keyops.VerifyOp]
    else:
        key = EC2(
            crv=cose.curves.P256,
            x=b64d(jwk_dict["x"].encode()),
            y=b64d(jwk_dict["y"].encode()),
        )
        key.key_ops = [cose.keys.keyops.VerifyOp]
    if "kid" in jwk_dict:
        key.kid = jwk_dict["kid"].encode()
    return key


class CWT(object):

    claims_map = CwtClaims

    def __init__(self, *args, **kwargs) -> None:
        self.protected_header = kwargs.get("protected_header")
        self.unprotected_header = kwargs.get("unprotected_header")
        self.claims = kwargs.get("claims", {})
        self.key = kwargs.get("key")

    def sign(self, private_key: CoseKey, alg: cose.algorithms.CoseAlgorithm) -> bytes:
        self.protected_header = {
            cose.headers.Algorithm: alg,
            cose.headers.ContentType: CoseContentTypes.CWT.value,
            cose.headers.KID: private_key.kid,
        }
        payload = cbor2.dumps(self.claims)
        cose_msg = Sign1Message(
            phdr=self.protected_header, uhdr=self.unprotected_header, payload=payload
        )
        cose_msg.key = private_key
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
        cose_msg: Sign1Message = CoseMessage.decode(signed_data)

        kid = cose_msg.phdr.get(cose.headers.KID)
        verified_key = None

        for key in public_keys:
            if key.kid == kid:
                cose_msg.key = key
                if cose_msg.verify_signature():
                    verified_key = key
                    break
        else:
            raise RuntimeError("Bad signature")

        return cls(
            protected_header=cose_msg.phdr,
            unprotected_header=cose_msg.uhdr,
            claims=cbor2.loads(cose_msg.payload),
            key=verified_key,
        )
