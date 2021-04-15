import logging
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import List

import cose.algorithms
from cose.keys.cosekey import CoseKey
from cryptojwt.utils import b64e

from .cwt import CWT, CwtClaims

SIGN_ALG = cose.algorithms.Es256
HCERT_CLAIM = -65537

logger = logging.getLogger(__name__)


class HealthCertificateClaims(Enum):
    EU_HCERT_V1 = 1


@dataclass
class HcertVerifyResult:
    kid: bytes
    iss: str
    iat: datetime
    exp: datetime
    expired: bool
    eu_hcert_v1: dict


def sign(
    private_key: CoseKey,
    issuer: str,
    ttl: int,
    payload: dict,
    content: HealthCertificateClaims = HealthCertificateClaims.EU_HCERT_V1,
    kid_protected: bool = True,
) -> bytes:
    """Create signed HCERT"""

    claims = {
        HCERT_CLAIM: {content.value: payload},
    }
    cwt = CWT.from_dict(claims=claims, issuer=issuer, ttl=ttl)
    cwt_bytes = cwt.sign(
        private_key=private_key, alg=SIGN_ALG, kid_protected=kid_protected
    )

    logger.info("Raw signed CWT: %d bytes", len(cwt_bytes))

    return cwt_bytes


def verify(signed_data: bytes, public_keys: List[CoseKey]) -> dict:

    now = int(time.time())
    cwt = CWT.from_bytes(signed_data=signed_data, public_keys=public_keys)

    if (iss := cwt.claims.get(CwtClaims.ISS.value)) is not None:
        logger.info("Signatured issued by: %s", iss)

    logger.info("Signature verified by: %s", b64e(cwt.key.kid).decode())

    if (iat := cwt.claims.get(CwtClaims.IAT.value)) is not None:
        logger.info("Signatured issued at: %s", datetime.fromtimestamp(iat))

    if (exp := cwt.claims.get(CwtClaims.EXP.value)) is not None:
        if exp > now:
            logger.info("Signatured expires at: %s", datetime.fromtimestamp(exp))
            expired = False
        else:
            logger.info("Signatured expired at: %s", datetime.fromtimestamp(exp))
            expired = True

    hcert = cwt.claims.get(HCERT_CLAIM)
    eu_hcert_v1 = hcert.get(HealthCertificateClaims.EU_HCERT_V1.value)

    return HcertVerifyResult(
        iss=iss,
        kid=cwt.key.kid,
        iat=datetime.fromtimestamp(iat) if iat else None,
        exp=datetime.fromtimestamp(exp) if exp else None,
        expired=expired,
        eu_hcert_v1=eu_hcert_v1,
    )
