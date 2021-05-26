from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.jwk.x509 import import_public_key_from_pem_data
from cryptojwt.utils import b64e


def pem_to_jwk_dict(pem_data: str):
    """Read PEM certificate and return JWK dictionary"""
    public_key = import_public_key_from_pem_data(pem_data)
    if isinstance(public_key, rsa.RSAPublicKey):
        jwk = RSAKey().load_key(public_key)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        jwk = ECKey().load_key(public_key)
    else:
        raise ValueError("Unknown key type")
    jwk_dict = jwk.serialize()
    cert = x509.load_pem_x509_certificate(pem_data.encode(), default_backend())
    fp = cert.fingerprint(hashes.SHA256())
    jwk_dict["kid"] = b64e(fp[:8]).decode()
    jwk_dict["x5t#S256"] = b64e(fp).decode()
    jwk_dict["x5a"] = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": cert.serial_number,
    }
    return jwk_dict
