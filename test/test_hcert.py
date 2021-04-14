import os

from cryptojwt.jwk.ec import new_ec_key

from hcert.cwt import cosekey_from_jwk_dict
from hcert.hcert import sign, verify
from hcert.optical import compress_and_encode, decode_and_decompress, save_qrcode


def gen_keypair():

    jwk = new_ec_key(crv="P-256")

    private_key_dict = jwk.serialize(private=True)
    public_key_dict = jwk.serialize(private=False)

    private_key = cosekey_from_jwk_dict(private_key_dict, private=True)
    public_key = cosekey_from_jwk_dict(public_key_dict, private=False)

    return private_key, public_key


def test_sign_verify():

    private_key, public_key = gen_keypair()

    issuer = "hello"
    ttl = 3600
    payload = {"test": True}

    signed_data = sign(private_key, issuer, ttl, payload)
    res = verify(signed_data, [public_key])

    assert res.eu_hcert_v1.get("test") is True
    assert res.expired is False


def test_optical():

    payload = os.urandom(1024)

    e = compress_and_encode(payload)
    d = decode_and_decompress(e)

    assert d == payload


def test_qr():

    private_key, public_key = gen_keypair()

    issuer = "hello"
    ttl = 3600
    payload = {"test": True}

    signed_data = sign(private_key, issuer, ttl, payload)
    img = save_qrcode(signed_data)
    assert len(img)
