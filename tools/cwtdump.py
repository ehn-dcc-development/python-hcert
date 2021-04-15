import argparse
import binascii

import cbor2
from cose.headers import CoseHeaderAttribute
from cryptojwt.utils import b64e

from hcert.cwt import CwtClaims


def print_header(hdr):
    if isinstance(hdr, dict):
        for k, v in hdr.items():
            attr = CoseHeaderAttribute.from_id(k)
            if isinstance(v, bytes):
                v = "{hex}" + binascii.hexlify(v).decode()
            print(f"  {k} ({attr.fullname}) = {v}")


def print_message(msg):
    if isinstance(msg, dict):
        for k, v in msg.items():
            try:
                claim = CwtClaims(k).name.lower()
            except ValueError:
                claim = None
            if isinstance(v, bytes):
                v = "{hex}" + binascii.hexlify(v).decode()
            print(f"  {k} ({claim}) = {v}")


def main():

    parser = argparse.ArgumentParser(description="CWT dump tool")

    parser.add_argument(
        "file",
        help="File with CWT contents",
    )

    args = parser.parse_args()

    with open(args.file, "rb") as cwt_file:
        cwt_bytes = cwt_file.read()

    cwt_cbor = cbor2.loads(cwt_bytes)

    phdr = cbor2.loads(cwt_cbor.value[0]) if cwt_cbor.value[0] else None
    uhdr = cbor2.loads(cwt_cbor.value[1]) if cwt_cbor.value[1] else None
    message = cbor2.loads(cwt_cbor.value[2])
    signature = cwt_cbor.value[3]

    print("Protected header:")
    print_header(phdr)

    print("Unprotected header:")
    print_header(uhdr)

    print("Message:")
    print_message(message)

    print("Signature:", b64e(signature).decode())


if __name__ == "__main__":
    main()
