import argparse
import binascii

import cbor2
from cryptojwt.utils import b64e

from hcert.cwt import CwtClaims


def print_hdr(hdr):
    if isinstance(hdr, dict):
        for k, v in hdr.items():
            claim = CwtClaims(k)
            if isinstance(v, bytes):
                v = "{hex}" + binascii.hexlify(v).decode()
            print(f"  {claim.name.lower()} ({k}) = {v}")


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
    print_hdr(phdr)

    print("Unprotected header:")
    print_hdr(uhdr)

    print("Message:", message)
    print("Signature:", b64e(signature).decode())


if __name__ == "__main__":
    main()
