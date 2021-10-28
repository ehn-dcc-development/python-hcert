import argparse
import binascii
import json
import logging

from cryptojwt.utils import b64d, b64e

from .cwt import cosekey_from_jwk_dict, read_cosekey
from .hcert import sign, verify
from .optical import save_qrcode

logger = logging.getLogger(__name__)


def command_sign(args: argparse.Namespace):
    """Create signed EHC"""

    private_key = read_cosekey(args.key, private=True)
    if args.kid:
        private_key.kid = b64d(args.kid.encode())

    with open(args.input, "rt") as input_file:
        input_data = input_file.read()

    logger.info("Input JSON data: %d bytes", len(input_data))

    eu_dgc_v1 = json.loads(input_data)
    cwt_bytes = sign(
        private_key=private_key,
        payload=eu_dgc_v1,
        issuer=args.issuer,
        ttl=args.ttl,
        sign1=args.sign1,
    )
    logger.info("Raw signed CWT: %d bytes", len(cwt_bytes))

    if args.output:
        with open(args.output, "wb") as output_file:
            output_file.write(cwt_bytes)
    else:
        logger.info("Output: %s", binascii.hexlify(cwt_bytes).decode())

    if args.qrcode:
        save_qrcode(cwt_bytes, args.qrcode)


def command_verify(args: argparse.Namespace):
    """Verify signed EHC"""

    public_keys = []
    if args.jwks:
        with open(args.jwks) as jwks_file:
            jwks = json.load(jwks_file)
            for jwk_dict in jwks.get("keys", []):
                key = cosekey_from_jwk_dict(jwk_dict, private=False)
                key.iss = jwk_dict.get("iss")
                public_keys.append(key)
    elif args.key:
        public_keys = [read_cosekey(args.key, private=False)]

    if args.kid:
        public_key.kid = b64d(args.kid.encode())

    with open(args.input, "rb") as input_file:
        signed_data = input_file.read()

    res = verify(signed_data=signed_data, public_keys=public_keys)

    logger.info("Signatured issued by: %s", res.iss)
    logger.info(
        "Signature verified by: %s (%s)",
        b64e(res.kid).decode(),
        cwt.key.iss if hasattr(cwt.key, "iss") else None,
    )
    logger.info("Signatured issued at: %s", res.iat)

    if res.expired:
        logger.warning("Signatured expired at: %s", res.exp)
    else:
        logger.info("Signatured expires at: %s", res.exp)

    if res.eu_dgc_v1 is None:
        logger.warning("No EU DCC version 1 found in payload")

    if args.output:
        with open(args.output, "wt") as output_file:
            json.dump(res.eu_dgc_v1, output_file, indent=4)
    else:
        logger.info("Verified payload: %s", json.dumps(res.eu_dgc_v1, indent=4))


def main():
    """Main function"""

    parser = argparse.ArgumentParser(
        description="Electronic Health Certificate signer/verifier"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose output",
        required=False,
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Debug output",
        required=False,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    parser_sign = subparsers.add_parser("sign", help="Sign health cert")
    parser_sign.set_defaults(func=command_sign)
    parser_sign.add_argument(
        "--key", metavar="filename", help="Private JWK filename", required=True
    )
    parser_sign.add_argument(
        "--issuer",
        metavar="issuer",
        help="Signature issuer (ISO 3166 country code)",
        required=False,
    )
    parser_sign.add_argument(
        "--ttl",
        metavar="seconds",
        help="Signature TTL",
        type=int,
        required=False,
    )
    parser_sign.add_argument(
        "--input",
        metavar="filename",
        help="JSON-encoded payload",
        required=True,
    )
    parser_sign.add_argument(
        "--output",
        metavar="filename",
        help="Binary CWT output",
        required=False,
    )
    parser_sign.add_argument(
        "--kid",
        metavar="id",
        help="Key identifier (base64url encoded)",
        required=False,
    )
    parser_sign.add_argument(
        "--qrcode",
        metavar="filename",
        help="QR output",
        required=False,
    )
    parser_sign.add_argument(
        "--sign1",
        action="store_true",
        help="Sign with COSE_Sign1",
        default=True,
    )

    parser_verify = subparsers.add_parser("verify", help="Verify signed cert")
    parser_verify.set_defaults(func=command_verify)
    parser_verify.add_argument("--key", metavar="filename", help="Public JWK filename")
    parser_verify.add_argument(
        "--jwks", metavar="filename", help="Public JWKS filename"
    )
    parser_verify.add_argument(
        "--input",
        metavar="filename",
        help="Compressed CBOR input",
        required=True,
    )
    parser_verify.add_argument(
        "--output",
        metavar="filename",
        help="JSON-encoded payload",
        required=False,
    )
    parser_verify.add_argument(
        "--kid",
        metavar="id",
        help="Key identifier (base64url encoded)",
        required=False,
    )

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    elif args.verbose:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.WARNING)

    args.func(args)


if __name__ == "__main__":
    main()
