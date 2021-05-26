"""Tool to process DGC test data"""

import argparse
import datetime
import json
import logging
import sys
from datetime import timezone

from cryptojwt.utils import b64e
from deepdiff import DeepDiff

from hcert.cwt import cosekey_from_jwk_dict
from hcert.hcert import verify
from hcert.optical import decode_and_decompress
from hcert.utils import pem_to_jwk_dict

PEM_CERT_START_DELIMITER = "-----BEGIN CERTIFICATE-----"
PEM_CERT_END_DELIMITER = "-----END CERTIFICATE-----"

TIMESTAMP_ISO8601_EXTENDED = "%Y-%m-%dT%H:%M:%S.%fZ"

logger = logging.getLogger(__name__)


def json_datetime_encoder(o):
    """Encoding JSON with datetime"""
    if isinstance(o, (datetime.date, datetime.datetime)):
        return o.astimezone(timezone.utc).strftime(TIMESTAMP_ISO8601_EXTENDED)


def canonicalize_dict(d: dict) -> dict:
    """Canonicalize dict using JSON"""
    return json.loads(
        json.dumps(d, indent=4, sort_keys=True, default=json_datetime_encoder)
    )


def main():
    """Main function"""

    parser = argparse.ArgumentParser(description="DGC test eval")

    parser.add_argument(
        "testfile",
        metavar="filename",
        help="Test filename",
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

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    elif args.verbose:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.WARNING)

    with open(args.testfile) as input_file:
        testdata = json.load(input_file)

    certificate_data = testdata["TESTCTX"]["CERTIFICATE"]

    cert_pem = (
        PEM_CERT_START_DELIMITER
        + "\n"
        + certificate_data
        + "\n"
        + PEM_CERT_END_DELIMITER
    )
    jwk_dict = pem_to_jwk_dict(cert_pem)
    public_key = cosekey_from_jwk_dict(jwk_dict, private=False)

    reference_payload = testdata.get("JSON")

    optical_payload = testdata["PREFIX"]
    assert optical_payload.startswith("HC1:")

    if (base45_payload := testdata.get("BASE45")) :
        assert optical_payload[4:] == base45_payload
    else:
        base45_payload = optical_payload[4:]

    signed_data = decode_and_decompress(base45_payload.encode())

    res = verify(signed_data=signed_data, public_keys=[public_key])
    logger.info("Signature verified")

    if res.eu_dgc_v1 is None:
        logger.warning("No EU DGC version 1 found in payload")
        sys.exit(-1)

    if reference_payload:
        reference_serialized = canonicalize_dict(reference_payload)
        verified_serialized = canonicalize_dict(res.eu_dgc_v1)
        ddiff = DeepDiff(reference_serialized, verified_serialized)

        if ddiff:
            logger.error("Reference data does not match payload")
            print(json.dumps(ddiff, indent=4))
            sys.exit(-1)
        else:
            logger.info("Reference data match payload")
            logger.info("Reference payload: %s", reference_serialized)
            logger.info("Verified payload: %s", verified_serialized)
            sys.exit(0)
    else:
        logger.warning("Reference data not checked")


if __name__ == "__main__":
    main()
