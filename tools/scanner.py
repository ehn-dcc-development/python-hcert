import argparse
import json
import logging
import time
from typing import Optional

import serial
from cryptojwt.utils import b64d, b64e

from hcert.cwt import cosekey_from_jwk_dict
from hcert.hcert import verify
from hcert.optical import decode_and_decompress

logger = logging.getLogger(__name__)

DEFAULT_SCANNER_PORT = "/dev/tty.usbmodem1143101"


class SerialScanner:
    """Serial scanner"""

    def __init__(self, port: str, baudrate: Optional[int] = None) -> None:
        self.scanner = serial.Serial(port=port, baudrate=baudrate or 115200)

    def read(self) -> Optional[bytes]:
        """Read data from scanner"""
        waiting = self.scanner.inWaiting()
        if waiting > 0:
            data = self.scanner.read(waiting)
            return data
        return None

    def write(self, data: bytes) -> None:
        """Write data to scanner"""
        self.scanner.write(data)


class AccessIsAtr110(SerialScanner):
    def __init__(self, port: str, baudrate: Optional[int] = None) -> None:
        super().__init__(port, baudrate)
        self.send_modify_command("AISRDS", 1)
        self.send_modify_command("ALLENA", 1)

    def send_command(self, command: str) -> bytes:
        """Send command to scanner, return any resulting data"""
        prefix = [0x16, 0x4D, 0x0D]
        data = bytes(prefix) + command.encode()
        self.write(data)
        return self.read()

    def send_modify_command(
        self, command: str, parameter=None, permanent: bool = False
    ):
        """Send modify command to scanner"""
        if permanent:
            # modify a setting permanently
            terminator = "."
        else:
            # modify a setting temporarily
            terminator = "!"
        if parameter is not None:
            self.send_command(command + str(parameter) + terminator)
        else:
            self.send_command(command + terminator)


def process_hc1_cwt(signed_data: bytes, public_keys):

    res = verify(signed_data=signed_data, public_keys=public_keys)

    logger.info("Signatured issued by: %s", res.iss)
    logger.info("Signature verified by: %s", b64e(res.kid).decode())
    logger.info("Signatured issued at: %s", res.iat)

    if res.expired:
        logger.warning("Signatured expired at: %s", res.exp)
    else:
        logger.info("Signatured expires at: %s", res.exp)

    if res.eu_dgc_v1 is None:
        logger.warning("No EU HCERT version 1 found in payload")

    logger.info("Verified payload: %s", json.dumps(res.eu_dgc_v1, indent=4))


def main():
    parser = argparse.ArgumentParser(
        description="Electronic Health Certificate Optical Verifier"
    )
    parser.add_argument(
        "--port",
        metavar="port",
        help="Scanner serial port",
        default=DEFAULT_SCANNER_PORT,
    )
    parser.add_argument(
        "--jwks", metavar="filename", help="JWKS filename", required=True
    )
    parser.add_argument("--input", metavar="filename", help="Raw input filename")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Debug output",
        required=False,
    )
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    public_keys = []

    with open(args.jwks) as jwks_file:
        jwks = json.load(jwks_file)
        for jwk_dict in jwks.get("keys", []):
            key = cosekey_from_jwk_dict(jwk_dict, private=False)
            key.kid = b64d(jwk_dict["kid"].encode())
            public_keys.append(key)

    if args.input:
        with open(args.input, "rb") as input_file:
            data = input_file.read()
            process_hc1_cwt(data, public_keys)
        return

    scanner = AccessIsAtr110(port=args.port)
    print("Waiting for data from scanner...")
    while True:
        data = scanner.read()
        if data:
            s = data.decode()
            if s.startswith("HC1:"):
                signed_data = decode_and_decompress(data[4:])
                process_hc1_cwt(signed_data, public_keys)
        time.sleep(1)


if __name__ == "__main__":
    main()
