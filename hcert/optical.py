import binascii
import logging
import math
import zlib
from base64 import b32decode, b32encode
from typing import Optional

import qrcode
import qrcode.image.pil
import qrcode.image.svg
import qrcode.util
from base45 import b45decode, b45encode

logger = logging.getLogger(__name__)


def remove_padding(data: bytes) -> bytes:
    return data.decode().replace("=", "").encode()


def add_padding(data: bytes) -> bytes:
    pad_length = math.ceil(len(data) / 8) * 8 - len(data)
    return data + b"=" * pad_length


def compress_and_encode(data: bytes, encoding: str = "base45") -> bytes:
    compressed_data = zlib.compress(data, level=zlib.Z_BEST_COMPRESSION)
    if encoding == "base45":
        encoded_compressed_data = b45encode(compressed_data)
    elif encoding == "base32":
        encoded_compressed_data = remove_padding(b32encode(compressed_data))
    else:
        raise ValueError("Unknown encoding")
    logger.debug(
        "Uncompressed data: %d bytes, %s",
        len(data),
        binascii.hexlify(data).decode(),
    )
    logger.debug(
        "Compressed data: %d bytes, %s",
        len(compressed_data),
        binascii.hexlify(compressed_data).decode(),
    )
    logger.debug(
        "Encoded compressed data: %d bytes, %s",
        len(encoded_compressed_data),
        binascii.hexlify(encoded_compressed_data).decode(),
    )
    return encoded_compressed_data


def decode_and_decompress(data: bytes, encoding: str = "base45") -> bytes:
    if encoding == "base45":
        decoded_data = b45decode(data)
    elif encoding == "base32":
        decoded_data = b32decode(add_padding(data))
    else:
        raise ValueError("Unknown encoding")
    decompressed_data = zlib.decompress(decoded_data)
    logger.debug(
        "Uncompressed data: %d bytes, %s",
        len(decompressed_data),
        binascii.hexlify(decompressed_data).decode(),
    )
    return decompressed_data


def save_qrcode(
    payload: bytes, filename: Optional[str] = None, version: int = 1
) -> bytes:
    """Save CWT as QR Code"""
    logger.debug("Encoding %d bytes for QR", len(payload))
    if version == 1:
        qr_data = b"HC1:" + compress_and_encode(payload, "base45")
    elif version == 2:
        qr_data = b"HC2:" + compress_and_encode(payload, "base32")
    else:
        raise ValueError("Invalid version")
    logger.info("QR data: %s", qr_data)
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_Q,
        box_size=4,
        border=4,
    )
    if filename is None or filename.endswith(".png"):
        image_factory = qrcode.image.pil.PilImage
    elif filename.endswith(".svg"):
        image_factory = qrcode.image.svg.SvgImage
    else:
        raise ValueError("Unknown QRcode image format")
    qr.add_data(qr_data, optimize=0)
    assert qr.data_list[0].mode == qrcode.util.MODE_ALPHA_NUM
    qr.make(fit=True)
    img = qr.make_image(image_factory=image_factory)
    if filename:
        with open(filename, "wb") as qr_file:
            img.save(qr_file)
        logger.info("Wrote %d bytes as QR to %s", len(qr_data), filename)
    else:
        return img.tobytes()
