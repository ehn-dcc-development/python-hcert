import binascii
import logging
import zlib
from typing import Optional

import base45
import qrcode
import qrcode.image.pil
import qrcode.image.svg
import qrcode.util

logger = logging.getLogger(__name__)


def compress_and_encode(data: bytes) -> bytes:
    compressed_data = zlib.compress(data, level=zlib.Z_BEST_COMPRESSION)
    encoded_compressed_data = base45.b45encode(compressed_data)
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


def decode_and_decompress(data: bytes) -> bytes:
    decoded_data = base45.b45decode(data)
    decompressed_data = zlib.decompress(decoded_data)
    logger.debug(
        "Uncompressed data: %d bytes, %s",
        len(decompressed_data),
        binascii.hexlify(decompressed_data).decode(),
    )
    return decompressed_data


def save_qrcode(payload: bytes, filename: Optional[str] = None) -> bytes:
    """Save CWT as QR Code"""
    logger.debug("Encoding %d bytes for QR", len(payload))
    qr_data = b"HC1:" + compress_and_encode(payload)
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
