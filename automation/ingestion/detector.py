# automation/ingestion/detector.py
# Detects whether a disk image is E01 or RAW format
# by reading the first 8 bytes (magic bytes) of the file.

import os

EWF_SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"


def detect_format(image_path: str) -> str:
    """
    Detect the format of a forensic disk image.

    Args:
        image_path: Full path to the image file

    Returns:
        "e01" if E01/EWF image, "raw" if RAW/DD image

    Raises:
        FileNotFoundError: if the image path does not exist
        ValueError: if the file is too small to be a valid image
    """
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Image not found: {image_path}")

    if os.path.getsize(image_path) < 8:
        raise ValueError(f"File too small to be a valid image: {image_path}")

    with open(image_path, "rb") as f:
        header = f.read(8)

    return "e01" if header == EWF_SIGNATURE else "raw"