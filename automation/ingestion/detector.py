# automation/ingestion/detector.py
# Detects whether a disk image is E01 or RAW format
# by reading the first 8 bytes (magic bytes) of the file.
#
# E01 files always start with: 45 56 46 09 0D 0A FF 00
# which is the ASCII string "EVF" followed by control bytes.
# RAW/DD files have no such signature — they start with raw disk data.

import os


# Magic bytes that identify an E01 (Expert Witness Format) file
EWF_SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"


def detect_format(image_path: str) -> str:
    """
    Detect the format of a forensic disk image.

    Args:
        image_path: Full path to the image file

    Returns:
        "e01" if the file is an E01/EWF image
        "raw" if the file appears to be a RAW/DD image

    Raises:
        FileNotFoundError: if the image path does not exist
        ValueError: if the file is too small to be a valid image
    """
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Image not found: {image_path}")

    file_size = os.path.getsize(image_path)
    if file_size < 8:
        raise ValueError(f"File too small to be a valid image: {image_path}")

    # Read just the first 8 bytes — no need to load the whole file
    with open(image_path, "rb") as f:
        header = f.read(8)

    if header == EWF_SIGNATURE:
        return "e01"
    else:
        return "raw"


if __name__ == "__main__":
    # Quick test — run this file directly to test detection
    import sys
    if len(sys.argv) < 2:
        print("Usage: python detector.py <image_path>")
        sys.exit(1)

    path = sys.argv[1]
    fmt = detect_format(path)
    print(f"Detected format: {fmt.upper()}")