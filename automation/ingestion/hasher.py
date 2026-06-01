# automation/ingestion/hasher.py
# Computes and verifies cryptographic hashes of forensic disk images.
# Streams in chunks — handles images of any size without memory issues.

import hashlib
import os
from tqdm import tqdm

CHUNK_SIZE = 65536  # 64KB


def compute_hash(image_path: str) -> dict:
    """
    Compute MD5 and SHA256 hashes of any file in a single pass.

    Args:
        image_path: Full path to the file

    Returns:
        dict with keys "md5" and "sha256"
    """
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"File not found: {image_path}")

    file_size = os.path.getsize(image_path)
    md5    = hashlib.md5()
    sha256 = hashlib.sha256()

    with open(image_path, "rb") as f:
        with tqdm(
            total=file_size,
            unit="B",
            unit_scale=True,
            desc=f"Hashing {os.path.basename(image_path)}",
            colour="cyan"
        ) as pbar:
            while chunk := f.read(CHUNK_SIZE):
                md5.update(chunk)
                sha256.update(chunk)
                pbar.update(len(chunk))

    return {
        "md5":    md5.hexdigest(),
        "sha256": sha256.hexdigest()
    }