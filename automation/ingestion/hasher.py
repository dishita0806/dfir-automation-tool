# automation/ingestion/hasher.py
# Computes and verifies cryptographic hashes of forensic disk images.
#
# Why we stream in chunks:
# Forensic images can be 50GB, 500GB, or larger.
# Loading the whole file into memory would crash your machine.
# Instead we read 64KB at a time, feeding each chunk to the hash
# function incrementally — same result, almost zero memory usage.

import hashlib
import os
from tqdm import tqdm


CHUNK_SIZE = 65536  # 64KB per read — memory efficient for large images


def compute_hash(image_path: str) -> dict:
    """
    Compute MD5 and SHA256 hashes of a file simultaneously.
    Both are computed in a single pass through the file.

    Args:
        image_path: Full path to the image file

    Returns:
        dict with keys "md5" and "sha256", values are hex strings

    Raises:
        FileNotFoundError: if the image path does not exist
    """
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Image not found: {image_path}")

    file_size = os.path.getsize(image_path)
    md5    = hashlib.md5()
    sha256 = hashlib.sha256()

    # tqdm gives us a progress bar — important for large images
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


def verify_hash(image_path: str, expected_sha256: str) -> bool:
    """
    Verify a file's SHA256 hash against an expected value.
    Used to confirm the image hasn't been tampered with.

    Args:
        image_path:      Full path to the image file
        expected_sha256: The known-good SHA256 hash to compare against

    Returns:
        True if hashes match, False if they don't
    """
    hashes = compute_hash(image_path)
    computed = hashes["sha256"].lower()
    expected = expected_sha256.lower().strip()

    match = computed == expected

    if match:
        print(f"  ✓ Hash verified — image is intact")
    else:
        print(f"  ✗ Hash MISMATCH — image may be corrupted or tampered")
        print(f"    Expected : {expected}")
        print(f"    Computed : {computed}")

    return match


if __name__ == "__main__":
    # Quick test — run directly to hash your image
    import sys
    if len(sys.argv) < 2:
        print("Usage: python hasher.py <image_path>")
        sys.exit(1)

    path = sys.argv[1]
    result = compute_hash(path)
    print(f"\n  MD5    : {result['md5']}")
    print(f"  SHA256 : {result['sha256']}")