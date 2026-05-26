# automation/ingestion/imager.py
# Opens a forensic disk image and returns a filesystem object
# that the rest of the pipeline can walk and query.
#
# For E01 images:  uses pyewf to read the format, then wraps
#                  it in pytsk3 for filesystem access
# For RAW images:  opens directly with pytsk3
#
# The key concept: pytsk3 needs an "img_info" object to work with.
# For RAW files this is straightforward.
# For E01 files we build a custom bridge class (EWFImgInfo)
# because pytsk3 doesn't natively understand E01 — it only
# understands raw byte streams. pyewf gives us the raw bytes,
# and EWFImgInfo bridges the two libraries together.

import pyewf
import pytsk3
import os


class EWFImgInfo(pytsk3.Img_Info):
    """
    Bridge class that lets pytsk3 read an E01 image via pyewf.

    pytsk3 expects a raw byte stream.
    pyewf reads E01 files and exposes their contents as a byte stream.
    This class connects them by implementing pytsk3's read/get_size
    interface on top of pyewf's handle.
    """

    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        self._ewf_handle.close()

    def read(self, offset, length):
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(length)

    def get_size(self):
        return self._ewf_handle.get_media_size()


def open_image(image_path: str, fmt: str):
    """
    Open a forensic disk image and return an img_info object.

    Args:
        image_path: Full path to the image file
        fmt:        "e01" or "raw" (from detector.detect_format)

    Returns:
        pytsk3 Img_Info object ready for filesystem parsing

    Raises:
        FileNotFoundError: if image path does not exist
        ValueError: if format is not "e01" or "raw"
        RuntimeError: if the image cannot be opened
    """
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Image not found: {image_path}")

    if fmt == "e01":
        # Resolve to absolute path — pyewf on Windows struggles
        # with relative paths and spaces in filenames
        image_path = os.path.abspath(image_path)
        filenames = pyewf.glob(image_path)
        ewf_handle = pyewf.handle()
        ewf_handle.open(filenames)
        img_info = EWFImgInfo(ewf_handle)

    elif fmt == "raw":
        img_info = pytsk3.Img_Info(url=image_path)

    else:
        raise ValueError(f"Unsupported format: {fmt}. Use 'e01' or 'raw'.")

    return img_info


def get_filesystem(img_info, partition_offset: int = 0):
    """
    Get a filesystem object from an opened image.

    Most images have a partition table. If partition_offset is 0
    we try the image directly first, then attempt common offsets.

    Args:
        img_info:         pytsk3 Img_Info object (from open_image)
        partition_offset: byte offset to the partition (default 0)

    Returns:
        pytsk3 FS_Info object you can use to walk the filesystem

    Raises:
        RuntimeError: if no filesystem can be found
    """
    try:
        fs_info = pytsk3.FS_Info(img_info, offset=partition_offset)
        return fs_info
    except Exception as e:
        raise RuntimeError(
            f"Could not open filesystem at offset {partition_offset}. "
            f"The image may have a partition table — try get_partition_offset(). "
            f"Original error: {e}"
        )


def get_partition_offset(img_info):
    """
    Scan the partition table and return the byte offset
    of the first usable partition.

    Many forensic images contain a full disk (MBR + partitions),
    not just a single partition. pytsk3 needs to know where the
    actual filesystem starts inside the disk.

    Args:
        img_info: pytsk3 Img_Info object

    Returns:
        byte offset (int) of the first valid partition
        0 if no partition table is found (image is a bare partition)
    """
    try:
        volume = pytsk3.Volume_Info(img_info)
        sector_size = 512  # standard sector size

        for part in volume:
            # Skip metadata and unallocated partitions
            # Only return the first real data partition
            if part.flags == pytsk3.TSK_VS_PART_FLAG_ALLOC:
                offset = part.start * sector_size
                print(f"  Found partition at offset {offset} "
                      f"(sector {part.start}, "
                      f"size {part.len * sector_size / (1024**2):.1f} MB)")
                return offset

    except Exception:
        # No partition table — image is a bare filesystem
        return 0

    return 0


if __name__ == "__main__":
    # Quick test — open the image and print filesystem type
    import sys
    from detector import detect_format

    if len(sys.argv) < 2:
        print("Usage: python imager.py <image_path>")
        sys.exit(1)

    path = sys.argv[1]
    print(f"Opening: {path}")

    fmt = detect_format(path)
    print(f"Format : {fmt.upper()}")

    img  = open_image(path, fmt)
    offset = get_partition_offset(img)

    # Re-open for filesystem (partition scan consumed the handle)
    img  = open_image(path, fmt)
    fs   = get_filesystem(img, offset)

    fs_types = {
        pytsk3.TSK_FS_TYPE_NTFS: "NTFS",
        pytsk3.TSK_FS_TYPE_FAT12: "FAT12",
        pytsk3.TSK_FS_TYPE_FAT16: "FAT16",
        pytsk3.TSK_FS_TYPE_FAT32: "FAT32",
        pytsk3.TSK_FS_TYPE_EXFAT: "exFAT",
        pytsk3.TSK_FS_TYPE_EXT2: "EXT2",
        pytsk3.TSK_FS_TYPE_EXT3: "EXT3",
        pytsk3.TSK_FS_TYPE_EXT4: "EXT4",
    }

    fs_type = fs_types.get(fs.info.ftype, f"Unknown({fs.info.ftype})")
    print(f"Filesystem: {fs_type}")
    print(f"Block size: {fs.info.block_size} bytes")
    print(f"Total blocks: {fs.info.block_count}")