import hashlib
from pathlib import Path
from threading import Lock

# Memory cache for SHA-256 hashes, keyed by (image_path, mtime, size)
_hash_cache: dict[tuple[str, float, int], str] = {}
_cache_lock = Lock()


def get_image_hash(image_path: Path) -> str:
    """
    Compute a SHA-256 hash of a memory image file.
    To avoid repeatedly hashing multi-gigabyte files, the hash is memory-cached
    using the file's mtime and size.
    """
    try:
        stat = image_path.stat()
    except FileNotFoundError:
        raise ValueError(f"Image not found: {image_path.name}")
    except PermissionError:
        raise ValueError(f"Image is unreadable (permission denied): {image_path.name}")
    except Exception as e:
        raise ValueError(f"Failed to access image {image_path.name}: {e}")

    if stat.st_size == 0:
        raise ValueError(f"Image is empty: {image_path.name}")

    cache_key = (str(image_path), stat.st_mtime, stat.st_size)

    with _cache_lock:
        if cache_key in _hash_cache:
            return _hash_cache[cache_key]

    h = hashlib.sha256()
    try:
        with open(image_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
    except PermissionError:
        raise ValueError(f"Image is unreadable (permission denied): {image_path.name}")
    except Exception as e:
        raise ValueError(f"Failed to read image {image_path.name}: {e}")

    digest = h.hexdigest()

    with _cache_lock:
        _hash_cache[cache_key] = digest

    return digest
