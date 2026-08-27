"""
file_service.py
================
Secure file handling: sanitized random filenames, extension allow-listing,
path-traversal protection, and basic "magic bytes" validation for image
carriers so a renamed non-image file can't be smuggled in as a cover image.
"""
import os
import uuid
from werkzeug.utils import secure_filename

IMAGE_MAGIC_BYTES = {
    b"\x89PNG\r\n\x1a\n": "png",
    b"BM": "bmp",
}


def allowed_file(filename: str, allowed_extensions: set) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in allowed_extensions


def get_extension(filename: str) -> str:
    if "." not in filename:
        return ""
    return filename.rsplit(".", 1)[1].lower()


def generate_safe_filename(original_filename: str) -> str:
    """Random server-side filename; never trust the client-supplied name."""
    ext = get_extension(secure_filename(original_filename))
    random_name = uuid.uuid4().hex
    return f"{random_name}.{ext}" if ext else random_name


def safe_join(base_dir: str, filename: str) -> str:
    """Join a filename to a base directory, refusing any path traversal attempt."""
    filename = secure_filename(filename)
    full_path = os.path.abspath(os.path.join(base_dir, filename))
    base_abs = os.path.abspath(base_dir)
    if not full_path.startswith(base_abs + os.sep) and full_path != base_abs:
        raise ValueError("Invalid file path detected (path traversal blocked).")
    return full_path


def validate_image_magic_bytes(filepath: str) -> bool:
    """Check the file actually starts with PNG or BMP magic bytes (not just extension)."""
    try:
        with open(filepath, "rb") as f:
            header = f.read(8)
    except OSError:
        return False

    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return True
    if header.startswith(b"BM"):
        return True
    return False


def human_readable_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"
