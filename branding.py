"""Shared branding settings and inert image asset validation."""

import base64
import binascii
import json
import re
import struct
import zlib
from pathlib import Path

DEFAULT_COLORS = {
    "light": {"accent": "#64748B", "background": "#F4F5F6", "surface": "#FFFFFF", "text": "#1F2933"},
    "dark": {"accent": "#94A3B8", "background": "#111315", "surface": "#1B1F22", "text": "#F3F4F6"},
}
ASSET_KEYS = {"light_logo", "dark_logo", "favicon", "sso_logo"}
COLOR_KEYS = {"accent", "background", "surface", "text"}
HEX_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")
DEFAULTS = {
    "app_name": "Camera Health Monitor",
    "colors": DEFAULT_COLORS,
    "assets": {key: None for key in ASSET_KEYS},
    "sso_button_text": "Sign in with single sign-on",
}


class BrandingError(ValueError):
    pass


def load(db):
    row = db.execute("SELECT value_json FROM settings WHERE key='branding'").fetchone()
    saved = json.loads(row[0]) if row else {}
    result = {**DEFAULTS, **saved}
    result.pop("theme", None)  # Theme is a browser-local choice, never shared.
    result["colors"] = {theme: {**DEFAULT_COLORS[theme], **(saved.get("colors", {}).get(theme) or {})} for theme in ("light", "dark")}
    result["assets"] = {**DEFAULTS["assets"], **(saved.get("assets") or {})}
    return result


def validate(payload):
    if not isinstance(payload, dict):
        raise BrandingError("invalid_branding")
    name = payload.get("app_name")
    label = payload.get("sso_button_text")
    colors = payload.get("colors")
    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 80 or any(ord(c) < 32 for c in name):
        raise BrandingError("invalid_app_name")
    if not isinstance(label, str) or not label.strip() or len(label.strip()) > 80 or any(ord(c) < 32 for c in label):
        raise BrandingError("invalid_sso_button_text")
    if not isinstance(colors, dict) or set(colors) != {"light", "dark"}:
        raise BrandingError("invalid_colors")
    cleaned_colors = {}
    for theme in ("light", "dark"):
        values = colors[theme]
        if not isinstance(values, dict) or set(values) != COLOR_KEYS or not all(isinstance(v, str) and HEX_COLOR.fullmatch(v) for v in values.values()):
            raise BrandingError("invalid_colors")
        cleaned_colors[theme] = {key: value.upper() for key, value in values.items()}
    return {"app_name": name.strip(), "sso_button_text": label.strip(), "colors": cleaned_colors}


def _png_dimensions(data, max_dimension):
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return None
    offset, dimensions, ended, compressed, color_type = 8, None, False, bytearray(), None
    while offset + 12 <= len(data):
        size = struct.unpack(">I", data[offset:offset + 4])[0]
        kind = data[offset + 4:offset + 8]
        end = offset + 12 + size
        if size > len(data) or end > len(data):
            return None
        chunk = data[offset + 4:offset + 8 + size]
        crc = struct.unpack(">I", data[offset + 8 + size:end])[0]
        if zlib.crc32(chunk) & 0xffffffff != crc:
            return None
        if kind == b"IHDR" and size == 13 and offset == 8:
            width, height, bit_depth, color_type, compression, filtering, interlace = struct.unpack(">IIBBBBB", data[offset + 8:offset + 21])
            valid_depths = {0: {1, 2, 4, 8, 16}, 2: {8, 16}, 3: {1, 2, 4, 8}, 4: {8, 16}, 6: {8, 16}}
            if not width or not height or max(width, height) > max_dimension or bit_depth not in valid_depths.get(color_type, set()) or compression or filtering or interlace:
                return None
            dimensions = (width, height)
        if kind == b"IDAT":
            compressed.extend(data[offset + 8:offset + 8 + size])
        if kind == b"IEND":
            if size != 0 or end != len(data):
                return None
            ended = True
            break
        offset = end
    if not ended or not dimensions or not compressed:
        return None
    width, height = dimensions
    bits_per_pixel = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color_type] * bit_depth
    row_bytes = (width * bits_per_pixel + 7) // 8
    expected = height * (row_bytes + 1)
    if expected > 64 * 1024 * 1024:
        return None
    try:
        decoder = zlib.decompressobj()
        decoded = decoder.decompress(bytes(compressed), expected + 1)
        if len(decoded) != expected or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            return None
    except zlib.error:
        return None
    if any(decoded[row * (row_bytes + 1)] > 4 for row in range(height)):
        return None
    return dimensions


def _jpeg_dimensions(data):
    if not data.startswith(b"\xff\xd8") or not data.endswith(b"\xff\xd9"):
        return None
    i = 2
    while i < len(data) - 4:
        if data[i] != 0xff:
            i += 1
            continue
        while i < len(data) and data[i] == 0xff:
            i += 1
        marker = data[i]
        i += 1
        if marker in (0xd8, 0xd9) or 0xd0 <= marker <= 0xd7:
            continue
        if i + 2 > len(data):
            return None
        length = struct.unpack(">H", data[i:i + 2])[0]
        if length < 2 or i + length > len(data):
            return None
        if marker in {0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf}:
            if length < 7:
                return None
            height, width = struct.unpack(">HH", data[i + 3:i + 7])
            return (width, height)
        i += length
    return None


def validate_image(encoded, asset_key):
    if asset_key not in ASSET_KEYS or not isinstance(encoded, str) or len(encoded) > 2_800_000:
        raise BrandingError("invalid_image")
    try:
        data = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise BrandingError("invalid_image") from None
    max_bytes, max_dimension = (512 * 1024, 512) if asset_key == "favicon" else (2 * 1024 * 1024, 2048)
    if not data or len(data) > max_bytes:
        raise BrandingError("invalid_image_size")
    dimensions = _png_dimensions(data, max_dimension)
    content_type = "image/png"
    if dimensions is None:
        dimensions = _jpeg_dimensions(data)
        content_type = "image/jpeg"
    if not dimensions or min(dimensions) < 1 or max(dimensions) > max_dimension:
        raise BrandingError("invalid_image")
    return data, content_type


def asset_path(data_dir, key):
    return Path(data_dir) / "branding-assets" / f"{key}.img"
