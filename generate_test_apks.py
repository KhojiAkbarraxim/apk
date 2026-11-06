#!/usr/bin/env python3
"""
generate_test_apks.py – build three synthetic test APK files for the
Android Malware Analyzer Bot.

Each APK contains:
  • A valid Android Binary XML (AXML) AndroidManifest.xml
  • A valid DEX file with embedded strings that trigger YARA / hardcoded
    detectors

No Android SDK is needed.  Everything is built with struct + zipfile.

SYNTHETIC TEST FILES FOR DEFENSIVE SECURITY RESEARCH ONLY.
All tokens, URLs and IPs are fake / reserved.
"""

import base64
import hashlib
import io
import os
import struct
import zipfile
import zlib

# ──────────────────────────────────────────────────────────────────────
# DEX CONSTRUCTION
# ──────────────────────────────────────────────────────────────────────

def _uleb128(value: int) -> bytes:
    """Encode an unsigned integer as ULEB128."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        out.append(byte)
        if not value:
            break
    return bytes(out)


def _align(offset: int, alignment: int = 4) -> int:
    return (offset + alignment - 1) & ~(alignment - 1)


def _pad_to(data: bytearray, alignment: int = 4):
    while len(data) % alignment:
        data.append(0)


def build_dex(strings: list[str]) -> bytes:
    """
    Build a minimal but valid DEX 035 file whose string table contains
    the given strings.  The file has:
      header | string_ids | type_ids | string_data | map_list

    No class_defs, methods, fields, protos are needed – androguard will
    happily parse a DEX that only defines strings, and YARA scans raw bytes.
    """
    # --- 1. Build string data items (MUTF-8 encoding) ---
    string_data_items = []
    for s in strings:
        encoded = s.encode("utf-8")  # MUTF-8 ≈ UTF-8 for BMP chars
        item = _uleb128(len(s)) + encoded + b"\x00"
        string_data_items.append(item)

    # --- 2. Calculate section offsets ---
    HEADER_SIZE = 0x70  # 112 bytes

    string_ids_off = HEADER_SIZE
    string_ids_size = len(strings)
    string_ids_bytes = string_ids_size * 4  # each string_id_item is 4 bytes

    # We need at least one type so androguard doesn't complain
    type_ids_off = string_ids_off + string_ids_bytes
    type_ids_size = 1  # single type pointing to first string
    type_ids_bytes = type_ids_size * 4

    # String data starts after type_ids, aligned to 4
    string_data_off = _align(type_ids_off + type_ids_bytes)

    # Compute the offsets for each string_data_item
    current_off = string_data_off
    string_data_offsets = []
    for item in string_data_items:
        string_data_offsets.append(current_off)
        current_off += len(item)

    string_data_end = current_off

    # Map list comes after string data, aligned to 4
    map_off = _align(string_data_end)

    # Map list: 4 entries (header, string_id, type_id, string_data, map_list)
    MAP_ITEM_SIZE = 12  # type(2) + unused(2) + size(4) + offset(4)
    map_entry_count = 5
    map_list_size = 4 + map_entry_count * MAP_ITEM_SIZE  # size field + entries

    file_size = map_off + map_list_size
    data_off = string_data_off
    data_size = file_size - data_off

    # --- 3. Assemble the DEX ---
    buf = bytearray()

    # Header
    buf += b"dex\n035\x00"          # magic (8 bytes)
    buf += b"\x00" * 4              # checksum placeholder (4 bytes) [offset 8]
    buf += b"\x00" * 20             # SHA-1 signature placeholder (20 bytes) [offset 12]
    buf += struct.pack("<I", file_size)      # file_size [offset 32]
    buf += struct.pack("<I", HEADER_SIZE)    # header_size [offset 36]
    buf += struct.pack("<I", 0x12345678)     # endian_tag [offset 40]
    buf += struct.pack("<I", 0)              # link_size [offset 44]
    buf += struct.pack("<I", 0)              # link_off [offset 48]
    buf += struct.pack("<I", map_off)        # map_off [offset 52]
    buf += struct.pack("<I", string_ids_size)  # string_ids_size [offset 56]
    buf += struct.pack("<I", string_ids_off)   # string_ids_off [offset 60]
    buf += struct.pack("<I", type_ids_size)     # type_ids_size [offset 64]
    buf += struct.pack("<I", type_ids_off)      # type_ids_off [offset 68]
    buf += struct.pack("<I", 0)              # proto_ids_size [offset 72]
    buf += struct.pack("<I", 0)              # proto_ids_off [offset 76]
    buf += struct.pack("<I", 0)              # field_ids_size [offset 80]
    buf += struct.pack("<I", 0)              # field_ids_off [offset 84]
    buf += struct.pack("<I", 0)              # method_ids_size [offset 88]
    buf += struct.pack("<I", 0)              # method_ids_off [offset 92]
    buf += struct.pack("<I", 0)              # class_defs_size [offset 96]
    buf += struct.pack("<I", 0)              # class_defs_off [offset 100]
    buf += struct.pack("<I", data_size)      # data_size [offset 104]
    buf += struct.pack("<I", data_off)       # data_off [offset 108]

    assert len(buf) == HEADER_SIZE

    # String ID items (uint32 offsets to string_data_items)
    for off in string_data_offsets:
        buf += struct.pack("<I", off)

    # Type ID items (uint32 indices into string_ids)
    buf += struct.pack("<I", 0)  # type 0 → string 0

    # Padding to string_data_off
    _pad_to(buf, 4)
    while len(buf) < string_data_off:
        buf.append(0)

    # String data items
    for item in string_data_items:
        buf += item

    # Padding to map_off
    while len(buf) < map_off:
        buf.append(0)

    # Map list
    TYPE_HEADER_ITEM     = 0x0000
    TYPE_STRING_ID_ITEM  = 0x0001
    TYPE_TYPE_ID_ITEM    = 0x0002
    TYPE_STRING_DATA_ITEM = 0x2002
    TYPE_MAP_LIST        = 0x1000

    buf += struct.pack("<I", map_entry_count)

    # map_item: type(u16), unused(u16), size(u32), offset(u32)
    buf += struct.pack("<HHI I", TYPE_HEADER_ITEM, 0, 1, 0)
    buf += struct.pack("<HHI I", TYPE_STRING_ID_ITEM, 0, string_ids_size, string_ids_off)
    buf += struct.pack("<HHI I", TYPE_TYPE_ID_ITEM, 0, type_ids_size, type_ids_off)
    buf += struct.pack("<HHI I", TYPE_STRING_DATA_ITEM, 0, string_ids_size, string_data_off)
    buf += struct.pack("<HHI I", TYPE_MAP_LIST, 0, 1, map_off)

    assert len(buf) == file_size

    # --- 4. Compute checksum and signature ---
    # SHA-1 over bytes[32:]
    sha1 = hashlib.sha1(buf[32:]).digest()
    buf[12:32] = sha1

    # Adler32 over bytes[12:]
    checksum = zlib.adler32(bytes(buf[12:])) & 0xFFFFFFFF
    struct.pack_into("<I", buf, 8, checksum)

    return bytes(buf)


# ──────────────────────────────────────────────────────────────────────
# AXML (ANDROID BINARY XML) CONSTRUCTION
# ──────────────────────────────────────────────────────────────────────
# We build the binary XML step-by-step, keeping the string pool at front.

# Chunk types
RES_NULL_TYPE              = 0x0000
RES_STRING_POOL_TYPE       = 0x0001
RES_XML_TYPE               = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE   = 0x0101
RES_XML_START_ELEMENT_TYPE   = 0x0102
RES_XML_END_ELEMENT_TYPE     = 0x0103
RES_XML_RESOURCE_MAP_TYPE    = 0x0180

# Android resource attribute IDs
ATTR_IDS = {
    "versionCode":      0x0101021b,
    "versionName":      0x0101021c,
    "minSdkVersion":    0x0101020c,
    "targetSdkVersion": 0x01010270,
    "name":             0x01010003,
    "permission":       0x01010006,
    "priority":         0x0101001c,
    "enabled":          0x0101000e,
    "exported":         0x01010010,
    "label":            0x01010001,
    "theme":            0x01010000,
    "icon":             0x01010002,
    "resource":         0x01010025,
    "value":            0x01010024,
}

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Typed value types
TYPE_NULL      = 0x00
TYPE_REFERENCE = 0x01
TYPE_STRING    = 0x03
TYPE_INT_DEC   = 0x10
TYPE_INT_HEX   = 0x11
TYPE_INT_BOOLEAN = 0x12


class AXMLBuilder:
    """Builds a valid Android Binary XML (AXML) document."""

    def __init__(self):
        self._strings = []       # list of str
        self._string_map = {}    # str -> index
        self._resource_ids = []  # list of (attr_name_index, resource_id) pairs
        self._body_chunks = []   # list of bytes

        # Pre-register the android namespace strings
        self._ns_prefix_idx = self._add_string("android")
        self._ns_uri_idx = self._add_string(ANDROID_NS)

    def _add_string(self, s: str) -> int:
        if s in self._string_map:
            return self._string_map[s]
        idx = len(self._strings)
        self._strings.append(s)
        self._string_map[s] = idx
        return idx

    def _add_attr_string(self, name: str) -> int:
        """Add an attribute name string and register its resource ID if known."""
        idx = self._add_string(name)
        if name in ATTR_IDS and (idx, ATTR_IDS[name]) not in self._resource_ids:
            self._resource_ids.append((idx, ATTR_IDS[name]))
        return idx

    def start_namespace(self, prefix: str = "android", uri: str = ANDROID_NS):
        chunk = struct.pack("<HHI", RES_XML_START_NAMESPACE_TYPE, 0x10, 24)
        chunk += struct.pack("<II", 0, 0xFFFFFFFF)  # lineNumber, comment
        chunk += struct.pack("<II", self._string_map[prefix], self._string_map[uri])
        self._body_chunks.append(chunk)

    def end_namespace(self, prefix: str = "android", uri: str = ANDROID_NS):
        chunk = struct.pack("<HHI", RES_XML_END_NAMESPACE_TYPE, 0x10, 24)
        chunk += struct.pack("<II", 0, 0xFFFFFFFF)
        chunk += struct.pack("<II", self._string_map[prefix], self._string_map[uri])
        self._body_chunks.append(chunk)

    def start_element(self, name: str, attrs: list = None,
                      ns: str = None, line: int = 0):
        """
        attrs: list of (attr_name, attr_value, value_type, data) tuples.
          For string attrs: (name, "value", TYPE_STRING, None) -- data computed from string pool
          For int attrs: (name, None, TYPE_INT_DEC, int_value)
          For bool attrs: (name, None, TYPE_INT_BOOLEAN, 0 or 0xFFFFFFFF)
        """
        if attrs is None:
            attrs = []

        name_idx = self._add_string(name)
        ns_idx = self._string_map.get(ns, 0xFFFFFFFF) if ns else 0xFFFFFFFF

        # Pre-register all attribute name and value strings
        attr_entries = []
        for attr_name, attr_value, val_type, data in attrs:
            attr_name_idx = self._add_attr_string(attr_name)

            if val_type == TYPE_STRING:
                value_str_idx = self._add_string(attr_value)
                raw_value_idx = value_str_idx
                typed_data = value_str_idx
            elif val_type in (TYPE_INT_DEC, TYPE_INT_HEX, TYPE_INT_BOOLEAN):
                raw_value_idx = 0xFFFFFFFF
                typed_data = data & 0xFFFFFFFF
                if attr_value is not None:
                    self._add_string(str(attr_value))
                    raw_value_idx = self._string_map[str(attr_value)]
            elif val_type == TYPE_REFERENCE:
                raw_value_idx = 0xFFFFFFFF
                typed_data = data & 0xFFFFFFFF
            else:
                raw_value_idx = 0xFFFFFFFF
                typed_data = 0

            attr_entries.append((attr_name_idx, raw_value_idx, val_type, typed_data))

        # Each attribute is 20 bytes (5 x uint32):
        #   ns(4) name(4) rawValue(4) typedValue(size=2 res0=1 dataType=1 data=4 = 8)
        attr_count = len(attr_entries)
        # Chunk size: header(16) + ext(20) + attrs(20*n)
        chunk_size = 16 + 20 + attr_count * 20

        chunk = struct.pack("<HHI", RES_XML_START_ELEMENT_TYPE, 0x10, chunk_size)
        chunk += struct.pack("<II", line, 0xFFFFFFFF)  # lineNumber, comment
        # Element ext: ns, name, attributeStart, attributeSize, attributeCount, idIndex, classIndex, styleIndex
        chunk += struct.pack("<II", ns_idx, name_idx)
        chunk += struct.pack("<HHHHHH", 0x14, 0x14, attr_count, 0, 0, 0)

        for attr_name_idx, raw_value_idx, val_type, typed_data in attr_entries:
            # Attribute: ns(4) + name(4) + rawValue(4) + typedValue(8)
            # typedValue: size(2)=8, res0(1)=0, dataType(1), data(4)
            attr_ns = self._ns_uri_idx  # all attrs are in android namespace unless otherwise
            chunk += struct.pack("<III", attr_ns, attr_name_idx, raw_value_idx)
            chunk += struct.pack("<HBB I", 8, 0, val_type, typed_data)

        self._body_chunks.append(chunk)

    def end_element(self, name: str, ns: str = None, line: int = 0):
        name_idx = self._string_map[name]
        ns_idx = self._string_map.get(ns, 0xFFFFFFFF) if ns else 0xFFFFFFFF
        chunk = struct.pack("<HHI", RES_XML_END_ELEMENT_TYPE, 0x10, 24)
        chunk += struct.pack("<II", line, 0xFFFFFFFF)
        chunk += struct.pack("<II", ns_idx, name_idx)
        self._body_chunks.append(chunk)

    def _build_string_pool(self) -> bytes:
        """Build the RES_STRING_POOL_TYPE chunk (UTF-8 mode)."""
        flags = 0x100  # UTF-8
        string_count = len(self._strings)
        style_count = 0

        # Build string data: for UTF-8 mode, each entry is:
        #   uint16_charLen (as ULEB-ish, actually just the char count encoded as 1-2 bytes)
        #   uint16_byteLen (same encoding)
        #   utf8_bytes + 0x00
        # But simpler: Android's actual format for UTF-8 strings in string pool is:
        #   - charLen encoded as 1 or 2 bytes (if <128: 1 byte, else 2 bytes with high bit)
        #   - byteLen encoded as 1 or 2 bytes (same)
        #   - UTF-8 data
        #   - 0x00 terminator
        string_data = bytearray()
        offsets = []

        for s in self._strings:
            offsets.append(len(string_data))
            encoded = s.encode("utf-8")
            char_len = len(s)
            byte_len = len(encoded)

            # Encode char_len (1 or 2 bytes)
            if char_len > 0x7F:
                string_data.append(((char_len >> 8) & 0x7F) | 0x80)
                string_data.append(char_len & 0xFF)
            else:
                string_data.append(char_len & 0x7F)

            # Encode byte_len (1 or 2 bytes)
            if byte_len > 0x7F:
                string_data.append(((byte_len >> 8) & 0x7F) | 0x80)
                string_data.append(byte_len & 0xFF)
            else:
                string_data.append(byte_len & 0x7F)

            string_data += encoded
            string_data.append(0x00)

        # String pool header
        POOL_HEADER_SIZE = 28
        offsets_bytes = b"".join(struct.pack("<I", o) for o in offsets)
        strings_start = POOL_HEADER_SIZE + len(offsets_bytes)

        # Total chunk size
        chunk_size = strings_start + len(string_data)
        # Align to 4
        while chunk_size % 4:
            string_data.append(0)
            chunk_size += 1

        pool = struct.pack("<HHI", RES_STRING_POOL_TYPE, POOL_HEADER_SIZE, chunk_size)
        pool += struct.pack("<IIIII",
                            string_count,   # stringCount
                            style_count,    # styleCount
                            flags,          # flags (UTF-8)
                            strings_start,  # stringsStart
                            0)              # stylesStart
        pool += offsets_bytes
        pool += bytes(string_data)

        return pool

    def _build_resource_map(self) -> bytes:
        """Build the RES_XML_RESOURCE_MAP_TYPE chunk."""
        if not self._resource_ids:
            return b""

        # Sort resource IDs by their string index
        self._resource_ids.sort(key=lambda x: x[0])

        # The resource map has one entry for each attribute string index
        # from 0 up to the max attribute string index.
        max_idx = max(idx for idx, _ in self._resource_ids)
        res_map = [0] * (max_idx + 1)
        for idx, res_id in self._resource_ids:
            res_map[idx] = res_id

        data = b"".join(struct.pack("<I", rid) for rid in res_map)
        header = struct.pack("<HHI", RES_XML_RESOURCE_MAP_TYPE, 8, 8 + len(data))
        return header + data

    def build(self) -> bytes:
        """Assemble the complete AXML document."""
        # We need to finalize strings first (body_chunks are already recorded),
        # then build the pool. But body_chunks might reference string indices
        # that were added during element construction.

        string_pool = self._build_string_pool()
        resource_map = self._build_resource_map()

        body = b"".join(self._body_chunks)

        total_size = 8 + len(string_pool) + len(resource_map) + len(body)
        header = struct.pack("<HHI", RES_XML_TYPE, 8, total_size)

        return header + string_pool + resource_map + body


def build_axml_manifest(config: dict) -> bytes:
    """
    Build an Android Binary XML manifest from a config dict.

    Config keys:
      package: str
      version_code: int
      version_name: str
      min_sdk: int
      target_sdk: int
      permissions: list[str]
      activities: list[dict] with keys: name, launcher (bool), exported (bool)
      receivers: list[dict] with keys: name, actions (list[str]), priority (int), permission (str)
      services: list[dict] with keys: name, permission (str), actions (list[str])
    """
    ax = AXMLBuilder()

    # Pre-register strings that need to be in the pool for element/attr names
    ax._add_string("manifest")
    ax._add_string("uses-sdk")
    ax._add_string("uses-permission")
    ax._add_string("application")
    ax._add_string("activity")
    ax._add_string("receiver")
    ax._add_string("service")
    ax._add_string("intent-filter")
    ax._add_string("action")
    ax._add_string("category")
    ax._add_string("meta-data")
    # Also pre-register common attribute value strings
    ax._add_string(config["package"])
    ax._add_string(config.get("version_name", "1.0"))

    ax.start_namespace()

    # <manifest> with package, versionCode, versionName
    ax.start_element("manifest", attrs=[
        ("package", config["package"], TYPE_STRING, None),
        ("versionCode", None, TYPE_INT_DEC, config.get("version_code", 1)),
        ("versionName", config.get("version_name", "1.0"), TYPE_STRING, None),
    ], line=1)

    # <uses-sdk>
    ax.start_element("uses-sdk", attrs=[
        ("minSdkVersion", None, TYPE_INT_DEC, config.get("min_sdk", 21)),
        ("targetSdkVersion", None, TYPE_INT_DEC, config.get("target_sdk", 30)),
    ], line=2)
    ax.end_element("uses-sdk", line=2)

    # <uses-permission> for each permission
    for perm in config.get("permissions", []):
        ax.start_element("uses-permission", attrs=[
            ("name", perm, TYPE_STRING, None),
        ], line=3)
        ax.end_element("uses-permission", line=3)

    # <application>
    ax.start_element("application", attrs=[
        ("label", config.get("app_label", config["package"]), TYPE_STRING, None),
    ], line=10)

    # Activities
    for act in config.get("activities", []):
        act_attrs = [("name", act["name"], TYPE_STRING, None)]
        if "exported" in act:
            ax.start_element("activity", attrs=act_attrs + [
                ("exported", None, TYPE_INT_BOOLEAN, 0xFFFFFFFF if act["exported"] else 0),
            ], line=11)
        else:
            ax.start_element("activity", attrs=act_attrs, line=11)

        if act.get("launcher"):
            ax.start_element("intent-filter", line=12)
            ax.start_element("action", attrs=[
                ("name", "android.intent.action.MAIN", TYPE_STRING, None),
            ], line=13)
            ax.end_element("action", line=13)
            ax.start_element("category", attrs=[
                ("name", "android.intent.category.LAUNCHER", TYPE_STRING, None),
            ], line=14)
            ax.end_element("category", line=14)
            ax.end_element("intent-filter", line=15)

        ax.end_element("activity", line=16)

    # Receivers
    for recv in config.get("receivers", []):
        recv_attrs = [("name", recv["name"], TYPE_STRING, None)]
        if recv.get("permission"):
            recv_attrs.append(("permission", recv["permission"], TYPE_STRING, None))
        if recv.get("exported") is not None:
            recv_attrs.append(("exported", None, TYPE_INT_BOOLEAN,
                               0xFFFFFFFF if recv["exported"] else 0))
        if recv.get("enabled") is not None:
            recv_attrs.append(("enabled", None, TYPE_INT_BOOLEAN,
                               0xFFFFFFFF if recv["enabled"] else 0))

        ax.start_element("receiver", attrs=recv_attrs, line=20)

        for action_group in recv.get("intent_filters", []):
            filter_attrs = []
            if action_group.get("priority"):
                filter_attrs.append(("priority", None, TYPE_INT_DEC, action_group["priority"]))
            ax.start_element("intent-filter", attrs=filter_attrs, line=21)
            for action_name in action_group.get("actions", []):
                ax.start_element("action", attrs=[
                    ("name", action_name, TYPE_STRING, None),
                ], line=22)
                ax.end_element("action", line=22)
            ax.end_element("intent-filter", line=23)

        ax.end_element("receiver", line=24)

    # Services
    for svc in config.get("services", []):
        svc_attrs = [("name", svc["name"], TYPE_STRING, None)]
        if svc.get("permission"):
            svc_attrs.append(("permission", svc["permission"], TYPE_STRING, None))
        if svc.get("exported") is not None:
            svc_attrs.append(("exported", None, TYPE_INT_BOOLEAN,
                               0xFFFFFFFF if svc["exported"] else 0))

        ax.start_element("service", attrs=svc_attrs, line=30)

        for action_name in svc.get("actions", []):
            ax.start_element("intent-filter", line=31)
            ax.start_element("action", attrs=[
                ("name", action_name, TYPE_STRING, None),
            ], line=32)
            ax.end_element("action", line=32)
            ax.end_element("intent-filter", line=33)

        # Meta-data (e.g., for accessibility config)
        for meta in svc.get("meta_data", []):
            meta_attrs = [("name", meta["name"], TYPE_STRING, None)]
            if "value" in meta:
                meta_attrs.append(("value", meta["value"], TYPE_STRING, None))
            if "resource" in meta:
                meta_attrs.append(("resource", None, TYPE_REFERENCE, meta["resource"]))
            ax.start_element("meta-data", attrs=meta_attrs, line=35)
            ax.end_element("meta-data", line=35)

        ax.end_element("service", line=36)

    ax.end_element("application", line=40)
    ax.end_element("manifest", line=41)
    ax.end_namespace()

    return ax.build()


# ──────────────────────────────────────────────────────────────────────
# APK PACKAGING
# ──────────────────────────────────────────────────────────────────────

def build_apk(manifest_config: dict, dex_strings: list[str], output_path: str):
    """
    Build a synthetic APK file:
      1. Construct AXML manifest
      2. Construct DEX with embedded strings
      3. Package both into a ZIP with .apk extension
    """
    print(f"  Building {os.path.basename(output_path)}...")

    # Build components
    manifest_data = build_axml_manifest(manifest_config)
    dex_data = build_dex(dex_strings)

    # Create the APK as a ZIP
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest_data)
        zf.writestr("classes.dex", dex_data)
        # Add a minimal resources.arsc (empty but present)
        # Actually, we'll skip it – androguard handles missing resources.arsc

    apk_data = buf.getvalue()
    with open(output_path, "wb") as f:
        f.write(apk_data)

    size_kb = len(apk_data) / 1024
    print(f"    ✓ Written {output_path} ({size_kb:.1f} KB)")
    print(f"    ✓ Manifest: {len(manifest_data)} bytes, DEX: {len(dex_data)} bytes")
    return output_path


# ──────────────────────────────────────────────────────────────────────
# TEST APK DEFINITIONS
# ──────────────────────────────────────────────────────────────────────

def generate_sms_stealer(output_dir: str) -> str:
    """
    test_sms_stealer.apk – Uzbek SMS stealer.
    Expected score: 🔴 Critical 8-10/10
    """
    # Base64-encoded 'api.telegram.org/bot' for the b64 detector
    b64_tg = base64.b64encode(b"api.telegram.org/bot").decode()

    manifest_config = {
        "package": "uz.fake.smsstealer",
        "version_code": 1,
        "version_name": "1.0",
        "min_sdk": 21,
        "target_sdk": 30,
        "app_label": "System Service",
        "permissions": [
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_CONTACTS",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        ],
        "activities": [],  # No launcher activity → hidden icon
        "receivers": [
            {
                "name": "uz.fake.smsstealer.SmsReceiver",
                "exported": True,
                "enabled": True,
                "intent_filters": [{
                    "actions": ["android.provider.Telephony.SMS_RECEIVED"],
                    "priority": 999,
                }],
            },
            {
                "name": "uz.fake.smsstealer.BootReceiver",
                "exported": True,
                "enabled": True,
                "intent_filters": [{
                    "actions": ["android.intent.action.BOOT_COMPLETED"],
                }],
            },
        ],
        "services": [
            {
                "name": "uz.fake.smsstealer.A11yService",
                "permission": "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "exported": False,
                "actions": [
                    "android.accessibilityservice.AccessibilityService",
                ],
                "meta_data": [
                    {
                        "name": "android.accessibilityservice",
                        "resource": 0x7F040000,
                    },
                ],
            },
        ],
    }

    dex_strings = [
        # Type descriptor (needed for the type_ids section)
        "Luz/fake/smsstealer/SmsReceiver;",

        # Telegram bot exfiltration
        "api.telegram.org",
        "1234567890:ABCDefghIJKLmnopQRSTuvwxyz123456789",
        "sendMessage",
        "sendDocument",
        "sendPhoto",
        "chat_id",
        "chat_id=-1001234567890",

        # SMS interception APIs
        "getMessagesFromIntent",
        "createFromPdu",
        "getDisplayMessageBody",
        "getMessageBody",
        "getOriginatingAddress",
        "sendTextMessage",

        # Network / HTTP
        "HttpURLConnection",
        "http://evil-c2.example.com/api/sms",
        "185.192.69.42",

        # SMS content provider
        "content://sms/inbox",
        "content://sms",
        "address",

        # Icon hiding
        "setComponentEnabledSetting",

        # Accessibility abuse
        "Landroid/accessibilityservice/AccessibilityService;",
        "performGlobalAction",
        "dispatchGesture",
        "getRootInActiveWindow",
        "findAccessibilityNodeInfosByViewId",
        "findAccessibilityNodeInfosByText",

        # Overlay / phishing
        "canDrawOverlays",
        "Landroid/view/WindowManager;",
        "addView",
        "loadUrl",

        # Uzbek banking / payment lure strings
        "uzcard",
        "humo",
        "payme.uz",
        "karta raqami",
        "tasdiqlash kodi",
        "sms kod",

        # Base64 encoded suspicious string
        b64_tg,

        # Additional strings for YARA coverage
        "android.settings.action.MANAGE_OVERLAY_PERMISSION",
        "loadDataWithBaseURL",
    ]

    return build_apk(manifest_config, dex_strings, os.path.join(output_dir, "test_sms_stealer.apk"))


def generate_banker_trojan(output_dir: str) -> str:
    """
    test_banker_trojan.apk – Banking trojan with overlay + accessibility.
    Expected score: 🟠 High 5-7/10
    """
    manifest_config = {
        "package": "com.fake.bankhelper",
        "version_code": 1,
        "version_name": "2.1",
        "min_sdk": 21,
        "target_sdk": 33,
        "app_label": "Bank Helper",
        "permissions": [
            "android.permission.INTERNET",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.READ_SMS",
            "android.permission.READ_PHONE_STATE",
            "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
        ],
        "activities": [
            {
                "name": "com.fake.bankhelper.MainActivity",
                "launcher": True,
                "exported": True,
            },
        ],
        "receivers": [],
        "services": [
            {
                "name": "com.fake.bankhelper.A11yService",
                "permission": "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "exported": False,
                "actions": [
                    "android.accessibilityservice.AccessibilityService",
                ],
                "meta_data": [
                    {
                        "name": "android.accessibilityservice",
                        "resource": 0x7F040000,
                    },
                ],
            },
            {
                "name": "com.fake.bankhelper.NotifListener",
                "permission": "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
                "exported": False,
                "actions": [
                    "android.service.notification.NotificationListenerService",
                ],
                "meta_data": [],
            },
        ],
    }

    dex_strings = [
        # Type descriptor
        "Lcom/fake/bankhelper/MainActivity;",

        # Accessibility abuse
        "Landroid/accessibilityservice/AccessibilityService;",
        "performGlobalAction",
        "getRootInActiveWindow",
        "findAccessibilityNodeInfosByViewId",

        # Overlay / phishing
        "canDrawOverlays",
        "android.settings.action.MANAGE_OVERLAY_PERMISSION",
        "Landroid/view/WindowManager;",
        "addView",
        "loadUrl",
        "loadDataWithBaseURL",

        # Uzbek banking targets
        "uzcard",
        "click.uz",
        "kapitalbank",
        "karta raqami",
        "amal qilish muddati",

        # Network
        "HttpURLConnection",
        "http://banking-helper.example.com/config",
    ]

    return build_apk(manifest_config, dex_strings, os.path.join(output_dir, "test_banker_trojan.apk"))


def generate_benign_app(output_dir: str) -> str:
    """
    test_benign_app.apk – A benign calculator app.
    Expected score: 🟢 Low 0-2/10
    """
    manifest_config = {
        "package": "com.example.calculator",
        "version_code": 1,
        "version_name": "1.0",
        "min_sdk": 21,
        "target_sdk": 34,
        "app_label": "Calculator",
        "permissions": [
            "android.permission.INTERNET",
        ],
        "activities": [
            {
                "name": "com.example.calculator.MainActivity",
                "launcher": True,
                "exported": True,
            },
        ],
        "receivers": [],
        "services": [],
    }

    dex_strings = [
        # Type descriptor
        "Lcom/example/calculator/MainActivity;",

        # Normal app strings
        "https://api.example.com/version",
        "HttpURLConnection",
        "Calculator",
        "MainActivity",
        "onCreate",
        "setContentView",
        "findViewById",
        "setText",
        "getText",
        "0123456789+-*/=",
    ]

    return build_apk(manifest_config, dex_strings, os.path.join(output_dir, "test_benign_app.apk"))


# ──────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────

def main():
    output_dir = os.path.dirname(os.path.abspath(__file__))
    print("=" * 60)
    print("  Synthetic Test APK Generator")
    print("  For Android Malware Analyzer Bot testing")
    print("=" * 60)
    print()

    results = []
    results.append(("🔴 Critical (8-10)", generate_sms_stealer(output_dir)))
    print()
    results.append(("🟠 High (5-7)", generate_banker_trojan(output_dir)))
    print()
    results.append(("🟢 Low (0-2)", generate_benign_app(output_dir)))
    print()

    print("=" * 60)
    print("  Summary")
    print("=" * 60)
    for expected_score, path in results:
        basename = os.path.basename(path)
        size = os.path.getsize(path)
        print(f"  {basename:30s}  {size:>6d} bytes  Expected: {expected_score}")
    print()
    print("  All APKs generated successfully!")
    print()

    # Quick self-validation
    print("Running self-validation...")
    _validate_dex(output_dir)
    _validate_axml(output_dir)
    print()
    print("Done. Use the bot's venv to run full androguard validation:")
    print("  python -c \"from androguard.core.apk import APK; \\")
    print("    a = APK('test_sms_stealer.apk'); \\")
    print("    print(a.get_package(), a.get_permissions())\"")


def _validate_dex(output_dir: str):
    """Basic structural validation of generated DEX files."""
    import zipfile
    for name in ["test_sms_stealer.apk", "test_banker_trojan.apk", "test_benign_app.apk"]:
        path = os.path.join(output_dir, name)
        with zipfile.ZipFile(path, "r") as zf:
            assert "AndroidManifest.xml" in zf.namelist(), f"{name}: missing AndroidManifest.xml"
            assert "classes.dex" in zf.namelist(), f"{name}: missing classes.dex"
            dex = zf.read("classes.dex")
            assert dex[:8] == b"dex\n035\x00", f"{name}: bad DEX magic"
            # Verify IsDex YARA rule: uint32(0) == 0x0a786564
            magic_u32 = struct.unpack("<I", dex[:4])[0]
            assert magic_u32 == 0x0a786564, f"{name}: DEX magic mismatch for YARA IsDex rule"
            manifest = zf.read("AndroidManifest.xml")
            # AXML starts with RES_XML_TYPE (0x0003) at offset 0
            axml_type = struct.unpack("<H", manifest[:2])[0]
            assert axml_type == 0x0003, f"{name}: bad AXML magic (got {axml_type:#x})"
        print(f"  ✓ {name}: ZIP, DEX magic, AXML header OK")


def _validate_axml(output_dir: str):
    """Check that the AXML string pool contains expected package names."""
    import zipfile
    expected_packages = {
        "test_sms_stealer.apk": "uz.fake.smsstealer",
        "test_banker_trojan.apk": "com.fake.bankhelper",
        "test_benign_app.apk": "com.example.calculator",
    }
    for name, pkg in expected_packages.items():
        path = os.path.join(output_dir, name)
        with zipfile.ZipFile(path, "r") as zf:
            manifest = zf.read("AndroidManifest.xml")
        # The package name should appear in the string pool as UTF-8 bytes
        assert pkg.encode("utf-8") in manifest, f"{name}: package '{pkg}' not found in AXML"
        print(f"  ✓ {name}: package '{pkg}' found in AXML string pool")


if __name__ == "__main__":
    main()
