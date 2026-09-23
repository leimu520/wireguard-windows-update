#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# Checks that the executable that was just built really carries the resource
# section it is supposed to.
#
# This exists because every one of these failures is silent. Without the
# manifest the window falls back to the pre-6 common controls and merely looks
# wrong; without the icon group the tray icon is missing and the user has no way
# to reach the window at all; without the embedded wireguard.dll in RCDATA the
# tunnel service cannot load the driver. None of that shows up in a build log.
#
# Resource group id 7 is not arbitrary: ui/iconprovider.go loads the tray icon
# with NewIconFromResourceIdWithSize(7, ...).

import struct
import sys

PATH = sys.argv[1] if len(sys.argv) > 1 else "amd64/wireguard.exe"

data = open(PATH, "rb").read()

pe = struct.unpack_from("<I", data, 0x3C)[0]
if data[pe:pe + 4] != b"PE\x00\x00":
    sys.exit("%s is not a PE file" % PATH)

section_count = struct.unpack_from("<H", data, pe + 6)[0]
optional_size = struct.unpack_from("<H", data, pe + 20)[0]
optional = pe + 24
magic = struct.unpack_from("<H", data, optional)[0]
data_directories = optional + (112 if magic == 0x20B else 96)

# Data directory 2 is the resource table.
resource_rva, _ = struct.unpack_from("<II", data, data_directories + 2 * 8)

resource_offset = None
for i in range(section_count):
    header = optional + optional_size + i * 40
    virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from("<IIII", data, header + 8)
    if virtual_address <= resource_rva < virtual_address + max(virtual_size, raw_size):
        resource_offset = raw_pointer + (resource_rva - virtual_address)
        break

if resource_offset is None:
    sys.exit("no resource section in %s" % PATH)


def entries(base):
    """One level of the resource directory tree: (id, offset) pairs."""
    named = struct.unpack_from("<H", data, base + 12)[0]
    ids = struct.unpack_from("<H", data, base + 14)[0]
    result = []
    for k in range(named + ids):
        identifier, offset = struct.unpack_from("<II", data, base + 16 + k * 8)
        result.append((identifier, offset))
    return result


by_type = {}
for type_id, type_offset in entries(resource_offset):
    if type_id & 0x80000000:
        continue  # a named type; this executable has none
    children = entries(resource_offset + (type_offset & 0x7FFFFFFF))
    by_type[type_id] = [identifier for identifier, _ in children]

print("resource types present:", ", ".join("%d" % t for t in sorted(by_type)))

problems = []

if 3 not in by_type:
    problems.append("RT_ICON is missing, so there are no icon images")
else:
    print("  RT_ICON images:", len(by_type[3]))

if 14 not in by_type:
    problems.append("RT_GROUP_ICON is missing, so there is no tray icon")
else:
    groups = by_type[14]
    print("  RT_GROUP_ICON groups:", [hex(g) for g in groups])
    if 7 not in groups:
        problems.append("RT_GROUP_ICON has no group 7, which is the one the tray loads")

if 24 not in by_type:
    problems.append("RT_MANIFEST is missing, so the window loses the version 6 controls and per-monitor DPI")
if 16 not in by_type:
    problems.append("RT_VERSION is missing, so the file properties are empty")
if 10 not in by_type:
    problems.append("no named RCDATA is present, so the embedded wireguard.dll is missing")

if "WireGuard 专版".encode("utf-16-le") not in data:
    problems.append("the version resource does not carry the product name")

if problems:
    for problem in problems:
        print("FAIL: " + problem)
    sys.exit(1)

print("resource section for %s looks complete" % PATH)
