#!/usr/bin/env python3
"""Checks EasyPatch macOS agent packages without macOS: the xar container and its checksums, Distribution and
PackageInfo, every Payload and Scripts entry with owner and mode, the LaunchDaemon, and the agent executable (Mach-O
CPU type, minimum macOS, code signature). Standard library only; runs in the package builder image and on CI.

    check-pkg.py [--agent <published easypatch-agent>] EasyPatchAgent-<version>-<x64|arm64>.pkg...

--agent also requires the packaged agent to be byte-identical to that file (one package at a time). Exit code 0 when
every package is as expected, 1 otherwise.
"""
import argparse
import gzip
import hashlib
import os
import plistlib
import re
import struct
import sys
import xml.etree.ElementTree as ET
import zlib

IDENTIFIER = "com.dhitechnical.easypatch.agent"
COMPONENT = "easypatch-agent.pkg"
TITLE = "EasyPatch Agent (experimental)"
MIN_OS = "14.0"
AGENT = "Library/EasyPatch/easypatch-agent"
PLIST = "Library/LaunchDaemons/" + IDENTIFIER + ".plist"
UNINSTALL = "Library/EasyPatch/uninstall.sh"

# path (without the "./" that pkgbuild writes and GNU cpio leaves out) -> (mode including the file type, uid, gid)
PAYLOAD = {
    ".": (0o040755, 0, 0),
    "Library": (0o040755, 0, 0),
    "Library/EasyPatch": (0o040755, 0, 0),
    AGENT: (0o100755, 0, 0),
    UNINSTALL: (0o100755, 0, 0),
    "Library/LaunchDaemons": (0o040755, 0, 0),
    PLIST: (0o100644, 0, 0),
}
SCRIPTS = {
    ".": (0o040755, 0, 0),
    "postinstall": (0o100755, 0, 0),
}
XAR_ENTRIES = {"Distribution", COMPONENT, COMPONENT + "/Bom", COMPONENT + "/Payload", COMPONENT + "/Scripts",
               COMPONENT + "/PackageInfo"}
LAUNCHD = {
    "Label": IDENTIFIER,
    "ProgramArguments": ["/Library/EasyPatch/easypatch-agent", "run"],
    "RunAtLoad": True,
    "KeepAlive": True,
    "ThrottleInterval": 30,
    "ExitTimeOut": 75,
    "WorkingDirectory": "/",
    "StandardOutPath": "/Library/Logs/EasyPatch/launchd.log",
    "StandardErrorPath": "/Library/Logs/EasyPatch/launchd.log",
}
# package architecture -> (Distribution hostArchitectures, Mach-O CPU type, name)
ARCHITECTURES = {"x64": ("x86_64", 0x01000007, "x86_64"), "arm64": ("arm64", 0x0100000C, "arm64")}
NAME = re.compile(r"^EasyPatchAgent-(\d{1,5}\.\d{1,5}\.\d{1,5})-(x64|arm64)\.pkg$")


class PackageError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise PackageError(message)


def read_xar(data):
    """Returns {path: (type, content or None, xar encoding or None)} after checking the TOC and every file checksum."""
    require(len(data) >= 28 and data[:4] == b"xar!", "not a xar archive")
    header_size, version, toc_length, toc_size, checksum_kind = struct.unpack(">HHQQI", data[4:28])
    require(version == 1, f"xar version {version}")
    toc_compressed = data[header_size:header_size + toc_length]
    toc_xml = zlib.decompress(toc_compressed)
    require(len(toc_xml) == toc_size, "TOC size does not match the header")
    heap = header_size + toc_length
    toc = ET.fromstring(toc_xml).find("toc")
    require(toc is not None, "no TOC")

    checksum = toc.find("checksum")
    require(checksum is not None and checksum_kind == 1 and checksum.get("style") == "sha1",
            "TOC checksum is not SHA-1 (what Apple's installer expects)")
    offset, size = int(checksum.findtext("offset")), int(checksum.findtext("size"))
    require(data[heap + offset:heap + offset + size] == hashlib.sha1(toc_compressed).digest(), "TOC checksum mismatch")

    entries = {}

    def walk(element, prefix):
        for node in element.findall("file"):
            path = prefix + node.findtext("name")
            kind = node.findtext("type")
            content = None
            data_node = node.find("data")
            if data_node is not None:
                start = heap + int(data_node.findtext("offset"))
                archived = data[start:start + int(data_node.findtext("length"))]
                style = data_node.find("encoding").get("style")
                if style == "application/x-gzip":
                    content = zlib.decompress(archived)
                elif style == "application/octet-stream":
                    content = archived
                else:
                    raise PackageError(f"{path}: unexpected xar encoding {style}")
                for name, blob in (("archived-checksum", archived), ("extracted-checksum", content)):
                    element_sum = data_node.find(name)
                    require(element_sum is not None and element_sum.get("style") == "sha1", f"{path}: no SHA-1 {name}")
                    require(hashlib.sha1(blob).hexdigest() == element_sum.text.strip(), f"{path}: {name} mismatch")
                require(len(content) == int(data_node.findtext("size")), f"{path}: size mismatch")
            entries[path] = (kind, content, style if data_node is not None else None)
            walk(node, path + "/")

    walk(toc, "")
    return entries


def read_cpio(data):
    """Parses an odc (070707) cpio archive: [(name, mode, uid, gid, mtime, content)]."""
    entries, position = [], 0
    while True:
        header = data[position:position + 76]
        require(len(header) == 76 and header[:6] == b"070707", f"bad cpio header at {position}")
        fields = header.decode("ascii")
        mode, uid, gid = int(fields[18:24], 8), int(fields[24:30], 8), int(fields[30:36], 8)
        mtime, name_size, file_size = int(fields[48:59], 8), int(fields[59:65], 8), int(fields[65:76], 8)
        position += 76
        name = data[position:position + name_size - 1].decode("utf-8")
        name = name[2:] if name.startswith("./") else name
        position += name_size
        content = data[position:position + file_size]
        position += file_size
        if name == "TRAILER!!!":
            return entries
        entries.append((name, mode, uid, gid, mtime, content))


def check_tree(label, entries, expected):
    names = [entry[0] for entry in entries]
    require(len(names) == len(set(names)), f"{label}: duplicate entries")
    require(set(names) == set(expected),
            f"{label}: entries {sorted(set(names) ^ set(expected))} differ from the expected list")
    for name, mode, uid, gid, _, _ in entries:
        want = expected[name]
        require((mode, uid, gid) == want,
                f"{label}: {name} is {mode:o} {uid}:{gid}, expected {want[0]:o} {want[1]}:{want[2]}")


def describe_tree(entries):
    lines = []
    for name, mode, uid, gid, mtime, content in entries:
        kind = "d" if mode & 0o170000 == 0o040000 else "-"
        bits = "".join(c if mode & (1 << (8 - i)) else "-" for i, c in enumerate("rwxrwxrwx"))
        lines.append(f"    {kind}{bits} {mode & 0o7777:04o} {uid}:{gid} {len(content):>10}  {name}")
    return lines


def check_macho(binary, cpu_type, cpu_name):
    """Returns a description of a thin 64-bit Mach-O executable; requires the CPU type and a code signature."""
    require(len(binary) > 32 and struct.unpack("<I", binary[:4])[0] == 0xFEEDFACF, "agent: not a 64-bit Mach-O file")
    cpu, _, file_type, commands, _, _ = struct.unpack("<iiIIII", binary[4:28])
    require(cpu & 0xFFFFFFFF == cpu_type, f"agent: Mach-O CPU type {cpu & 0xFFFFFFFF:#x}, expected {cpu_type:#x} ({cpu_name})")
    require(file_type == 2, "agent: not an executable (MH_EXECUTE)")
    position, minimum, signature = 32, None, None
    for _ in range(commands):
        command, size = struct.unpack("<II", binary[position:position + 8])
        if command == 0x32:  # LC_BUILD_VERSION
            platform, minos = struct.unpack("<II", binary[position + 8:position + 16])
            require(platform == 1, f"agent: built for platform {platform}, not macOS")
            minimum = f"{minos >> 16}.{(minos >> 8) & 0xFF}.{minos & 0xFF}"
        elif command == 0x1D:  # LC_CODE_SIGNATURE
            signature = struct.unpack("<II", binary[position + 8:position + 16])
        position += size
    require(minimum is not None, "agent: no LC_BUILD_VERSION")
    require(signature is not None, "agent: no LC_CODE_SIGNATURE (Apple silicon refuses to run unsigned code)")

    offset, size = signature
    blob = binary[offset:offset + size]
    magic, _, count = struct.unpack(">III", blob[:12])
    require(magic == 0xFADE0CC0, "agent: the code signature is not an embedded signature SuperBlob")
    details = None
    for index in range(count):
        slot, slot_offset = struct.unpack(">II", blob[12 + index * 8:20 + index * 8])
        if slot == 0:  # CodeDirectory
            magic, _, _, flags, _, ident_offset = struct.unpack(">IIIIII", blob[slot_offset:slot_offset + 24])
            require(magic == 0xFADE0C02, "agent: bad CodeDirectory")
            identifier = blob[slot_offset + ident_offset:].split(b"\0", 1)[0].decode()
            kind = "ad hoc" if flags & 0x2 else "certificate"
            details = f"{kind} (CodeDirectory flags {flags:#x}), identifier {identifier}"
    require(details is not None, "agent: the code signature has no CodeDirectory")
    return f"Mach-O 64-bit executable {cpu_name}, minimum macOS {minimum}, LC_CODE_SIGNATURE {size} bytes: {details}"


def check_package(path, agent_path):
    match = NAME.match(os.path.basename(path))
    require(match, f"{os.path.basename(path)} is not EasyPatchAgent-<version>-<x64|arm64>.pkg")
    version, arch = match.groups()
    host_arch, cpu_type, cpu_name = ARCHITECTURES[arch]
    with open(path, "rb") as stream:
        data = stream.read()
    report = [f"{os.path.basename(path)}: {len(data)} bytes, SHA-256 {hashlib.sha256(data).hexdigest()}"]

    xar = read_xar(data)
    require(set(xar) == XAR_ENTRIES, f"xar entries {sorted(xar)} differ from {sorted(XAR_ENTRIES)}")
    require(xar[COMPONENT][0] == "directory", f"{COMPONENT} is not a directory")
    report.append("  xar: TOC and file SHA-1 checksums OK; " + ", ".join(
        f"{name} ({xar[name][2] or 'directory'})" for name in sorted(xar)))

    distribution = ET.fromstring(xar["Distribution"][1])
    require(distribution.tag == "installer-gui-script", "Distribution: not an installer-gui-script")
    require(distribution.findtext("title") == TITLE, "Distribution: wrong title")
    options = distribution.find("options")
    require(options is not None and options.get("hostArchitectures") == host_arch,
            f"Distribution: hostArchitectures is not {host_arch}")
    require(options.get("customize") == "never", "Distribution: customize is not never")
    os_versions = [e.get("min") for e in distribution.findall("volume-check/allowed-os-versions/os-version")]
    require(os_versions == [MIN_OS], f"Distribution: os-version min is {os_versions}, expected {MIN_OS}")
    refs = [e for e in distribution.findall("pkg-ref") if (e.text or "").strip()]
    require(len(refs) == 1 and refs[0].text.strip() == "#" + COMPONENT and refs[0].get("id") == IDENTIFIER
            and refs[0].get("version") == version, "Distribution: wrong component pkg-ref")
    product = distribution.find("product")
    require(product is not None and product.get("id") == IDENTIFIER and product.get("version") == version,
            "Distribution: wrong product")
    report.append(f"  Distribution: \"{TITLE}\", hostArchitectures {host_arch}, macOS {MIN_OS} or later, "
                  f"{IDENTIFIER} {version} in #{COMPONENT}")

    payload = read_cpio(gzip.decompress(xar[COMPONENT + "/Payload"][1]))
    check_tree("Payload", payload, PAYLOAD)
    scripts = read_cpio(gzip.decompress(xar[COMPONENT + "/Scripts"][1]))
    check_tree("Scripts", scripts, SCRIPTS)

    info = ET.fromstring(xar[COMPONENT + "/PackageInfo"][1])
    require(info.tag == "pkg-info" and info.get("format-version") == "2", "PackageInfo: not a format 2 pkg-info")
    for attribute, value in (("identifier", IDENTIFIER), ("version", version), ("install-location", "/"),
                             ("auth", "root")):
        require(info.get(attribute) == value, f"PackageInfo: {attribute} is not {value}")
    payload_info = info.find("payload")
    require(payload_info is not None and int(payload_info.get("numberOfFiles")) == len(payload),
            "PackageInfo: numberOfFiles does not match the Payload")
    require([e.get("file") for e in info.findall("scripts/*")] == ["./postinstall"]
            and info.find("scripts/postinstall") is not None, "PackageInfo: scripts are not exactly ./postinstall")
    report.append(f"  PackageInfo: {IDENTIFIER} {version}, install-location /, auth root, "
                  f"{payload_info.get('numberOfFiles')} files, {payload_info.get('installKBytes')} KB, postinstall")

    require(xar[COMPONENT + "/Bom"][1][:8] == b"BOMStore", "Bom: not a BOM file")

    files = {entry[0]: entry[5] for entry in payload}
    files.update({"scripts/" + entry[0]: entry[5] for entry in scripts})
    for name in (UNINSTALL, "scripts/postinstall"):
        require(files[name].startswith(b"#!/bin/sh\n"), f"{name} is not a /bin/sh script")
    launchd = plistlib.loads(files[PLIST])
    require(launchd == LAUNCHD, f"LaunchDaemon differs from the expected one: {launchd}")

    agent = files[AGENT]
    if agent_path:
        with open(agent_path, "rb") as stream:
            require(stream.read() == agent, f"the packaged agent differs from {agent_path}")
    report.append("  Payload (cpio odc):")
    report.extend(describe_tree(payload))
    report.append("  Scripts (cpio odc):")
    report.extend(describe_tree(scripts))
    report.append(f"  LaunchDaemon: {IDENTIFIER}, {' '.join(LAUNCHD['ProgramArguments'])}")
    report.append(f"  agent: {check_macho(agent, cpu_type, cpu_name)}; SHA-256 {hashlib.sha256(agent).hexdigest()}")
    return report


def main():
    parser = argparse.ArgumentParser(description="Checks EasyPatch macOS agent packages.")
    parser.add_argument("--agent", help="published easypatch-agent the package must contain unchanged")
    parser.add_argument("packages", nargs="+")
    arguments = parser.parse_args()
    if arguments.agent and len(arguments.packages) != 1:
        parser.error("--agent needs exactly one package")

    failed = 0
    for path in arguments.packages:
        try:
            print("\n".join(check_package(path, arguments.agent)))
            print("  OK")
        except Exception as error:  # any malformed input is a failed check, reported without a traceback
            print(f"FAILED  {os.path.basename(path)}: {error}")
            failed += 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
