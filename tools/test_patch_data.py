#!/usr/bin/env python3
"""Host-side validation of the user-space patch data.

Parses the byte arrays and tables in `NootedRed/UserPatches.cpp` and
`NootedRed/TahoePatchData.hpp` and checks their internal consistency:

  * every `PagePatch` references known arrays, and `find`/`replace` sizes agree;
  * each site's `find` sequence occurs in its page image at least `skip + count` times;
  * every resolver `SignaturePatch` references known arrays, its masked context occurs in the
    expected page image, and the site bytes under `patchOffset` are the matching `find` sequence;
  * the version/APU `PatchSet` table is ordered and versioned sensibly.

This does not load the kext and does not need a Mac; it is meant to catch table regressions before a
reboot (and to make adding a new macOS build or APU a data-only change).
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

BYTE_ARRAY_RE = re.compile(r"(?:static\s+)?const\s+UInt8\s+(\w+)\s*\[\s*\]\s*=\s*\{(.*?)\}\s*;", re.S)
HEX_BYTE_RE = re.compile(r"0x([0-9A-Fa-f]{2})")

PATCH_ROW_RE = re.compile(
    r"\{\s*UserPatcher::FileSegment::SegmentTextText\s*,\s*"
    r"(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*,\s*sizeof\((\w+)\)\s*,\s*(\d+)\s*,\s*(\d+)\s*\}",
    re.S,
)

SIGNATURE_ROW_RE = re.compile(
    r"\{\s*(\w+)\s*,\s*(\w+)\s*,\s*sizeof\((\w+)\)\s*,\s*(\d+)\s*,\s*(\w+)\s*,\s*"
    r"sizeof\((\w+)\)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(0x[0-9A-Fa-f]+|~static_cast<UInt64>\(0\))\s*\}",
    re.S,
)

PATCH_SET_RE = re.compile(
    r'\{"([^"]+)",\s*PenguinWizardry::KernelVersion\((\d+),\s*(\d+)\),\s*'
    r'PenguinWizardry::KernelVersion\((\d+),\s*(\d+)\)',
    re.S,
)

ALL_APUS = 0x3F


class Failure(Exception):
    pass


def check(condition, message):
    if not condition:
        raise Failure(message)


def load_arrays(path):
    text = path.read_text()
    arrays = {}
    for match in BYTE_ARRAY_RE.finditer(text):
        name, body = match.group(1), match.group(2)
        values = [int(value, 16) for value in HEX_BYTE_RE.findall(body)]
        arrays[name] = values
    return arrays, text


def find_all(haystack, needle, mask=None):
    offsets = []
    start = 0
    while True:
        offset = find_at(haystack, needle, start, mask)
        if offset < 0:
            return offsets
        offsets.append(offset)
        start = offset + 1
    return offsets


def find_at(haystack, needle, start, mask=None):
    if not needle:
        return -1
    limit = len(haystack) - len(needle)
    if mask is None:
        for index in range(start, limit + 1):
            if haystack[index : index + len(needle)] == needle:
                return index
    else:
        for index in range(start, limit + 1):
            match = True
            for i in range(len(needle)):
                if (haystack[index + i] & mask[i]) != (needle[i] & mask[i]):
                    match = False
                    break
            if match:
                return index
    return -1


def check_page_patches(arrays, text):
    rows = list(PATCH_ROW_RE.finditer(text))
    check(rows, "no PagePatch rows found")
    seen = set()
    for row in rows:
        page_name, find_name, replace_name, size_name, skip, count = row.groups()
        skip, count = int(skip), int(count)
        for name in (page_name, find_name, replace_name):
            check(name in arrays, f"PagePatch references unknown array {name}")
        find, replace, page = arrays[find_name], arrays[replace_name], arrays[page_name]
        check(size_name == find_name, f"sizeof({size_name}) should refer to {find_name}")
        check(len(page) == 0x1000, f"{page_name} must be exactly one 4 KiB page (got {len(page)})")
        check(len(find) == len(replace), f"{find_name}/{replace_name} sizes differ")
        check(0 < len(find) <= 32, f"{find_name} size {len(find)} is not 1..32")
        check(count > 0, f"{find_name} count is zero")
        key = (page_name, bytes(find))
        check(key not in seen, f"duplicate PagePatch ({page_name}, {find_name})")
        seen.add(key)
        occurrences = find_all(page, find)
        check(
            len(occurrences) >= skip + count,
            f"{find_name}: only {len(occurrences)} occurrence(s) in {page_name}, need skip({skip}) + count({count})",
        )
    return len(rows)


def signature_page_name(arrays, page_offset, context_name=""):
    suffix = "_Sequoia"
    if "_Sonoma" in context_name:
        suffix = "_Sonoma"
    elif "_Tahoe" in context_name:
        suffix = "_Tahoe"
    elif "_Ventura" in context_name:
        suffix = "_Ventura"

    if page_offset.startswith("~"):
        return f"kMTLControlPage{suffix}" if f"kMTLControlPage{suffix}" in arrays else "kMTLControlPage"
    offset = int(page_offset, 16)
    if offset == 0xE000:
        return f"kGLDriverHwInfoPage{suffix}" if f"kGLDriverHwInfoPage{suffix}" in arrays else "kGLDriverHwInfoPage"
    if offset == 0x8000:
        return f"kGLDriverDualQuadPage{suffix}" if f"kGLDriverDualQuadPage{suffix}" in arrays else "kGLDriverDualQuadPage"
    return None


def check_signatures(arrays, text):
    rows = list(SIGNATURE_ROW_RE.finditer(text))
    check(rows, "no SignaturePatch rows found")
    for row in rows:
        context_name, mask_name, size_name, patch_offset, replace_name, replace_size_name, skip, count, page_offset = (
            row.groups()
        )
        patch_offset, skip, count = int(patch_offset), int(skip), int(count)
        check(size_name == context_name, f"sizeof({size_name}) should refer to {context_name}")
        check(replace_size_name == replace_name, f"sizeof({replace_size_name}) should refer to {replace_name}")
        for name in (context_name, mask_name, replace_name):
            check(name in arrays, f"SignaturePatch references unknown array {name}")
        context, mask, replace = arrays[context_name], arrays[mask_name], arrays[replace_name]
        check(len(mask) == len(context), f"{mask_name} mask length != {context_name} context length")
        check(len(replace) > 0 and patch_offset + len(replace) <= len(context),
              f"{context_name}: patchOffset {patch_offset} + {len(replace)} exceeds context length {len(context)}")
        check(count > 0, f"{context_name}: count is zero")

        find_name = replace_name.replace("Replace", "Find")
        check(find_name != replace_name and find_name in arrays, f"missing {find_name} for {replace_name}")
        find = arrays[find_name]
        check(len(find) == len(replace), f"{find_name}/{replace_name} sizes differ")

        page_name = signature_page_name(arrays, page_offset, context_name)
        check(page_name is not None, f"unknown resolver pageOffset {page_offset}")
        check(page_name in arrays, f"SignaturePatch needs page image {page_name}")
        page = arrays[page_name]
        check(len(page) == 0x1000, f"{page_name} must be one 4 KiB page")

        offsets = find_all(page, context, mask)
        check(offsets, f"{context_name} context not found in {page_name}")
        for offset in offsets:
            site = page[offset + patch_offset : offset + patch_offset + len(replace)]
            check(site == find, f"{context_name}: site at {offset:#x}+{patch_offset} is not {find_name}")
    return len(rows)


def check_patch_sets(text):
    sets = list(PATCH_SET_RE.finditer(text))
    check(len(sets) >= 2, "no PatchSet rows found")
    ranges = []
    for match in sets:
        name, major, minor, max_major, max_minor = match.groups()
        major, minor, max_major, max_minor = map(int, (major, minor, max_major, max_minor))
        check((major, minor) <= (max_major, max_minor), f"PatchSet {name}: minVersion > maxVersion")
        ranges.append(((major, minor), (max_major, max_minor)))
        check("KernelVersion" not in name, f"PatchSet {name}: malformed entry")

    def covers(target):
        return any(start <= target <= end for start, end in ranges)

    check(covers((24, 6)), "missing a Darwin 24.6 (macOS 15.8.1) PatchSet")
    check(covers((25, 6)), "missing a Darwin 25.6 (macOS 26.7.1) PatchSet")
    check(covers((23, 6)), "missing a Darwin 23.6 (macOS 14.x) PatchSet")
    check(covers((22, 6)), "missing a Darwin 22.6 (macOS 13.x) PatchSet")
    return len(sets)


def main():
    user_patches = ROOT / "NootedRed" / "UserPatches.cpp"
    tahoe = ROOT / "NootedRed" / "TahoePatchData.hpp"
    for path in (user_patches, tahoe):
        check(path.is_file(), f"missing {path}")

    arrays, text = load_arrays(user_patches)
    tahoe_arrays, _ = load_arrays(tahoe)
    arrays.update(tahoe_arrays)
    for inc_file in sorted((ROOT / "NootedRed").glob("UserPatches*.inc")):
        inc_arrays, _ = load_arrays(inc_file)
        arrays.update(inc_arrays)

    patches = check_page_patches(arrays, text)
    signatures = check_signatures(arrays, text)
    sets = check_patch_sets(text)

    print(f"ok: {patches} page patch(es), {signatures} resolver signature(s), {sets} patch set(s)")
    print("all user-space patch data checks passed")


if __name__ == "__main__":
    try:
        main()
    except Failure as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
