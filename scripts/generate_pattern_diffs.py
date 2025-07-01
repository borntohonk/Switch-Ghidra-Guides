#!/usr/bin/env python

# Copyright (c) 2026 borntohonk
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import re
import sys
import os
import importlib
from typing import Dict, List, Tuple, Callable

# Ensure the scripts directory is on the path so sibling modules resolve.
_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

from find_patterns import PATCH_RULES, FW_VER_ANY


# ---------------------------------------------------------------------------
# Pattern-diff loading
# ---------------------------------------------------------------------------

def to_version_dict(pattern_list) -> Dict[str, bytes]:
    """Convert list of (version, bytes) tuples → dict[version: bytes]."""
    if isinstance(pattern_list, dict):
        return pattern_list
    if isinstance(pattern_list, list):
        return {ver: pat for ver, pat in pattern_list}
    raise ValueError(f"Unexpected pattern format: {type(pattern_list)}")


def _load_diff(name: str) -> Dict[str, bytes]:
    """Load one named variable from pattern_diffs.py; return {} if absent."""
    try:
        mod = importlib.import_module('pattern_diffs')
        return to_version_dict(getattr(mod, name, []))
    except Exception:
        return {}


# Ordered to match diff_categories in find_patterns.py.
ALL_CATEGORIES: List[str] = [
    'es_pattern_diffs',
    'blankcal0crashfix_pattern_diffs',
    'blockfirmwareupdates_pattern_diffs',
    'nifm_pattern_diffs',
    'ns_pattern_diffs',
    'usb_pattern_1_diffs',
    'usb_pattern_2_diffs',
    'usb_pattern_3_diffs',
    'olsc_pattern_diffs',
    'am_pattern_diffs',
    'fat32_noacidsigchk1_pattern_diffs',
    'exfat_noacidsigchk1_pattern_diffs',
    'fat32_noacidsigchk2_pattern_diffs',
    'exfat_noacidsigchk2_pattern_diffs',
    'fat32_noncasigchk_pattern_diffs',
    'exfat_noncasigchk_pattern_diffs',
    'fat32_nocntchk_pattern_diffs',
    'exfat_nocntchk_pattern_diffs',
    'browser_pattern_diffs',
    'ssl_pattern_1_diffs',
    'ssl_pattern_2_diffs',
    'ssl_pattern_3_diffs',
    'loader_pattern_diffs',
    'erpt_pattern_diffs',
]

pattern_diffs_data: Dict[str, Dict[str, bytes]] = {
    name: _load_diff(name) for name in ALL_CATEGORIES
}


# ---------------------------------------------------------------------------
# Mapping: diff-category → PatchRule selector
# ---------------------------------------------------------------------------
# Each entry is (PATCH_RULES key, filter callable).
# The filter receives a PatchRule and returns True if that rule feeds this category.

CATEGORY_RULES_FILTER: Dict[str, Tuple[str, Callable]] = {
    'es_pattern_diffs':                   ('ES',      lambda _: True),
    'blankcal0crashfix_pattern_diffs':    ('NIM',     lambda r: r.module == 'NIM'),
    'blockfirmwareupdates_pattern_diffs': ('NIM',     lambda r: r.module == 'NIM-FW'),
    'nifm_pattern_diffs':                 ('NIFM',    lambda _: True),
    'ns_pattern_diffs':                   ('NS',      lambda _: True),
    # USB: three categories distinguished by version-range boundary and match_position
    'usb_pattern_1_diffs':                ('USB',     lambda r: r.max_version != FW_VER_ANY),
    'usb_pattern_2_diffs':                ('USB',     lambda r: r.max_version == FW_VER_ANY and r.match_position == 0),
    'usb_pattern_3_diffs':                ('USB',     lambda r: r.match_position == 1),
    'olsc_pattern_diffs':                 ('OLSC',    lambda _: True),
    'am_pattern_diffs':                   ('AM',      lambda _: True),
    # FS: each category selects rules by name fragment (fat32/exfat share the same FS rules)
    'fat32_noacidsigchk1_pattern_diffs':  ('FS',      lambda r: 'noacidsigchk1' in r.name),
    'exfat_noacidsigchk1_pattern_diffs':  ('FS',      lambda r: 'noacidsigchk1' in r.name),
    'fat32_noacidsigchk2_pattern_diffs':  ('FS',      lambda r: 'noacidsigchk2' in r.name),
    'exfat_noacidsigchk2_pattern_diffs':  ('FS',      lambda r: 'noacidsigchk2' in r.name),
    'fat32_noncasigchk_pattern_diffs':    ('FS',      lambda r: 'noncasigchk' in r.name),
    'exfat_noncasigchk_pattern_diffs':    ('FS',      lambda r: 'noncasigchk' in r.name),
    'fat32_nocntchk_pattern_diffs':       ('FS',      lambda r: 'nocntchk' in r.name),
    'exfat_nocntchk_pattern_diffs':       ('FS',      lambda r: 'nocntchk' in r.name),
    'browser_pattern_diffs':              ('BROWSER', lambda _: True),
    # SSL: three sub-modules distinguished by rule.module value
    'ssl_pattern_1_diffs':                ('SSL',     lambda r: r.module == 'SSL1'),
    'ssl_pattern_2_diffs':                ('SSL',     lambda r: r.module == 'SSL2'),
    'ssl_pattern_3_diffs':                ('SSL',     lambda r: r.module == 'SSL3'),
    'loader_pattern_diffs':               ('LOADER',  lambda _: True),
    'erpt_pattern_diffs':                 ('ERPT',    lambda _: True),
}


def get_known_patterns_for_category(category_name: str) -> List[Dict]:
    """Derive known-pattern entries for a diff category directly from PATCH_RULES."""
    if category_name not in CATEGORY_RULES_FILTER:
        return []
    rules_key, filter_func = CATEGORY_RULES_FILTER[category_name]
    rules = [r for r in PATCH_RULES.get(rules_key, []) if filter_func(r)]
    return [
        {
            'regex': rule.pattern,
            'offset': str(rule.offset),
            'match_position': rule.match_position,
            'version_range': f"{rule.min_version} to {rule.max_version}",
        }
        for rule in rules
    ]


# ---------------------------------------------------------------------------
# Version range helpers
# ---------------------------------------------------------------------------

def parse_version_range(version_str: str) -> Tuple[str, str]:
    match = re.search(r'(\d+\.\d+\.\d+)\s+to\s+(\d+\.\d+\.\d+)', version_str)
    if match:
        return match.group(1), match.group(2)
    return None, None


def generate_versions_in_range(start: str, end: str) -> List[str]:
    def parse_version(v):
        return tuple(map(int, v.split('.')))

    start_tuple = parse_version(start)
    end_tuple = parse_version(end)

    versions = []
    major, minor, patch = start_tuple
    while (major, minor, patch) <= end_tuple:
        versions.append(f"{major}.{minor}.{patch}")
        patch += 1
        if patch > 99:
            patch = 0
            minor += 1
            if minor > 99:
                minor = 0
                major += 1
    return versions


def build_version_to_known_pattern_map(known_patterns: List[Dict]) -> Dict[str, Dict]:
    """Build version → known-pattern-info map; first matching rule wins per version."""
    version_map = {}
    for pattern_info in known_patterns:
        start_ver, end_ver = parse_version_range(pattern_info['version_range'])
        if start_ver and end_ver:
            for version in generate_versions_in_range(start_ver, end_ver):
                if version not in version_map:
                    version_map[version] = {
                        'regex':          pattern_info['regex'],
                        'offset':         pattern_info['offset'],
                        'match_position': pattern_info.get('match_position', 0),
                        'version_range':  pattern_info['version_range'],
                    }
    return version_map


# ---------------------------------------------------------------------------
# Pattern analysis
# ---------------------------------------------------------------------------

def find_common_prefix_suffix(patterns: List[bytes]) -> Tuple[bytes, bytes]:
    if not patterns:
        return b'', b''

    prefix = b''
    min_len = min(len(p) for p in patterns)
    for i in range(min_len):
        if all(p[i:i+1] == patterns[0][i:i+1] for p in patterns):
            prefix += patterns[0][i:i+1]
        else:
            break

    suffix = b''
    for i in range(1, min_len + 1):
        if all(p[-i:] == patterns[0][-i:] for p in patterns if len(p) >= i):
            suffix = patterns[0][-i:] + suffix
        else:
            break

    return prefix, suffix


def create_wildcard_pattern(patterns: Dict[str, bytes], pattern_name: str) -> Tuple[str, Dict]:
    print(f"\n{'='*80}")
    print(f"Processing {pattern_name}")
    print(f"Found {len(patterns)} pattern entries")
    print(f"{'='*80}\n")

    if not patterns:
        return "", {"all": [], "partial": {}, "unmatchable": []}

    sorted_versions = sorted(patterns.keys(), key=lambda x: tuple(map(int, x.split('.'))))
    pattern_list = [patterns[v] for v in sorted_versions]

    prefix, suffix = find_common_prefix_suffix(pattern_list)

    if all(p == pattern_list[0] for p in pattern_list):
        print(f"\n✓ All {len(patterns)} patterns are IDENTICAL - using single pattern\n")
        pattern_hex = pattern_list[0].hex().upper()
        return pattern_hex, {"all": sorted_versions, "partial": {}, "unmatchable": []}

    if prefix and suffix:
        regex_pattern = prefix.hex().upper() + ".*" + suffix.hex().upper()
        all_match = all(
            p.hex().upper().startswith(prefix.hex().upper()) and
            p.hex().upper().endswith(suffix.hex().upper())
            for p in pattern_list
        )
        if all_match:
            return regex_pattern, {"all": sorted_versions, "partial": {}, "unmatchable": []}

    pattern_groups: Dict[str, List[str]] = {}
    for v, p in zip(sorted_versions, pattern_list):
        hex_p = p.hex().upper()
        if hex_p not in pattern_groups:
            pattern_groups[hex_p] = []
        pattern_groups[hex_p].append(v)

    version_mappings: Dict = {"all": [], "partial": {}, "unmatchable": []}
    for hex_pattern, versions in sorted(pattern_groups.items(), key=lambda x: -len(x[1])):
        if len(versions) == len(patterns):
            version_mappings["all"] = versions
        else:
            version_mappings["partial"][hex_pattern] = versions

    most_common_hex = max(pattern_groups.keys(), key=lambda x: len(pattern_groups[x]))
    version_mappings['pattern_bytes'] = patterns
    return most_common_hex, version_mappings


def add_markers_to_hex_pattern(hex_pattern: str, marker_position: int) -> str:
    """Mark 4 bytes (8 hex chars) at byte-offset marker_position in the pattern."""
    try:
        bytes.fromhex(hex_pattern)
    except ValueError:
        return hex_pattern

    hex_pos = marker_position * 2
    marker_start = hex_pos
    marker_end = min(len(hex_pattern), hex_pos + 8)

    if marker_start >= len(hex_pattern):
        marker_start = max(0, len(hex_pattern) - 8)
        marker_end = len(hex_pattern)

    before = hex_pattern[:marker_start]
    marked = hex_pattern[marker_start:marker_end]
    after  = hex_pattern[marker_end:]

    def spaced(h: str) -> str:
        return ' '.join(h[i:i+2] for i in range(0, len(h), 2))

    b, m, a = spaced(before), spaced(marked), spaced(after)

    if b and m and a:
        return f"{b} -> {m} <- {a}"
    elif b and m:
        return f"{b} -> {m} <-"
    elif m and a:
        return f"-> {m} <- {a}"
    else:
        return f"-> {m} <-"


# ---------------------------------------------------------------------------
# Main generation
# ---------------------------------------------------------------------------

def generate_all_regex_patterns() -> Dict:
    all_results = {}

    for category_name in ALL_CATEGORIES:
        pattern_dict = pattern_diffs_data.get(category_name, {})

        if not pattern_dict:
            print(f"\nSkipping {category_name} - no patterns found")
            continue

        known_patterns = get_known_patterns_for_category(category_name)
        version_map    = build_version_to_known_pattern_map(known_patterns)

        regex, mappings = create_wildcard_pattern(pattern_dict, category_name)
        all_results[category_name] = {
            'regex':          regex,
            'mappings':       mappings,
            'pattern_bytes':  mappings.get('pattern_bytes', {}),
            'total_versions': len(pattern_dict),
            'version_to_known': version_map,
        }

    return all_results


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_results_to_known_patterns_py(results: Dict):
    """Write known_patterns.py from the analysis results."""

    _LICENSE = """\
#!/usr/bin/env python

# Copyright (c) 2026 borntohonk
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""

    with open('scripts/known_patterns.py', 'w') as f:
        f.write(_LICENSE)
        f.write("# " + "="*78 + "\n")
        f.write("# AUTO-GENERATED PARTIAL REGEX PATTERNS\n")
        f.write("# These patterns were generated for firmware versions that don't match a\n")
        f.write("# single universal pattern. Each version may require its own specific pattern.\n")
        f.write("# " + "="*78 + "\n\n")

        for pattern_name, data in results.items():
            mappings        = data['mappings']
            version_to_known = data.get('version_to_known', {})

            # ── Universal: all versions share a single pattern ──────────────
            if mappings['all'] and not mappings['partial']:
                all_versions_sorted = sorted(
                    mappings['all'], key=lambda v: tuple(map(int, v.split('.')))
                )
                regex = data['regex']
                marked_pattern = add_markers_to_hex_pattern(regex, 32)
                first_known = version_to_known.get(all_versions_sorted[0], {})

                f.write(f"# {pattern_name}\n")
                f.write(pattern_name + "_universal_regex = {\n")

                if first_known:
                    f.write(f"    # Known pattern: {first_known['regex']}\n")
                    f.write(f"    # Offset: {first_known['offset']}\n")
                    f.write(f"    # Match position: {first_known.get('match_position', 0)}\n")
                    f.write(f"    # Valid from version: {all_versions_sorted[0]} to {all_versions_sorted[-1]}\n")
                    f.write(f"    # Original known range: {first_known['version_range']}\n")

                versions_str = ', '.join(f"{{'version': '{v}'}}" for v in all_versions_sorted)
                f.write(f"    \"{marked_pattern}\": [{versions_str}],\n")
                f.write("}\n\n")

            # ── Partial: multiple distinct patterns across versions ──────────
            if mappings['partial']:
                f.write(f"# {pattern_name}\n")
                f.write(pattern_name + "_partial_regexes = {\n")

                sorted_partial = sorted(
                    mappings['partial'].items(),
                    key=lambda x: tuple(map(int, x[1][-1].split('.'))),
                    reverse=True,
                )

                patterns_by_source: Dict = {}

                for hex_pattern, versions in sorted_partial:
                    marked_pattern = add_markers_to_hex_pattern(hex_pattern, 32)

                    versions_by_source: Dict = {}
                    for v in versions:
                        known_info = version_to_known.get(v, {})
                        source_key = (
                            known_info.get('regex', 'unknown'),
                            known_info.get('offset', 'unknown'),
                            known_info.get('version_range', 'unknown'),
                            known_info.get('match_position', 0),
                        )
                        versions_by_source.setdefault(source_key, []).append(v)

                    for source_key, source_versions in versions_by_source.items():
                        if source_key not in patterns_by_source:
                            first_ver = sorted(
                                source_versions, key=lambda x: tuple(map(int, x.split('.')))
                            )[0]
                            patterns_by_source[source_key] = {
                                'known_pattern':  source_key[0],
                                'offset':         source_key[1],
                                'original_range': source_key[2],
                                'match_position': source_key[3],
                                'hex_patterns':   [],
                                'all_versions':   [],
                                'first_version':  first_ver,
                            }

                        group = patterns_by_source[source_key]
                        for v in source_versions:
                            if v not in group['all_versions']:
                                group['all_versions'].append(v)

                        if marked_pattern not in [p['pattern'] for p in group['hex_patterns']]:
                            sv_sorted = sorted(source_versions, key=lambda x: tuple(map(int, x.split('.'))))
                            group['hex_patterns'].append({
                                'pattern':  marked_pattern,
                                'versions': [f"{{'version': '{sv}'}}" for sv in sv_sorted],
                            })

                sorted_sources = sorted(
                    patterns_by_source.items(),
                    key=lambda x: (
                        tuple(map(int, x[1]['first_version'].split('.')))
                        if x[1]['first_version'] else (999, 999, 999),
                        x[1]['offset'],
                    ),
                )

                for source_key, group in sorted_sources:
                    avs = sorted(group['all_versions'], key=lambda v: tuple(map(int, v.split('.'))))
                    min_v, max_v = avs[0], avs[-1]

                    original_range = group['original_range']
                    if original_range != 'unknown' and ' to ' in original_range:
                        upper = original_range.split(' to ')[1]
                        adjusted_range = f"{min_v} to {upper}"
                    else:
                        adjusted_range = original_range

                    f.write(f"    # Known pattern: {group['known_pattern']}\n")
                    f.write(f"    # Offset: {group['offset']}\n")
                    f.write(f"    # Match position: {group['match_position']}\n")
                    f.write(f"    # Valid from version: {min_v} to {max_v}\n")
                    if adjusted_range != 'unknown':
                        f.write(f"    # Original known range: {adjusted_range}\n")

                    def _first_ver_key(entry):
                        if entry['versions']:
                            m = re.search(r"'version':\s*'(\d+\.\d+\.\d+)'", entry['versions'][0])
                            return tuple(map(int, m.group(1).split('.'))) if m else (999, 999, 999)
                        return (999, 999, 999)

                    for entry in sorted(group['hex_patterns'], key=_first_ver_key):
                        f.write(f"    \"{entry['pattern']}\": [{', '.join(entry['versions'])}],\n")
                    f.write("\n")

                f.write("}\n\n")


if __name__ == "__main__":
    results = generate_all_regex_patterns()

    print(f"\n{'='*80}")
    print("SUMMARY")
    print(f"{'='*80}\n")

    for pattern_name, data in results.items():
        print(f"{pattern_name}:")
        print(f"  Total versions: {data['total_versions']}")
        mappings = data['mappings']
        if mappings['all']:
            print(f"  Universal match: {len(mappings['all'])} versions")
        if mappings['partial']:
            print(f"  Partial matches: {len(mappings['partial'])} pattern groups")
        print()

    write_results_to_known_patterns_py(results)
