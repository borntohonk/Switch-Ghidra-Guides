#!/usr/bin/env python

# Copyright (c) 2025 borntohonk
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
from typing import Dict, List, Tuple
from pattern_diffs import (
    es_pattern_diffs, blockfirmwareupdates_pattern_diffs, blankcal0crashfix_pattern_diffs, nifm_pattern_diffs,
    fat32_noncasigchk_pattern_diffs, exfat_noncasigchk_pattern_diffs,
    fat32_nocntchk_pattern_diffs, exfat_nocntchk_pattern_diffs
)

def parse_version_range(version_str: str) -> Tuple[str, str]:
    """Parse version range string like '1.0.0 to 8.1.1' and return (start, end)"""
    match = re.search(r'(\d+\.\d+\.\d+)\s+to\s+(\d+\.\d+\.\d+)', version_str)
    if match:
        return match.group(1), match.group(2)
    return None, None


def generate_versions_in_range(start: str, end: str) -> List[str]:
    """Generate all possible versions between start and end (inclusive)"""
    def parse_version(v):
        return tuple(map(int, v.split('.')))
    
    start_tuple = parse_version(start)
    end_tuple = parse_version(end)
    
    versions = []
    major = start_tuple[0]
    minor = start_tuple[1]
    patch = start_tuple[2]
    
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
    """Build a map from version to known pattern info"""
    version_map = {}
    
    for pattern_info in known_patterns:
        start_ver, end_ver = parse_version_range(pattern_info['version_range'])
        if start_ver and end_ver:
            versions = generate_versions_in_range(start_ver, end_ver)
            for version in versions:
                version_map[version] = {
                    'regex': pattern_info['regex'],
                    'offset': pattern_info['offset'],
                    'version_range': pattern_info['version_range']  # <-- ADD THIS LINE
                }
    
    return version_map

known_es_patterns = [
    {
        'regex': 'E8.00...FF97.0300AA..00.....E0.0091..0094.7E4092.......A9',
        'offset': '32',
        'version_range': '1.0.0 to 8.1.1'
    },
    {
        'regex': '00...............00.....A0..D1...97.......A9',
        'offset': '30',
        'version_range': '9.0.0 to 11.0.1'
    },
    {
        'regex': '02.00...........00...00.....A0..D1...97.......A9',
        'offset': '32',
        'version_range': '12.0.0 to 18.1.0'
    },
    {
        'regex': 'A1.00...........00...00.....A0..D1...97.......A9',
        'offset': '32',
        'version_range': '19.0.0 to 99.99.99'
    },
]

known_nifm_patterns = [
    {
        'regex': '03.AAE003.AA...39..04F8....E0',
        'offset': '-29',
        'version_range': '1.0.0 to 19.0.1'
    },
    {
        'regex': '03.AA...AA.........0314AA..14AA',
        'offset': '-17',
        'version_range': '20.0.0 to 99.99.99'
    },
]

known_blankcal0crashfix_patterns = [
    {
        'regex': '00351F2003D5...............97..0094..00.....61',
        'offset': '6',
        'version_range': '17.0.0 to 99.99.99'
    },
]

known_blockfirmwareupdates_patterns = [
    {
        'regex': '1139F30301AA81.40F9E0.1191',
        'offset': '-30',
        'version_range': '1.0.0 to 5.1.0'
    },
    {
        'regex': 'F30301AA.4E40F9E0..91',
        'offset': '-40',
        'version_range': '6.0.0 to 6.2.0'
    },
    {
        'regex': 'F30301AA014C40F9F40300AAE0..91',
        'offset': '-36',
        'version_range': '7.0.0 to 11.0.1'
    },
    {
        'regex': '280841F9084C00F9E0031F.C0035FD6',
        'offset': '16',
        'version_range': '12.0.0 to 99.99.99'
    },
]

known_fat32_and_exfat_noncasigchk_patterns = [
    {
        'regex': '1E48391F.0071..00544',
        'offset': '-17',
        'version_range': '10.0.0 to 16.1.0'
    },
    {
        'regex': '0694..00.42.0091',
        'offset': '-18',
        'version_range': '17.0.0 to 99.99.99'
    },
]

known_fat32_and_exfat_nocntchk_patterns = [
    {
        'regex': '00..0240F9....08.....00...00...0037',
        'offset': '6',
        'version_range': '10.0.0 to 18.1.0'
    },
    {
        'regex': '00..0240F9....08.....00...00...0054',
        'offset': '6',
        'version_range': '19.0.0 to 20.5.0'
    },
    {
        'regex': '00..0240F9....E8.....00...00...0054',
        'offset': '6',
        'version_range': '21.0.0 to 99.99.99'
    },
]

def find_common_prefix_suffix(patterns: List[bytes]) -> Tuple[bytes, bytes]:
    """Find common prefix and suffix among a list of byte patterns"""
    if not patterns:
        return b'', b''
    
    # Find common prefix
    prefix = b''
    min_len = min(len(p) for p in patterns)
    
    for i in range(min_len):
        if all(p[i:i+1] == patterns[0][i:i+1] for p in patterns):
            prefix += patterns[0][i:i+1]
        else:
            break
    
    # Find common suffix
    suffix = b''
    for i in range(1, min_len + 1):
        if all(p[-i:] == patterns[0][-i:] for p in patterns if len(p) >= i):
            suffix = patterns[0][-i:] + suffix
        else:
            break
    
    return prefix, suffix


def create_wildcard_pattern(patterns: Dict[str, bytes], pattern_name: str) -> Tuple[str, Dict[str, List[str]]]:
    """
    Create a regex pattern that matches all provided byte patterns.
    Returns (regex_pattern_str, version_mappings)
    
    version_mappings is a dict of:
    {
        'all': [versions that match the full pattern],
        'partial': {regex_str: [versions that match this partial pattern]},
        'unmatchable': [versions that don't match any pattern]
    }
    """
    print(f"\n{'='*80}")
    print(f"Processing {pattern_name}")
    print(f"Found {len(patterns)} pattern entries")
    print(f"{'='*80}\n")
    
    if not patterns:
        return "", {"all": [], "partial": {}, "unmatchable": []}
    
    # Sort versions for consistency
    sorted_versions = sorted(patterns.keys(), key=lambda x: tuple(map(int, x.split('.'))))
    pattern_list = [patterns[v] for v in sorted_versions]
    
    # Find common prefix and suffix
    prefix, suffix = find_common_prefix_suffix(pattern_list)
    
    #print(f"Common prefix: {prefix.hex().upper()}")
    #print(f"Common suffix: {suffix.hex().upper()}")
    #print(f"Prefix length: {len(prefix)} bytes")
    #print(f"Suffix length: {len(suffix)} bytes")
    
    # Check if all patterns are identical
    if all(p == pattern_list[0] for p in pattern_list):
        print(f"\n✓ All {len(patterns)} patterns are IDENTICAL - using single pattern\n")
        pattern_hex = pattern_list[0].hex().upper()
        regex = f"b'{bytes.fromhex(pattern_hex)!r}'[2:-1]"  # Remove b' and '
        return pattern_hex, {"all": sorted_versions, "partial": {}, "unmatchable": []}
    
    # Try to create a wildcard pattern that matches all
    # Use the prefix and suffix with wildcards for the middle
    if prefix and suffix:
        middle_wildcard = ".*"
        regex_pattern = prefix.hex().upper() + middle_wildcard + suffix.hex().upper()
        
        # Verify this matches all patterns
        all_match = True
        for v, p in zip(sorted_versions, pattern_list):
            hex_str = p.hex().upper()
            if not (hex_str.startswith(prefix.hex().upper()) and hex_str.endswith(suffix.hex().upper())):
                all_match = False
                break
        
        if all_match:
            #print(f"✓ Single wildcard pattern matches ALL {len(patterns)} versions\n")
            #print(f"Pattern: {regex_pattern}\n")
            return regex_pattern, {"all": sorted_versions, "partial": {}, "unmatchable": []}
    
    # Group identical patterns
    pattern_groups = {}
    for v, p in zip(sorted_versions, pattern_list):
        hex_p = p.hex().upper()
        if hex_p not in pattern_groups:
            pattern_groups[hex_p] = []
        pattern_groups[hex_p].append(v)
        
    version_mappings = {"all": [], "partial": {}, "unmatchable": []}
    
    for hex_pattern, versions in sorted(pattern_groups.items(), key=lambda x: -len(x[1])):
        
        if len(versions) == len(patterns):
            version_mappings["all"] = versions
        else:
            version_mappings["partial"][hex_pattern] = versions
    
    # Return the most common pattern as the primary one
    most_common_hex = max(pattern_groups.keys(), key=lambda x: len(pattern_groups[x]))
    most_common_versions = pattern_groups[most_common_hex]
    
    # For remaining versions, try to create wildcards
    other_versions = [v for v in sorted_versions if v not in most_common_versions]
    
    # Store original pattern bytes for analysis
    version_mappings['pattern_bytes'] = patterns
    
    return most_common_hex, version_mappings


def add_markers_to_hex_pattern(hex_pattern: str, marker_position: int) -> str:
    """
    Mark 4 bytes (8 hex chars) at a fixed byte position in the pattern.
    Output format: "A0 A2 04 91 F9 74 00" with markers around the marked section.
    """
    try:
        pattern_bytes = bytes.fromhex(hex_pattern)
    except ValueError:
        return hex_pattern
    
    # Convert byte position to hex character position
    hex_pos = marker_position * 2
    marker_start = hex_pos
    marker_end = min(len(hex_pattern), hex_pos + 8)
    
    if marker_start >= len(hex_pattern):
        # If position is beyond string, adjust to mark last 4 bytes
        marker_start = max(0, len(hex_pattern) - 8)
        marker_end = len(hex_pattern)
    
    before = hex_pattern[:marker_start]
    marked = hex_pattern[marker_start:marker_end]
    after = hex_pattern[marker_end:]
    
    # Convert to space-separated format
    def hex_to_spaced(h):
        return ' '.join(h[i:i+2] for i in range(0, len(h), 2))
    
    before_spaced = hex_to_spaced(before)
    marked_spaced = hex_to_spaced(marked)
    after_spaced = hex_to_spaced(after)
    
    # Build result with appropriate spacing
    if before_spaced and marked_spaced and after_spaced:
        return f"{before_spaced} -> {marked_spaced} <- {after_spaced}"
    elif before_spaced and marked_spaced:
        return f"{before_spaced} -> {marked_spaced} <-"
    elif marked_spaced and after_spaced:
        return f"-> {marked_spaced} <- {after_spaced}"
    else:
        return f"-> {marked_spaced} <-"


def generate_all_regex_patterns():
    """Generate regex patterns for all pattern types"""
    
    pattern_sets = {
        'es_pattern_diffs': es_pattern_diffs,
        'nim_blankcal0crashfix_pattern_diffs': blankcal0crashfix_pattern_diffs,
        'nim_blockfirmwareupdates_pattern_diffs': blockfirmwareupdates_pattern_diffs,
        'nifm_pattern_diffs': nifm_pattern_diffs,
        'fat32_noncasigchk_pattern_diffs': fat32_noncasigchk_pattern_diffs,
        'exfat_noncasigchk_pattern_diffs': exfat_noncasigchk_pattern_diffs,
        'fat32_nocntchk_pattern_diffs': fat32_nocntchk_pattern_diffs,
        'exfat_nocntchk_pattern_diffs': exfat_nocntchk_pattern_diffs,
    }
    
    # Map pattern names to their known patterns
    pattern_to_known = {
        'es_pattern_diffs': known_es_patterns,
        'nim_blankcal0crashfix_pattern_diffs': known_blankcal0crashfix_patterns,
        'nim_blockfirmwareupdates_pattern_diffs': known_blockfirmwareupdates_patterns,
        'nifm_pattern_diffs': known_nifm_patterns,
        'fat32_noncasigchk_pattern_diffs': known_fat32_and_exfat_noncasigchk_patterns,
        'exfat_noncasigchk_pattern_diffs': known_fat32_and_exfat_noncasigchk_patterns,
        'fat32_nocntchk_pattern_diffs': known_fat32_and_exfat_nocntchk_patterns,
        'exfat_nocntchk_pattern_diffs': known_fat32_and_exfat_nocntchk_patterns,
    }
    
    all_results = {}
    
    for pattern_name, pattern_dict in pattern_sets.items():
        if not pattern_dict:
            print(f"\nSkipping {pattern_name} - no patterns found")
            continue
        
        # Build version-to-known-pattern map
        known_patterns = pattern_to_known.get(pattern_name, [])
        version_map = build_version_to_known_pattern_map(known_patterns)
        
        regex, mappings = create_wildcard_pattern(pattern_dict, pattern_name)
        all_results[pattern_name] = {
            'regex': regex,
            'mappings': mappings,
            'pattern_bytes': mappings.get('pattern_bytes', {}),
            'total_versions': len(pattern_dict),
            'version_to_known': version_map
        }
    
    return all_results


def write_results_to_patterns_py(results: Dict):
    """Write the generated universal regex patterns to pattern_diffs.py"""
    
    with open('scripts/pattern_diffs.py', 'a') as f:
        f.write("\n\n")
        
        for pattern_name, data in results.items():
            regex = data['regex']
            mappings = data['mappings']
            version_to_known = data.get('version_to_known', {})
            
            if mappings['all']:
                f.write(f"# {pattern_name}\n")
                f.write(f"# Total versions covered: {data['total_versions']}\n\n")
                f.write(pattern_name + "_regex = {\n")
                f.write(f"    'pattern': \"{regex}\",\n")
                
                # Add known pattern info to each version
                versions_with_info = []
                for v in mappings['all']:
                    if v in version_to_known:
                        known_info = version_to_known[v]
                        version_entry = f"{{'version': '{v}', 'known_pattern': '{known_info['regex']}', 'offset': '{known_info['offset']}'}}"
                    else:
                        version_entry = f"{{'version': '{v}'}}"
                    versions_with_info.append(version_entry)
                
                f.write(f"    'versions': [\n")
                for entry in versions_with_info:
                    f.write(f"        {entry},\n")
                f.write(f"    ],\n")
                f.write(f"    'type': 'universal'\n")
                f.write("}\n\n")

def write_results_to_known_patterns_py(results: Dict):
    """Write the generated partial regex patterns to scripts/known_patterns.py"""
    
    with open('scripts/known_patterns.py', 'w') as f:
        f.write("#!/usr/bin/env python\n\n")
        f.write("# Copyright (c) 2025 borntohonk\n")
        f.write("#\n")
        f.write("# Permission is hereby granted, free of charge, to any person obtaining a copy\n")
        f.write("# of this software and associated documentation files (the \"Software\"), to deal\n")
        f.write("# in the Software without restriction, including without limitation the rights\n")
        f.write("# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\n")
        f.write("# copies of the Software, and to permit persons to whom the Software is\n")
        f.write("# furnished to do so, subject to the following conditions:\n")
        f.write("#\n")
        f.write("# The above copyright notice and this permission notice shall be included in all\n")
        f.write("# copies or substantial portions of the Software.\n")
        f.write("#\n")
        f.write("# THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n")
        f.write("# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n")
        f.write("# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n")
        f.write("# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n")
        f.write("# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n")
        f.write("# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\n")
        f.write("# SOFTWARE.\n\n")
        f.write("# " + "="*78 + "\n")
        f.write("# AUTO-GENERATED PARTIAL REGEX PATTERNS\n")
        f.write("# These patterns were generated for firmware versions that don't match a\n")
        f.write("# single universal pattern. Each version may require its own specific pattern.\n")
        f.write("# " + "="*78 + "\n\n")
        
        for pattern_name, data in results.items():
            mappings = data['mappings']
            version_to_known = data.get('version_to_known', {})
            
            if mappings['partial']:
                f.write(f"# {pattern_name}\n")
                f.write(pattern_name + "_partial_regexes = {\n")

                patterns_by_source = {}
                sorted_partial = sorted(
                    mappings['partial'].items(),
                    key=lambda x: tuple(map(int, x[1][-1].split('.'))),
                    reverse=True
                )
                
                marker_position = 32
                
                for hex_pattern, versions in sorted_partial:
                    marked_pattern = add_markers_to_hex_pattern(hex_pattern, marker_position)
                    
                    # Group these versions by their original known source
                    versions_by_source = {}
                    for v in versions:  # v is a string like '10.0.0'
                        known_info = version_to_known.get(v, {})
                        source_key = (
                            known_info.get('regex', 'unknown'),
                            known_info.get('offset', 'unknown'),
                            known_info.get('version_range', 'unknown')
                        )
                        
                        if source_key not in versions_by_source:
                            versions_by_source[source_key] = []
                        versions_by_source[source_key].append(v)
                    
                    # Add to global groups
                    for source_key, source_versions in versions_by_source.items():
                        if source_key not in patterns_by_source:
                            patterns_by_source[source_key] = {
                                'known_pattern': source_key[0],
                                'offset': source_key[1],
                                'original_range': source_key[2],
                                'hex_patterns': [],
                                'all_versions': []
                            }
                        
                        # Add versions (deduped)
                        for v in source_versions:
                            if v not in patterns_by_source[source_key]['all_versions']:
                                patterns_by_source[source_key]['all_versions'].append(v)
                        
                        # Add marked pattern if not already present for this source
                        existing = [p['pattern'] for p in patterns_by_source[source_key]['hex_patterns']]
                        if marked_pattern not in existing:
                            # Sort versions for display
                            sorted_source_versions = sorted(source_versions, key=lambda x: tuple(map(int, x.split('.'))))
                            versions_with_info = [f"{{'version': '{sv}'}}" for sv in sorted_source_versions]
                            patterns_by_source[source_key]['hex_patterns'].append({
                                'pattern': marked_pattern,
                                'versions': versions_with_info
                            })
                
                # Sort groups by earliest version
                sorted_sources = sorted(
                    patterns_by_source.items(),
                    key=lambda x: tuple(map(int, min(x[1]['all_versions'], key=lambda v: tuple(map(int, v.split('.')))).split('.')))
                )
                
                for source_key, group in sorted_sources:
                    all_versions_sorted = sorted(group['all_versions'], key=lambda v: tuple(map(int, v.split('.'))))
                    min_v = all_versions_sorted[0]
                    max_v = all_versions_sorted[-1]
                    
                    f.write(f"    # Known pattern: {group['known_pattern']}\n")
                    f.write(f"    # Offset: {group['offset']}\n")
                    f.write(f"    # Valid from version: {min_v} to {max_v}\n")
                    if group['original_range'] != 'unknown':
                        f.write(f"    # Original known range: {group['original_range']}\n")
                    
                    # Sort hex patterns by first version
                    def extract_first_version(entry):
                        if entry['versions']:
                            match = re.search(r"'version':\s*'(\d+\.\d+\.\d+)'", entry['versions'][0])
                            return tuple(map(int, match.group(1).split('.'))) if match else (999, 999, 999)
                        return (999, 999, 999)
                    
                    sorted_hex = sorted(group['hex_patterns'], key=extract_first_version)
                    
                    for entry in sorted_hex:
                        versions_str = ', '.join(entry['versions'])
                        f.write(f"    \"{entry['pattern']}\": [{versions_str}],\n")
                    f.write(f"\n")
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
    
    write_results_to_patterns_py(results)
    write_results_to_known_patterns_py(results)
