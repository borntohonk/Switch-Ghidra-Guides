#!/usr/bin/env python3
"""Update ipc_hashes.json (_hash / _hash_alt) from a folder of *_services.json exports.

DB schema:   "Services:" -> <program> -> <heading> -> <interface fullname> -> {_hash, _hash_alt?, ...}
Export:      { "<prog>": { "program_identified": "<Program>", "<iface fullname>": {_hash, _hash_alt?, ...}, ... } }

Matching is always (program, interface FULL name). Short names / headings are never used as keys, so
same-named interfaces in different namespaces or different programs cannot overwrite each other.

usage: update_ipc_hashes.py DB EXPORT_DIR [--dry-run] [--archive-old TAG]
"""
import argparse
import json
import re
import sys
from pathlib import Path

HASH_KEYS = ("_hash", "_hash_alt")
HEX16 = re.compile(r"[0-9a-f]{16}")


def load_export(path):
    """Return the export body (the dict holding program_identified), or None."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return None
    for body in data.values():
        if isinstance(body, dict) and "program_identified" in body:
            return body
    return None


def export_interfaces(body):
    """{fullname: entry} for interface blocks (keys with '::' holding a dict)."""
    return {k: v for k, v in body.items() if "::" in k and isinstance(v, dict)}


def find_program(services, name):
    """Exact key, else case-insensitive match, else None."""
    if name in services:
        return name
    low = {k.lower(): k for k in services}
    return low.get(name.lower())


def apply_hashes(entry, src, archive, log, where):
    """Write src _hash/_hash_alt into entry. Returns True if anything changed."""
    changed = False
    for key in HASH_KEYS:
        new = src.get(key)
        if new is None:
            continue
        old = entry.get(key)
        if old == new:
            continue
        if archive and old is not None:
            akey = f"{key}_{archive}"
            if akey in entry and entry[akey] != old:
                log(f"  WARN  {where}: {akey} already set to {entry[akey]}, not overwritten")
            else:
                entry[akey] = old
        entry[key] = new
        log(f"  {'SET ' if old is None else 'UPD '}  {where}: {key} {old} -> {new}")
        changed = True
    if "_hash_alt" not in src and "_hash_alt" in entry:
        log(f"  NOTE  {where}: DB has _hash_alt {entry['_hash_alt']} but export has none (left as is)")
    return changed


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("db", type=Path, help="path to ipc_hashes.json")
    ap.add_argument("exports", type=Path, help="folder of exported *.json files")
    ap.add_argument("--dry-run", action="store_true", help="report only, do not write")
    ap.add_argument("--archive-old", metavar="TAG",
                    help="keep replaced values as _hash_<TAG> / _hash_alt_<TAG> (the loader reads every _hash* key)")
    args = ap.parse_args()

    root = json.loads(args.db.read_text(encoding="utf-8"))
    services = root["Services:"]
    log = print
    stats = {"updated": 0, "unchanged": 0, "new": 0, "files": 0, "skipped": 0}
    seen = {}  # (program, iface) -> (hash, alt, file) to catch conflicting exports

    for path in sorted(args.exports.glob("*.json")):
        body = load_export(path)
        if body is None:
            log(f"SKIP  {path.name}: no program_identified")
            stats["skipped"] += 1
            continue
        stats["files"] += 1

        pid = body["program_identified"]
        prog_key = find_program(services, pid)
        if prog_key is None:
            log(f"NEW PROGRAM {pid} (not in DB)")
            prog_key = pid
            services[prog_key] = {}
        elif prog_key != pid:
            log(f"NOTE  {path.name}: program '{pid}' matched existing '{prog_key}' (case-insensitive)")
        prog = services[prog_key]
        log(f"== {path.name} -> {prog_key}")

        exported = export_interfaces(body)
        for name, src in exported.items():
            h = src.get("_hash")
            if h is None:
                log(f"  WARN  {name}: export has no _hash, skipped")
                continue
            for key in HASH_KEYS:
                v = src.get(key)
                if v is not None and not HEX16.fullmatch(v):
                    log(f"  WARN  {name}: {key} '{v}' is not 16 lowercase hex chars")

            sig = (h, src.get("_hash_alt"))
            prev = seen.setdefault((prog_key, name), (*sig, path.name))
            if prev[:2] != sig:
                log(f"  WARN  {name}: conflicts with {prev[2]} ({prev[0]}/{prev[1]} vs {sig[0]}/{sig[1]}), skipped")
                continue

            # every heading in this program that already holds this exact interface name
            headings = [hd for hd, ifs in prog.items() if isinstance(ifs, dict) and name in ifs]
            if headings:
                changed = False
                for hd in headings:
                    changed |= apply_hashes(prog[hd][name], src, args.archive_old, log, f"{name} [{hd}]")
                stats["updated" if changed else "unchanged"] += 1
            else:
                # new interface: file under its short-name heading; setdefault + sibling insert means an
                # existing heading (same short name, different namespace) keeps its other interfaces
                hd = name.rsplit("::", 1)[-1]
                entry = {k: src[k] for k in HASH_KEYS if k in src}
                prog.setdefault(hd, {})[name] = entry
                log(f"  NEW   {name} under [{hd}]: {entry}")
                stats["new"] += 1

        db_only = sorted({n for hd, ifs in prog.items() if isinstance(ifs, dict)
                          for n in ifs if "::" in n and n not in exported})
        for n in db_only:
            log(f"  DBONLY {n} (in DB, not in this export; untouched)")

    log(f"\nfiles={stats['files']} skipped={stats['skipped']} updated={stats['updated']} "
        f"unchanged={stats['unchanged']} new={stats['new']}")

    if args.dry_run:
        log("dry run, nothing written")
        return 0
    args.db.write_text(json.dumps(root, indent=4) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
