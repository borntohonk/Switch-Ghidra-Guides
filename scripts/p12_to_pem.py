#!/usr/bin/env python3
# Convert the eShop client certificate (.p12) to a PEM (key + cert + chain), reading the password from
# meta.json, and report the target URL patterns from the referenced URLs file.
#
# Required packages:
#   cryptography    (pip install cryptography)
#
# CLI:      p12_to_pem.py <input_folder> [-o OUTPUT_DIR] [--raw]
#           <input_folder> contains meta.json, the .p12 it names, and its targetUrlsFile.
#
# Library:  convert_client_cert(p12_file_object, json_file_object, txt_file_object, output_pem_path)
#           takes the three files as in-memory objects (nothing needs to exist on disk), writes the PEM
#           and returns (pem_bytes, urls). Objects may be bytes / bytearray / memoryview / str, or
#           anything with a .read() method (e.g. io.BytesIO).

import argparse
import json
import os
import re
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        pkcs12,
    )
except ImportError as _e:
    raise ImportError(
        "Missing required package: cryptography\n"
        "Required packages: cryptography\n"
        "Install with: pip install cryptography"
    ) from _e


class ClientCertError(Exception):
    """Raised when the client certificate cannot be converted."""


# ---------------------------------------------------------------- helpers

def _as_bytes(obj, what):
    """bytes-like, str, or file-like (.read()) -> bytes."""
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return bytes(obj)
    if isinstance(obj, str):
        return obj.encode("utf-8")
    read = getattr(obj, "read", None)
    if callable(read):
        seek = getattr(obj, "seek", None)
        if callable(seek):
            try:
                seek(0)
            except (OSError, ValueError):
                pass
        data = read()
        return data.encode("utf-8") if isinstance(data, str) else bytes(data)
    raise TypeError(f"{what}: unsupported object type {type(obj).__name__} "
                    "(expected bytes, str, or an object with .read())")


def readable(pattern: str) -> list:
    """Turn a simple URL regex into human-readable URLs: optional/alternation groups are expanded,
    character classes become '*', escapes are removed. Returns one string per variant."""
    p = pattern.strip()
    p = p[1:] if p.startswith("^") else p
    p = re.sub(r"\(/\|\$\)$", "/", p)  # trailing "(/|$)" -> "/"
    p = re.sub(r"\$$", "", p)
    p = re.sub(r"\[[^\]]*\][+*]?", "*", p)  # character class -> wildcard

    def expand(s):
        m = re.search(r"\(([^()]*)\)(\?)?", s)
        if not m:
            return [s]
        alts = m.group(1).split("|") + ([""] if m.group(2) else [])
        out = []
        for a in alts:
            out.extend(expand(s[:m.start()] + a + s[m.end():]))
        return out

    seen, res = set(), []
    for v in expand(p):
        v = re.sub(r"\\(.)", r"\1", v)
        if v not in seen:
            seen.add(v)
            res.append(v)
    return res


def p12_to_pem_bytes(p12_data: bytes, password) -> bytes:
    """PKCS#12 bytes -> PEM bytes (PKCS#8 key, then cert, then chain). password: str, bytes or None."""
    if isinstance(password, str):
        password = password.encode("utf-8")
    try:
        key, cert, extra = pkcs12.load_key_and_certificates(p12_data, password or None)
    except ValueError as e:
        raise ClientCertError(f"cannot load .p12 (wrong password in meta.json?): {e}") from e
    pem = b""
    if key is not None:
        pem += key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    if cert is not None:
        pem += cert.public_bytes(Encoding.PEM)
    for c in extra or []:
        pem += c.public_bytes(Encoding.PEM)
    return pem


def _urls(urls_data, raw=False) -> list:
    if urls_data is None:
        return []
    text = urls_data.decode("utf-8-sig") if isinstance(urls_data, bytes) else urls_data
    res = []
    for line in text.splitlines():
        if line.strip():
            res.extend([line] if raw else readable(line))
    return res


def _meta_entries(meta_data: bytes) -> list:
    try:
        entries = json.loads(meta_data.decode("utf-8-sig"))["list"]
    except (ValueError, KeyError, TypeError) as e:
        raise ClientCertError(f"invalid meta.json (expected a 'list' array): {e}") from e
    if not isinstance(entries, list) or not entries:
        raise ClientCertError("meta.json 'list' is empty")
    return entries


# ---------------------------------------------------------------- library entry point

def convert_client_cert(p12_file_object, json_file_object, txt_file_object=None,
                        output_pem_path=None, raw_urls=False):
    """Single-step conversion from in-memory files.

    p12_file_object   the .p12 (eshop_hac_prod.p12)
    json_file_object  meta.json (the first entry of its 'list' supplies the password)
    txt_file_object   the URLs file (optional)
    output_pem_path   if given, the PEM is written there (parent folders are created)
    raw_urls          True = URL patterns as written (regex), False = readable form

    Returns (pem_bytes, urls). Raises ClientCertError on bad input / wrong password.
    """
    entry = _meta_entries(_as_bytes(json_file_object, "meta.json"))[0]
    pem = p12_to_pem_bytes(_as_bytes(p12_file_object, ".p12"), entry.get("password"))
    urls = _urls(_as_bytes(txt_file_object, "urls file") if txt_file_object is not None else None, raw_urls)
    if output_pem_path:
        parent = os.path.dirname(os.fspath(output_pem_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(output_pem_path, "wb") as f:
            f.write(pem)
    return pem, urls


# ---------------------------------------------------------------- CLI

def _read(path: Path) -> bytes:
    if not path.is_file():
        raise ClientCertError(f"{path} not found")
    return path.read_bytes()


def main():
    ap = argparse.ArgumentParser(description="Convert the eShop client certificate .p12 to PEM.")
    ap.add_argument("folder", type=Path, help="folder containing meta.json, the .p12 and the URLs file")
    ap.add_argument("-o", "--output-dir", type=Path, default=Path("."), help="where to write the .pem (default: .)")
    ap.add_argument("--raw", action="store_true", help="print the URL patterns as written (regex)")
    args = ap.parse_args()

    try:
        if not args.folder.is_dir():
            raise ClientCertError(f"{args.folder} is not a directory")
        entries = _meta_entries(_read(args.folder / "meta.json"))
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for entry in entries:
            p12_path = args.folder / entry["file"]
            urls_name = entry.get("targetUrlsFile")
            pem = p12_to_pem_bytes(_read(p12_path), entry.get("password"))
            pem_path = args.output_dir / (p12_path.stem + ".pem")
            pem_path.write_bytes(pem)
            print(f"wrote {pem_path}", file=sys.stderr)
            if urls_name:
                for u in _urls(_read(args.folder / urls_name), args.raw):
                    print(u)
    except (ClientCertError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()