#!/usr/bin/env python3
# Recon of the eShop NextJS build: fetch the build manifest and every JS file the site loads, save them beautified,
# extract persisted-query info.
#
# Required packages:
#   requests          (pip install requests)
# Optional:
#   jsbeautifier      (pip install jsbeautifier)  without it the files are saved as downloaded
# External tool:
#   node              evaluates _buildManifest.js
#
# Usage: recon.py [buildId]      (default: the buildId the server serves to this session)
# Env:   CERT (default eshop_hac_prod.pem: certificate + private key), ENTRY_PATH (default /)
#
# Output (recon_out/): one beautified file per script, named after its path under /_next/ with "/" -> "_"
# (static/chunks/4490-x.js -> static_chunks_4490-x.js), plus manifest.js and persisted_queries.json.
# Nothing is ever overwritten with an error page, and nothing is deleted except the pretty_<name> copy that an
# older version of this script wrote next to a file it has just saved again.
#
# Why one Session and a first request to the entry page: the server sets a random "user-bucket" cookie and routes
# buckets to different builds. Requests that do not send it back can get the manifest of one build and static
# files of another (404). The scripts the page itself loads (main, framework, webpack, pages/_app, ...) are not
# in the build manifest, so they are taken from the entry page's <script> tags.

import json
import os
import re
import subprocess
import sys

try:
    import requests
    import urllib3
except ImportError:
    sys.exit("Missing required package: requests (pip install requests)")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://hac.lp1.savanna.srv.nintendo.net"
CERT_FILE = os.environ.get("CERT") or "eshop_hac_prod.pem"
ENTRY_PATH = os.environ.get("ENTRY_PATH") or "/"
USER_AGENT = ("Mozilla/5.0 (Nintendo Switch; ShopN) AppleWebKit/613.0 "
              "(KHTML, like Gecko) NF/6.0.3.31.11 NintendoBrowser/5.1.0.55481")
OUT_DIR = "recon_out"

SESSION = requests.Session()  # keeps the user-bucket cookie between requests
SESSION.verify = False  # curl --insecure
SESSION.cert = CERT_FILE
SESSION.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})


def get(path):
    url = path if path.startswith("http") else BASE_URL + path
    return SESSION.get(url, timeout=60)


def fetch_text(path):
    """Body of a 200 response, else None (reported). Never an error page."""
    try:
        r = get(path)
    except requests.RequestException as e:
        print(f"    [!] {path}: {e}")
        return None
    if r.status_code != 200:
        print(f"    [!] HTTP {r.status_code} for {path}")
        return None
    return r.text


def save(name, data):
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)
    return path


def beautify(js_text):
    try:
        import jsbeautifier
        return jsbeautifier.beautify(js_text)
    except ImportError:
        return js_text


def norm_script(src):
    """'/_next/static/chunks/x.js?dpl=1', 'static/chunks/x.js', 'https://host/_next/static/chunks/x.js' ->
    'static/chunks/x.js'; None for anything that is not a JS file under /_next/ of this host."""
    src = src.split("?", 1)[0].split("#", 1)[0]
    if src.startswith("http"):
        if not src.startswith(BASE_URL):
            return None
        src = src[len(BASE_URL):]
    src = src.lstrip("/")
    if src.startswith("_next/"):
        src = src[len("_next/"):]
    return src if src.endswith(".js") and src.startswith("static/") else None


def bootstrap():
    """GET the entry page: sets the user-bucket cookie and returns (buildId of that bucket's build, the scripts the
    page loads). The page may answer 500; its __NEXT_DATA__ and script tags are still used."""
    r = get(ENTRY_PATH)
    print(f"[*] {ENTRY_PATH} -> HTTP {r.status_code}, cookies: {sorted(SESSION.cookies.keys())}")
    build_id = None
    m = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', r.text, re.S)
    if m:
        try:
            build_id = json.loads(m.group(1)).get("buildId")
        except ValueError:
            pass
    scripts = []
    for tag in re.finditer(r'<(?:script|link)\b[^>]*?(?:src|href)="([^"]+\.js[^"]*)"', r.text):
        s = norm_script(tag.group(1))
        if s and s not in scripts:
            scripts.append(s)
    return build_id, scripts


def resolve_build_manifest(manifest_path):
    """Evaluate the manifest IIFE via node to get the real page->chunk mapping."""
    abs_path = os.path.abspath(manifest_path)
    node_script = f"""
    global.self = global;
    require({json.dumps(abs_path)});
    console.log(JSON.stringify(self.__BUILD_MANIFEST, null, 2));
    """
    try:
        result = subprocess.run(["node", "-e", node_script], capture_output=True, text=True)
    except FileNotFoundError:
        print("[!] node not found (needed to evaluate the build manifest)", file=sys.stderr)
        return {}
    if result.returncode != 0:
        print(f"[!] node eval failed: {result.stderr}", file=sys.stderr)
        return {}
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print("[!] could not parse node output as JSON", file=sys.stderr)
        return {}


AST_NAME_RE = re.compile(
    r'kind\s*:\s*["\']OperationDefinition["\'][^}]*?name\s*:\s*\{\s*kind\s*:\s*["\']Name["\']\s*,\s*value\s*:\s*["\']([A-Za-z0-9_]+)["\']'
)
HASH_RE = re.compile(r'sha256Hash\s*:\s*["\']([a-f0-9]{64})["\']')
HASH_NEAR_NAME_RE = re.compile(
    r'\{\s*id\s*:\s*["\']([a-f0-9]{64})["\']\s*,\s*operationName\s*:\s*["\']([A-Za-z0-9_]+)["\']'
)


def extract_persisted_queries(js_text):
    found = []
    for m in HASH_NEAR_NAME_RE.finditer(js_text):
        found.append({"hash": m.group(1), "operationName": m.group(2), "match": "id+operationName"})
    for m in AST_NAME_RE.finditer(js_text):
        found.append({"operationName": m.group(1), "match": "AST OperationDefinition"})
    for m in HASH_RE.finditer(js_text):
        found.append({"hash": m.group(1), "match": "bare sha256Hash"})
    return found


def main():
    if not os.path.isfile(CERT_FILE):
        sys.exit(f"client certificate not found: {CERT_FILE} (set CERT=/path/to/file.pem)")

    detected, page_scripts = bootstrap()
    build_id = sys.argv[1] if len(sys.argv) > 1 else detected
    if not build_id:
        print("[!] no buildId found in the page and none given on the command line, aborting")
        return
    if detected and build_id != detected:
        print(f"[!] given buildId {build_id} differs from the one served to this session ({detected}); "
              "static files may 404")
    print(f"[*] buildId = {build_id}")

    path = f"/_next/static/{build_id}/_buildManifest.js"
    print(f"[*] Fetching build manifest: {path}")
    manifest_text = fetch_text(path)
    if manifest_text is None:
        print("[!] could not fetch the build manifest, aborting (404: re-run; the build may have changed)")
        return
    manifest_path = save("manifest.js", beautify(manifest_text))

    print(f"[*] Resolving build manifest via node: {manifest_path}")
    page_chunks = resolve_build_manifest(manifest_path)
    if not page_chunks:
        print("[!] No manifest data resolved, aborting")
        return
    print(f"[+] Resolved {len(page_chunks)} manifest entries")

    scripts = []
    for chunks in page_chunks.values():
        if isinstance(chunks, list):
            for c in chunks:
                s = norm_script(c) if isinstance(c, str) else None
                if s and s not in scripts:
                    scripts.append(s)
    from_manifest = len(scripts)
    for s in page_scripts:
        if s not in scripts:
            scripts.append(s)
    print(f"[*] {len(scripts)} JS files to fetch ({from_manifest} from the manifest, "
          f"{len(scripts) - from_manifest} more from the entry page's script tags)")

    all_queries = {}
    got, failed = 0, []
    for script in sorted(scripts):
        print(f"[*] Fetching /_next/{script}")
        js_text = fetch_text("/_next/" + script)
        if js_text is None:
            failed.append(script)
            continue
        got += 1
        fname = script.replace("/", "_")
        pretty = beautify(js_text)
        save(fname, pretty)
        old = os.path.join(OUT_DIR, "pretty_" + fname)  # copy written by an older version of this script
        if os.path.isfile(old):
            os.remove(old)

        results = extract_persisted_queries(pretty)
        if results:
            print(f"    [+] {len(results)} candidate matches in {script}")
            for r in results:
                name = r.get("operationName", "UNKNOWN")
                entry = all_queries.setdefault(name, {"hashes": set(), "source_chunks": set()})
                if "hash" in r:
                    entry["hashes"].add(r["hash"])
                entry["source_chunks"].add(script)

    print("\n=== PERSISTED QUERY MAP ===")
    serializable = {}
    for name, data in all_queries.items():
        serializable[name] = {"hashes": sorted(data["hashes"]), "source_chunks": sorted(data["source_chunks"])}
        print(f"  {name}: {sorted(data['hashes'])}  <- {sorted(data['source_chunks'])}")
    save("persisted_queries.json", json.dumps(serializable, indent=2))
    print(f"\n[+] Saved mapping to {OUT_DIR}/persisted_queries.json")

    print(f"[+] {got} of {len(scripts)} JS files saved")
    if failed:
        print(f"[!] {len(failed)} not fetched (any earlier copy was left as it was): " + ", ".join(failed[:8])
              + (" ..." if len(failed) > 8 else ""))
        print("    404s usually mean the build changed or the session was routed to another bucket: re-run")
    # files from earlier runs of the old script that hold an error page instead of JavaScript
    bad = []
    for f in sorted(os.listdir(OUT_DIR)):
        if f.endswith(".js"):
            with open(os.path.join(OUT_DIR, f), encoding="utf-8", errors="replace") as fh:
                if fh.read(200).lstrip().startswith("<"):
                    bad.append(f)
    if bad:
        print(f"[!] {len(bad)} file(s) in {OUT_DIR}/ start with '<' (an HTML error page, not JS): "
              + ", ".join(bad[:8]) + (" ..." if len(bad) > 8 else ""))


if __name__ == "__main__":
    main()
