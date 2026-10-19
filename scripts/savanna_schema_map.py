#!/usr/bin/env python3
# Savanna GraphQL schema map. The eShop GraphQL server (Savanna) has introspection disabled, so its schema is
# reconstructed from two independent sources and compared with what simba.py requests:
#   - mine:  the queries the eShop web client ships (offline; proof that a field works under its parent)
#   - crawl: the server's own validation, field name by field name (live; finds fields the client never uses)
#
# Usage: python scripts/savanna_schema_map.py <command> [args]   (no command prints this help)
#
#   mine  [chunk_dir] [out.json]      offline. Every GraphQL document in the web client's JS chunks (compiled ASTs or
#                                     query strings) -> which fields are selected under which parent, by operation
#                                     root and by type condition. Writes out.json and out.md (same name, .md).
#                                     Defaults: recon_out  docs/savanna_map.json (-> docs/savanna_map.md, the map
#                                     simba.py's *-full commands read)
#   crawl [out.json] [root ...]       live, validation-only. Walks the schema from the known roots, testing candidate
#                                     field names in batches (the error column locates every rejected field) and
#                                     type conditions. Default out: schema_probed.json. Roots (default: all):
#                                     application demo dlc bundle country searchV4 item-lookups query
#   audit [probed.json] [root ...]    live. Re-verifies every crawled node against the server and re-crawls the ones
#                                     it rejects (use after a crawl made with REUSE=1 before reuse was verified).
#   check [observed.json] [probed.json]
#                                     offline. Every field simba.py requests, against both maps, plus the fields the
#                                     maps know that simba.py does not request. Writes schema_check.md.
#   show  <Type|root> [...]           what the maps say about a type or crawl root (e.g. show DlcItem, show dlc)
#
# Typical runs:
#   python scripts/recon_savanna.py                                 # fetch the client's JS chunks into recon_out/
#   python scripts/savanna_schema_map.py mine                       # -> docs/savanna_map.json + docs/savanna_map.md
#   python scripts/savanna_schema_map.py crawl schema_probed.json dlc   # live crawl of one root
#   python scripts/savanna_schema_map.py check                      # simba.py against both maps
#
# crawl, check and show read docs/savanna_map.json, or docs/savanna_map.md when there is no .json. crawl tests every
# field name in that map, in simba.py's queries and in its EXTRA_FIELDS (BUILTIN_WORDS only when there is no map);
# WORDS adds your own guesses.
#
# nsUids: crawl and audit need no real nsUid. They only test whether the server accepts a field: an error carrying a
# response "path" comes from running a field that passed validation and is ignored, so the lookup roots use fixed
# placeholder nsUids (application 70010000000025, demo 70030000000001, dlc 70050000000001, bundle 70070000000001)
# and an item that does not exist (null) changes nothing. Each root is calibrated first: { __typename } must be
# accepted and an unknown field rejected, otherwise the root is skipped.
#
# env (crawl / audit): CERT GQL SHOP COUNTRY LANG_CODE REGION as in simba.py  BATCH (100 names per request)
#              DEPTH (5)  WORDS (file: extra candidate names, one per line)  TYPES (file or comma list: extra type
#              names for `... on T`)  REUSE=1 (reuse results for a field name seen under another root; verify with
#              audit)  SLEEP (as in simba.py)  DEBUG=1
# Requires: requests (via simba.py; crawl, audit and check only). mine and show need no third-party packages.

import bisect
import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OBSERVED = os.path.join(os.path.dirname(SCRIPT_DIR), "docs", "savanna_map.json")  # mine writes the .md next to it
PROBED = "schema_probed.json"
CHECKED = "schema_check.md"
MARK = "\x00"


def env(name, default=""):
    v = os.environ.get(name)
    return v if v else default


def err(*a):
    print(*a, file=sys.stderr, flush=True)


class Status:
    """One progress line on stderr (redrawn on a terminal, a new line every STATUS_EVERY seconds otherwise)."""
    def __init__(self):
        self.tty = sys.stderr.isatty()
        self.every = float(os.environ.get("STATUS_EVERY") or (1 if self.tty else 30))
        self.last = 0.0
        self.width = 0

    def show(self, text, force=False):
        now = time.time()
        if not force and now - self.last < self.every:
            return
        self.last = now
        if self.tty:
            sys.stderr.write("\r" + text.ljust(self.width)[:200])
            self.width = len(text)
            sys.stderr.flush()
        else:
            err(text)

    def done(self):
        if self.tty and self.width:
            sys.stderr.write("\r" + " " * min(self.width, 200) + "\r")
            sys.stderr.flush()
            self.width = 0


STATUS = Status()


def fmt_secs(x):
    x = int(x)
    return f"{x // 3600}h{x % 3600 // 60:02d}m" if x >= 3600 else f"{x // 60}m{x % 60:02d}s"


def dig(obj, *keys):
    for k in keys:
        if isinstance(obj, dict):
            obj = obj.get(k)
        else:
            return None
    if keys and keys[-1] == "value" and not isinstance(obj, str):
        return None  # a JS expression ({"$expr": ...}) instead of a literal name
    return obj


# ---------------------------------------------------------------- JS object literals (compiled gql documents)

_IDENT = re.compile(r"[A-Za-z_$][\w$]*")
_NUM = re.compile(r"-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?")
_ESC = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}


class JsLiteral:
    """Parser for the JS literal subset that compiled GraphQL documents use: objects, arrays, strings, numbers,
    !0 / !1, null, void 0. Anything else (identifiers, calls, ...) becomes {"$expr": text}; spreads become
    {"$spreads": [...]} (objects) / {"$spread": ...} (arrays). Never executes anything."""

    def __init__(self, s):
        self.s = s
        self.n = len(s)

    def ws(self, i):
        s, n = self.s, self.n
        while i < n:
            c = s[i]
            if c in " \t\r\n":
                i += 1
            elif s.startswith("//", i):
                j = s.find("\n", i)
                i = n if j < 0 else j + 1
            elif s.startswith("/*", i):
                j = s.find("*/", i + 2)
                i = n if j < 0 else j + 2
            else:
                break
        return i

    def string(self, i):
        s, n = self.s, self.n
        q = s[i]
        j = i + 1
        buf = []
        while j < n:
            c = s[j]
            if c == "\\" and q != "`":
                nx = s[j + 1] if j + 1 < n else ""
                if nx == "u":
                    try:
                        buf.append(chr(int(s[j + 2:j + 6], 16)))
                        j += 6
                        continue
                    except ValueError:
                        pass
                if nx == "x":
                    try:
                        buf.append(chr(int(s[j + 2:j + 4], 16)))
                        j += 4
                        continue
                    except ValueError:
                        pass
                buf.append(_ESC.get(nx, nx))
                j += 2
                continue
            if c == q:
                return "".join(buf), j + 1
            buf.append(c)
            j += 1
        raise ValueError("unterminated string")

    def skip_expr(self, i):
        """Skip an expression that is not modelled; stops before a top-level , } ] ) ."""
        s, n = self.s, self.n
        depth = 0
        j = i
        while j < n:
            c = s[j]
            if c in "\"'`":
                _, j = self.string(j)
                continue
            if c in "([{":
                depth += 1
            elif c in ")]}":
                if depth == 0:
                    break
                depth -= 1
            elif c == "," and depth == 0:
                break
            j += 1
        return {"$expr": s[i:j].strip()[:200]}, j

    def skip_balanced(self, i):
        """i at ( [ or {: index after the matching closer."""
        s, n = self.s, self.n
        depth = 0
        j = i
        while j < n:
            c = s[j]
            if c in "\"'`":
                _, j = self.string(j)
                continue
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
        raise ValueError("unbalanced")

    def value(self, i, top=False):
        i = self.ws(i)
        s, n = self.s, self.n
        if i >= n:
            raise ValueError("eof")
        start = i
        c = s[i]
        if c == "{":
            v, j = self.obj(i)
        elif c == "[":
            v, j = self.arr(i)
        elif c in "\"'`":
            v, j = self.string(i)
        elif s.startswith("!0", i):
            v, j = True, i + 2
        elif s.startswith("!1", i):
            v, j = False, i + 2
        else:
            m = _NUM.match(s, i)
            if m:
                txt = m.group()
                v, j = (float(txt) if any(ch in txt for ch in ".eE") else int(txt)), m.end()
            else:
                m = _IDENT.match(s, i)
                lit = {"true": True, "false": False, "null": None, "undefined": None}
                if m and m.group() in lit:
                    v, j = lit[m.group()], m.end()
                elif m and m.group() == "void" and s[self.ws(m.end()):self.ws(m.end()) + 1] == "0":
                    v, j = None, self.ws(m.end()) + 1
                else:
                    return self.skip_expr(i)
        k = self.ws(j)
        if not top and k < n and s[k] not in ",}])":  # part of a larger expression ("a" + b, [..].concat(x))
            return self.skip_expr(start)
        return v, j

    def obj(self, i):
        s, n = self.s, self.n
        i += 1
        d = {}
        while True:
            i = self.ws(i)
            if i >= n:
                raise ValueError("eof in object")
            if s[i] == "}":
                return d, i + 1
            if s.startswith("...", i):
                v, i = self.value(i + 3)
                d.setdefault("$spreads", []).append(v)
            else:
                if s[i] in "\"'":
                    key, i = self.string(i)
                elif s[i] == "[":
                    i = self.skip_balanced(i)
                    key = "$computed"
                else:
                    m = _IDENT.match(s, i) or _NUM.match(s, i)
                    if not m:
                        raise ValueError(f"bad key at {i}: {s[i:i + 30]!r}")
                    key, i = m.group(), m.end()
                i = self.ws(i)
                if i < n and s[i] == ":":
                    d[key], i = self.value(i + 1)
                elif i < n and s[i] in ",}":
                    d[key] = {"$expr": key}
                elif i < n and s[i] == "(":  # method shorthand: skip params and body
                    i = self.ws(self.skip_balanced(i))
                    if i < n and s[i] == "{":
                        i = self.skip_balanced(i)
                    d[key] = {"$expr": "function"}
                else:
                    raise ValueError(f"unexpected {s[i:i + 30]!r} at {i}")
            i = self.ws(i)
            if i < n and s[i] == ",":
                i += 1

    def arr(self, i):
        s, n = self.s, self.n
        i += 1
        out = []
        while True:
            i = self.ws(i)
            if i >= n:
                raise ValueError("eof in array")
            if s[i] == "]":
                return out, i + 1
            if s[i] == ",":
                i += 1
                continue
            if s.startswith("...", i):
                v, i = self.value(i + 3)
                out.append({"$spread": v})
            else:
                v, i = self.value(i)
                out.append(v)
            i = self.ws(i)
            if i < n and s[i] == ",":
                i += 1


def brace_pairs(s):
    """{index of '{': index of its '}'} for a JS text (strings, comments and regex literals skipped)."""
    pairs, stack = {}, []
    i, n, prev = 0, len(s), ""
    while i < n:
        c = s[i]
        if c in "\"'`":
            j = i + 1
            while j < n and s[j] != c:
                j += 2 if s[j] == "\\" else 1
            i, prev = j + 1, c
            continue
        if c == "/" and i + 1 < n:
            nx = s[i + 1]
            if nx == "/":
                j = s.find("\n", i)
                i = n if j < 0 else j
                continue
            if nx == "*":
                j = s.find("*/", i + 2)
                i = n if j < 0 else j + 2
                continue
            if prev == "" or prev in "(,=:[!&|?{};":  # regex literal
                j, incls, ok = i + 1, False, False
                while j < n:
                    ch = s[j]
                    if ch == "\n":
                        break
                    if ch == "\\":
                        j += 2
                        continue
                    if ch == "[":
                        incls = True
                    elif ch == "]":
                        incls = False
                    elif ch == "/" and not incls:
                        ok = True
                        break
                    j += 1
                if ok:
                    i, prev = j + 1, "/"
                    continue
        if c == "{":
            stack.append(i)
        elif c == "}" and stack:
            pairs[stack.pop()] = i
        if not c.isspace():
            prev = c
        i += 1
    return pairs


KIND_RE = re.compile(r'kind\s*:\s*["\'](Document|OperationDefinition|FragmentDefinition)["\']')


def extract_js_objects(text):
    """-> ([parsed objects of kind Document / standalone OperationDefinition / FragmentDefinition], [warnings])."""
    pairs = brace_pairs(text)
    opens = sorted(pairs)
    lit = JsLiteral(text)
    found, warns, consumed = [], [], []

    def enclosing(p):
        k = bisect.bisect_right(opens, p) - 1
        while k >= 0:
            o = opens[k]
            if pairs[o] > p:
                seg = text[o + 1:p]
                return o if not any(ch in seg for ch in "{[(") else None
            k -= 1
        return None

    def inside(o):
        return any(a <= o <= b for a, b in consumed)

    matches = list(KIND_RE.finditer(text))
    for want in ("Document", "OperationDefinition", "FragmentDefinition"):
        for m in matches:
            if m.group(1) != want:
                continue
            o = enclosing(m.start())
            if o is None or inside(o):
                continue
            try:
                obj, _ = lit.value(o, top=True)
            except (ValueError, IndexError) as e:
                warns.append(f"offset {o}: {e}")
                continue
            consumed.append((o, pairs[o]))
            found.append(obj)
    return found, warns


# ---------------------------------------------------------------- normalised selections

def norm_sel(node):
    """AST SelectionSet dict -> {"fields": [{"name","alias","args","sel"}], "frags": [{"type","sel"}],
    "spreads": [name], "unresolved": n}."""
    sel = {"fields": [], "frags": [], "spreads": [], "unresolved": 0}
    for s in (node or {}).get("selections") or []:
        if not isinstance(s, dict):
            continue
        k = s.get("kind")
        if k == "Field":
            sub = s.get("selectionSet")
            sel["fields"].append({
                "name": dig(s, "name", "value"), "alias": dig(s, "alias", "value"),
                "args": [dig(a, "name", "value") for a in s.get("arguments") or [] if isinstance(a, dict)],
                "sel": norm_sel(sub) if isinstance(sub, dict) else None})
        elif k == "InlineFragment":
            sel["frags"].append({"type": dig(s, "typeCondition", "name", "value"),
                                 "sel": norm_sel(s.get("selectionSet"))})
        elif k == "FragmentSpread":
            nm = dig(s, "name", "value")
            if nm:
                sel["spreads"].append(nm)
            else:
                sel["unresolved"] += 1
        elif "$spread" in s or "$expr" in s:
            sel["unresolved"] += 1
    return sel


def js_type(t):
    if not isinstance(t, dict):
        return "?"
    k = t.get("kind")
    if k == "NonNullType":
        return js_type(t.get("type")) + "!"
    if k == "ListType":
        return "[" + js_type(t.get("type")) + "]"
    return dig(t, "name", "value") or "?"


def collect_defs(obj, source, ops, frags):
    k = obj.get("kind") if isinstance(obj, dict) else None
    if k == "Document":
        for d in obj.get("definitions") or []:
            collect_defs(d, source, ops, frags)
    elif k == "OperationDefinition":
        op = obj.get("operation")
        ops.append({
            "name": dig(obj, "name", "value"), "operation": op if isinstance(op, str) else "query",
            "variables": [{"name": dig(v, "variable", "name", "value"), "type": js_type(v.get("type"))}
                          for v in obj.get("variableDefinitions") or [] if isinstance(v, dict)],
            "sel": norm_sel(obj.get("selectionSet")), "source": source})
    elif k == "FragmentDefinition":
        name = dig(obj, "name", "value")
        if name and name not in frags:
            frags[name] = {"name": name, "type": dig(obj, "typeCondition", "name", "value"),
                           "sel": norm_sel(obj.get("selectionSet")), "source": source}


# ---------------------------------------------------------------- GraphQL query text (strings in chunks, simba.py)

_GQL_TOK = re.compile(
    r'(?:\s+|,|#[^\n]*)*(?:(?P<punct>\.\.\.|[!$&():=@\[\]{|}])|(?P<name>[_A-Za-z][_0-9A-Za-z]*)'
    r'|(?P<num>-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|(?P<str>"""[\s\S]*?"""|"(?:[^"\\]|\\.)*"))')


def gql_tokens(s):
    toks, i = [], 0
    while True:
        m = _GQL_TOK.match(s, i)
        if not m:
            if s[i:].strip(" \t\r\n,") and not s[i:].lstrip().startswith("#"):
                raise ValueError(f"cannot tokenize at {i}: {s[i:i + 30]!r}")
            return toks
        kind = m.lastgroup
        toks.append((kind, m.group(kind)))
        i = m.end()


class GqlParser:
    def __init__(self, text):
        self.t = gql_tokens(text)
        self.i = 0

    def peek(self, k=0):
        j = self.i + k
        return self.t[j] if j < len(self.t) else (None, None)

    def take(self):
        tok = self.peek()
        self.i += 1
        return tok

    def expect(self, val):
        tok = self.take()
        if tok[1] != val:
            raise ValueError(f"expected {val!r}, got {tok[1]!r}")

    def document(self):
        ops, frags = [], {}
        while self.i < len(self.t):
            kind, val = self.peek()
            if val == "{":
                ops.append({"name": None, "operation": "query", "variables": [], "sel": self.selection_set()})
            elif val in ("query", "mutation", "subscription"):
                self.take()
                name = None
                if self.peek()[0] == "name":
                    name = self.take()[1]
                variables = self.var_defs() if self.peek()[1] == "(" else []
                self.directives()
                ops.append({"name": name, "operation": val, "variables": variables, "sel": self.selection_set()})
            elif val == "fragment":
                self.take()
                name = self.take()[1]
                self.expect("on")
                typ = self.take()[1]
                self.directives()
                frags[name] = {"name": name, "type": typ, "sel": self.selection_set()}
            else:
                raise ValueError(f"unexpected token {val!r}")
        return ops, frags

    def var_defs(self):
        self.expect("(")
        out = []
        while self.peek()[1] != ")":
            self.expect("$")
            name = self.take()[1]
            self.expect(":")
            typ = self.type_ref()
            if self.peek()[1] == "=":
                self.take()
                self.skip_value()
            self.directives()
            out.append({"name": name, "type": typ})
        self.expect(")")
        return out

    def type_ref(self):
        if self.peek()[1] == "[":
            self.take()
            inner = self.type_ref()
            self.expect("]")
            t = "[" + inner + "]"
        else:
            t = self.take()[1]
        if self.peek()[1] == "!":
            self.take()
            t += "!"
        return t

    def skip_value(self):
        kind, val = self.take()
        if val == "$":
            self.take()
        elif val in ("[", "{"):
            close = "]" if val == "[" else "}"
            depth = 1
            while depth:
                v = self.take()[1]
                depth += (v in ("[", "{")) - (v in ("]", "}"))
            _ = close

    def arguments(self):
        names = []
        if self.peek()[1] == "(":
            self.take()
            while self.peek()[1] != ")":
                names.append(self.take()[1])
                self.expect(":")
                self.skip_value()
            self.expect(")")
        return names

    def directives(self):
        while self.peek()[1] == "@":
            self.take()
            self.take()
            self.arguments()

    def selection_set(self):
        self.expect("{")
        sel = {"fields": [], "frags": [], "spreads": [], "unresolved": 0}
        while self.peek()[1] != "}":
            if self.peek()[1] == "...":
                self.take()
                if self.peek()[1] == "on":
                    self.take()
                    typ = self.take()[1]
                    self.directives()
                    sel["frags"].append({"type": typ, "sel": self.selection_set()})
                elif self.peek()[1] in ("{", "@"):
                    self.directives()
                    sel["frags"].append({"type": None, "sel": self.selection_set()})
                else:
                    sel["spreads"].append(self.take()[1])
                    self.directives()
            else:
                name = self.take()[1]
                alias = None
                if self.peek()[1] == ":":
                    self.take()
                    alias, name = name, self.take()[1]
                args = self.arguments()
                self.directives()
                sub = self.selection_set() if self.peek()[1] == "{" else None
                sel["fields"].append({"name": name, "alias": alias, "args": args, "sel": sub})
        self.expect("}")
        return sel


def parse_gql(text):
    return GqlParser(text).document()


_QUERY_STR = re.compile(r'\b(?:query|mutation)\s+[A-Za-z_]\w*\s*(?:\([^)]*\))?\s*(?:@\w+\([^)]*\)\s*)*\{')


def extract_query_strings(text):
    """Operations written as plain query text inside a chunk (e.g. 'query Foo($a: Int) { ... }')."""
    out = []
    for m in _QUERY_STR.finditer(text):
        i = m.end() - 1
        depth, j = 0, i
        while j < len(text):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        else:
            continue
        try:
            ops, frags = parse_gql(text[m.start():j + 1])
        except ValueError:
            continue
        out.append((ops, frags))
    return out


# ---------------------------------------------------------------- observed tree

def new_node():
    return {"fields": {}, "types": set()}


def add_sel(node, sel, ftype, frags, seen, source, types, unresolved):
    """Merge a normalised selection into a path-tree node (fields keyed by name, children by path) and into the
    per-type index for every type condition met on the way."""
    unresolved["count"] += sel.get("unresolved", 0)
    for f in sel["fields"]:
        if not f["name"]:
            continue
        e = node["fields"].setdefault(f["name"], {"args": set(), "types": set(), "n": 0, "children": None,
                                                  "sources": set()})
        e["args"].update(a for a in f["args"] if a)
        e["types"].add(ftype)
        e["n"] += 1
        e["sources"].add(source)
        if f["sel"] is not None:
            if e["children"] is None:
                e["children"] = new_node()
            add_sel(e["children"], f["sel"], None, frags, seen, source, types, unresolved)
    for fr in sel["frags"]:
        t = fr["type"]
        if t:
            node["types"].add(t)
            add_sel(types.setdefault(t, new_node()), fr["sel"], t, frags, seen, source, types, unresolved)
        add_sel(node, fr["sel"], t or ftype, frags, seen, source, types, unresolved)
    for name in sel["spreads"]:
        d = frags.get(name)
        if d is None:
            unresolved.setdefault("names", set()).add(name)
            continue
        if name in seen:
            continue
        t = d["type"]
        if t:
            node["types"].add(t)
            add_sel(types.setdefault(t, new_node()), d["sel"], t, frags, seen | {name}, source, types, unresolved)
        add_sel(node, d["sel"], t or ftype, frags, seen | {name}, source, types, unresolved)


def node_json(node):
    out = {"fields": {}}
    for k, e in sorted(node["fields"].items()):
        j = {"args": sorted(e["args"]), "types": sorted(t if t else "*" for t in e["types"]), "count": e["n"]}
        if e["children"] is not None:
            j["children"] = node_json(e["children"])
        out["fields"][k] = j
    if node["types"]:
        out["types"] = sorted(node["types"])
    return out


def _md_node(node, indent, lines, depth=0):
    for k, e in node.get("fields", {}).items():
        args = f"({', '.join(e['args'])})" if e.get("args") else ""
        on = [t for t in e.get("types", []) if t != "*"]
        tail = f"   [on {', '.join(on)}]" if on and "*" not in e.get("types", []) else ""
        lines.append(f"{'  ' * indent}- {k}{args}{tail}")
        if "children" in e and depth < 12:
            _md_node(e["children"], indent + 1, lines, depth + 1)


def mine(chunk_dir, out_path):
    if not os.path.isdir(chunk_dir):
        sys.exit(f"{chunk_dir}: not a directory (run recon_savanna.py first)")
    files = sorted(f for f in os.listdir(chunk_dir) if f.endswith(".js"))
    ops, frags, warns = [], {}, []
    for f in files:
        with open(os.path.join(chunk_dir, f), encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        objs, w = extract_js_objects(text)
        warns.extend(f"{f}: {x}" for x in w)
        for obj in objs:
            collect_defs(obj, f, ops, frags)
        for qops, qfrags in extract_query_strings(text):
            for op in qops:
                op["source"] = f
                ops.append(op)
            for name, d in qfrags.items():
                frags.setdefault(name, {**d, "source": f})
    tree, types = {}, {}
    unresolved = {"count": 0}
    for op in ops:
        add_sel(tree.setdefault(op["operation"], new_node()), op["sel"], None, frags, frozenset(), op["source"],
                types, unresolved)
    result = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"), "chunks": len(files),
        "operations": [{"name": o["name"], "operation": o["operation"], "variables": o["variables"],
                        "source": o["source"]} for o in ops],
        "fragments": [{"name": d["name"], "type": d["type"], "source": d["source"]} for d in frags.values()],
        "tree": {k: node_json(v) for k, v in tree.items()},
        "types": {k: node_json(v) for k, v in sorted(types.items())},
        "unresolved_fragment_spreads": sorted(unresolved.get("names", [])),
        "unresolved_selection_entries": unresolved["count"],
        "parse_warnings": warns,
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=1, ensure_ascii=False)
        fh.write("\n")
    md = ["# GraphQL as used by the web client", "",
          f"{len(files)} chunks, {len(ops)} operations, {len(frags)} fragments. Fields below are selected by "
          "queries that ship with the site, so they are valid under that parent.", "", "## Operations", ""]
    for o in result["operations"]:
        v = ", ".join(f"${x['name']}: {x['type']}" for x in o["variables"])
        md.append(f"- {o['operation']} {o['name'] or '(anonymous)'}({v})  <- {o['source']}")
    md += ["", "## Paths (from the operation root)", ""]
    for k, v in result["tree"].items():
        md += [f"### {k}", ""]
        _md_node(v, 0, md)
        md.append("")
    md += ["## Types (fields selected under a type condition)", ""]
    for t, v in result["types"].items():
        md += [f"### {t}", ""]
        _md_node(v, 0, md)
        md.append("")
    with open(os.path.splitext(out_path)[0] + ".md", "w", encoding="utf-8") as fh:
        fh.write("\n".join(md) + "\n")
    err(f"mine: {len(files)} chunks, {len(ops)} operations, {len(frags)} fragments, {len(types)} types "
        f"-> {out_path}, {os.path.splitext(out_path)[0]}.md")
    if unresolved.get("names"):
        err(f"mine: {len(unresolved['names'])} fragment spread(s) with no definition in the chunks: "
            + ", ".join(sorted(unresolved["names"])[:10]))
    if warns:
        err(f"mine: {len(warns)} parse warning(s) (see parse_warnings in the JSON)")
    if not ops:
        err("mine: no GraphQL documents found - are these the beautified chunks from recon.py?")


# ---------------------------------------------------------------- live crawl

# Known-good call shapes for fields that need arguments (taken from simba.py's working queries).
SEEDED_CALLS = {
    "dlcItems": "(offset: 0, limit: 1, publicStatuses: [PUBLIC], salesStatuses: [ONSALE], isIncludeBundleItem: true)",
}

# Fallback candidate names for crawl when no schema map is available: field names the map confirms, plus genre
# (selected live by simba.py). crawl adds every name in the map and in simba.py's queries and EXTRA_FIELDS anyway;
# put guesses for fields nobody selects yet in a WORDS file.
BUILTIN_WORDS = """__typename nsUid formalName name publicStatus labelPlatform applications id imageUrl catchCopy heroBannerUrl
screenshotUrls releaseDateOnEshop description publisher ratingInfo rating ratingSystem contentDescriptors languages
isoCode playerNumber offlineMin offlineMax localMin localMax onlineMin onlineMax romRights titleId romSizes hac
totalRomSize estimatedRomSize rawValue svgImageUrl age demoItems dlcItems items itemsV2 item targetApplicationItems
isNew movies movieUrl movieMetaId isInline itemType offsetInfo length offset total isMembershipRequired upgradeInfo
playerNumberDescription miscDescription networkFeatureDescription regionCode availableLanguages defaultLanguage
code shopStatuses shopOpenStatus price discountPrice regularPrice salesStatus titleIds categories tags features url
text isFree genre""".split()

BUILTIN_TYPES = ["Item", "ApplicationItem", "DemoItem", "DlcItem", "BundleItem", "EshopMovie", "NemoMovie", "Movie",
                 "Query", "Country", "SearchResult", "ItemV2"]


def _simba():
    if SCRIPT_DIR not in sys.path:
        sys.path.insert(0, SCRIPT_DIR)
    try:
        import simba
    except ImportError as e:
        sys.exit(f"cannot import simba.py (same directory as schema_map.py, needs requests): {e}")
    return simba


def _hdr(decl):
    return ("query P($shopId: Int!, $country: CountryCode!, $language: LanguageCode!" + decl
            + ") @inContext(shopId: $shopId, country: $country, language: $language) ")


_SEARCH_DECL = (", $region: RequestableRegion!, $freeword: String, $itemTypes: [SearchItemType!], "
                "$labelPlatforms: [RequestableDeviceType!], $limit: Int!, $offset: Int!, "
                "$salesStatus: RequestableSearchSalesStatus, $sort: SearchSort!")


def _search_vars(simba):
    return {**simba._search_vars("ONSALE_OR_PRE_ORDER", "RELEASE_DATE_DESC", "", "HAC", 1), "offset": 0}


def root_specs(simba):
    """name -> (variable declarations, template with MARK where the selection goes, variables)."""
    def lookup(field, ns):
        return (", $nsUid: NsUid!", "{ item { %s(nsUid: $nsUid) { %s } } }" % (field, MARK), {"nsUid": ns})
    return {
        "application": lookup("applicationItem", 70010000000025),
        "demo": lookup("demoItem", 70030000000001),
        "dlc": lookup("dlcItem", 70050000000001),
        "bundle": lookup("bundleItem", 70070000000001),
        "country": ("", "{ country { %s } }" % MARK, {}),
        "searchV4": (_SEARCH_DECL,
                     "{ searchV4(region: $region, freeword: $freeword, itemTypes: $itemTypes, labelPlatforms: "
                     "$labelPlatforms, limit: $limit, offset: $offset, salesStatus: $salesStatus, sort: $sort) "
                     "{ %s } }" % MARK, _search_vars(simba)),
        "query": ("", "{ %s }" % MARK, {}),
    }


# Lookup fields under `item` take arguments, so they are tested with these call shapes instead of bare names.
LOOKUP_FORMS = [
    ("nsUid", ", $nsUid: NsUid!", "(nsUid: $nsUid)", {"nsUid": 70010000000025}),
    ("nsUids", ", $nsUids: [NsUid!]!", "(nsUids: $nsUids)", {"nsUids": [70010000000025]}),
    ("titleIds", ", $titleIds: [TitleId!]!",
     "(titleIds: $titleIds, publicStatuses: [PUBLIC], selectFirst: false, type: APPLICATION)",
     {"titleIds": ["0100000000010000"]}),
]


CONCRETE_ROOT = {"ApplicationItem": "application", "DemoItem": "demo", "DlcItem": "dlc", "BundleItem": "bundle"}

# Roots whose node IS a concrete type: expanding `... on <that type>` / `... on Item` there repeats the plain node.
ROOT_OWN = {"application": frozenset({"ApplicationItem", "Item"}), "demo": frozenset({"DemoItem", "Item"}),
            "dlc": frozenset({"DlcItem", "Item"}), "bundle": frozenset({"BundleItem", "Item"})}


class RootError(Exception):
    pass


def _unused_variable(e):
    msg = (e.get("message") or "") if isinstance(e, dict) else str(e)
    return "never used" in msg.lower() or "unused variable" in msg.lower()


REUSE_CACHE = {}


def node_snippets(node):
    """The fields a crawled node says exist, as selection snippets (objects as `x { __typename }`)."""
    out = [n + SEEDED_CALLS.get(n, "") for n in node.get("leaf") or []]
    out += [n + SEEDED_CALLS.get(n, "") + " { __typename }" for n in (node.get("object") or {})]
    return out


class Prober:
    """Validation-only probing of one root. run() returns the indexes of the snippets the server rejects."""

    def __init__(self, simba, name, decl, template, variables, batch):
        self.simba = simba
        self.name = name
        self.header = _hdr(decl)
        self.template = template
        self.variables = variables
        self.batch = batch
        self.delta = 0
        self.use_cols = True
        self.requests = 0
        self.samples = []
        self.t0 = time.time()
        self.lock = threading.RLock()
        self.sem = threading.BoundedSemaphore(max(1, int(env("THREADS", "1"))))
        self.threads = max(1, int(env("THREADS", "1")))
        self.reuse = env("REUSE") not in ("", "0")
        self.cache = REUSE_CACHE  # REUSE: field name -> (depth, result), shared between roots
        self.reused = 0
        self.rejected_reuse = 0
        self.nodes_done = 0
        self.queued = 0  # object nodes found but not yet visited
        self.where = name

    def _send(self, before, body, after):
        tpl_before, tpl_after = self.template.split(MARK)
        query = self.header + tpl_before + before + body + after + tpl_after
        base = len(self.header) + len(tpl_before) + len(before)
        with self.sem:
            r = self.simba.rawreq("P", query, self.variables, "en_US")
            self.simba.sleep_if()
        with self.lock:
            self.requests += 1
        self.status()
        errs = r.get("errors") if isinstance(r, dict) else None
        if errs:
            # declared but unused variables are not about the probed fields; an error with a response "path" comes
            # from running the field (it passed validation), a rejected field has no path
            errs = [e for e in errs if not _unused_variable(e) and not (isinstance(e, dict) and e.get("path"))]
        if errs:
            for e in errs:
                msg = e.get("message") if isinstance(e, dict) else str(e)
                with self.lock:
                    if msg and msg not in self.samples and len(self.samples) < 12:
                        self.samples.append(msg)
        return errs or [], base

    def status(self, force=False):
        el = max(time.time() - self.t0, 1e-9)
        rate = self.requests / el
        txt = f"  [{self.name}] {self.requests} req, {rate:.1f}/s, {fmt_secs(el)}, nodes done {self.nodes_done}"
        if self.queued:
            per = self.requests / max(self.nodes_done, 1)
            txt += f", queued {self.queued} (>= {fmt_secs(self.queued * per / max(rate, 1e-9))} left)"
        STATUS.show(txt + f"  @ {self.where}", force)

    def _attribute(self, e, starts, snippets, base):
        locs = e.get("locations") if isinstance(e, dict) else None
        if self.use_cols and locs and isinstance(locs, list) and isinstance(locs[0], dict):
            col, line = locs[0].get("column"), locs[0].get("line", 1)
            if isinstance(col, int) and line == 1:
                pos = col - 1 - self.delta
                if pos < base:
                    return "header"
                return max(bisect.bisect_right(starts, pos) - 1, 0)
        msg = (e.get("message") or "") if isinstance(e, dict) else str(e)
        m = re.search(r"[Ff]ield\s+[\"'`](\w+)[\"'`]", msg)  # Cannot query field "x" / Field "x" must have ...
        if m:
            for k, sn in enumerate(snippets):
                if re.match(r"\w+", sn) and re.match(r"\w+", sn).group() == m.group(1):
                    return k
        return None

    def _run(self, before, after, snippets):
        body = " ".join(snippets)
        starts, pos = [], 0
        errs, base = self._send(before, body, after)
        if not errs:
            return set()
        for sn in snippets:
            starts.append(base + pos)
            pos += len(sn) + 1
        rej, lost = set(), False
        for e in errs:
            k = self._attribute(e, starts, snippets, base)
            if k == "header":
                raise RootError(f"{self.name}: error outside the probed selection: {json.dumps(e)[:300]}")
            if k is None:
                lost = True
            else:
                rej.add(k)
        if lost:  # an error that cannot be tied to a snippet: bisect
            if len(snippets) == 1:
                return {0}
            mid = len(snippets) // 2
            left = self._run(before, after, snippets[:mid])
            right = self._run(before, after, snippets[mid:])
            return left | {mid + k for k in right}
        return rej

    def run(self, before, after, snippets):
        rej = set()
        for off in range(0, len(snippets), self.batch):
            part = snippets[off:off + self.batch]
            rej |= {off + k for k in self._run(before, after, part)}
        return rej

    def calibrate(self):
        ok_errs, _ = self._send("", "__typename", "")
        if ok_errs:
            raise RootError(f"{self.name}: baseline query {{ __typename }} was rejected: "
                            f"{json.dumps(ok_errs)[:500]}")
        errs, base = self._send("", "__typename zzNoSuchField9x", "")
        if not errs:
            raise RootError(f"{self.name}: an unknown field was accepted - the server does not validate selections")
        locs = dig(errs[0], "locations")
        want = base + len("__typename ") + 1
        if isinstance(locs, list) and locs and isinstance(locs[0], dict) and isinstance(locs[0].get("column"), int):
            self.delta = locs[0]["column"] - want
            if self.delta not in (0, -1, 1):
                err(f"  {self.name}: error column is off by {self.delta} from the field start (calibrated)")
        else:
            self.use_cols = False
            err(f"  {self.name}: errors carry no usable location - slow mode (bisecting)")

    def classify(self, before, after, names):
        """names -> (leaf, object, unknown). A name is a leaf if it is accepted bare, an object if it is accepted
        with { __typename }, unknown if neither (no such field, or it needs arguments)."""
        def sn(n, tail=""):
            return n + SEEDED_CALLS.get(n, "") + tail
        rej1 = self.run(before, after, [sn(n) for n in names])
        leaf = [n for i, n in enumerate(names) if i not in rej1]
        rest = [names[i] for i in sorted(rej1)]
        rej2 = self.run(before, after, [sn(n, " { __typename }") for n in rest])
        obj = [n for j, n in enumerate(rest) if j not in rej2]
        unk = [n for j, n in enumerate(rest) if j in rej2]
        return leaf, obj, unk

    def types_at(self, before, after, types):
        if not types:
            return []
        rej = self.run(before, after, [f"... on {t} {{ __typename }}" for t in types])
        return [t for i, t in enumerate(types) if i not in rej]

    def node(self, before, after, names, types, depth, max_depth, memo, path, in_type=False, skip=frozenset()):
        self.where = ".".join(path)
        self.status()
        leaf, obj, unk = self.classify(before, after, names)
        with self.lock:
            self.nodes_done += 1
        res = {"leaf": sorted(leaf), "unknown": sorted(unk), "object": {}, "types": [], "on": {}}
        if not in_type:
            res["types"] = self.types_at(before, after, types)
        todo = [f for f in sorted(obj) if depth < max_depth]
        with self.lock:
            self.queued += len(todo)
        for f in sorted(obj):
            if depth >= max_depth:
                res["object"][f] = {"truncated": True}

        def child(f):
            key = (next((x for x in reversed(path) if not x.startswith("[")), ""), f)  # parent field + field
            b, a = before + f + SEEDED_CALLS.get(f, "") + " { ", " } " + after
            with self.lock:
                self.queued -= 1
                hit = self.cache.get(key) if self.reuse else None
            if hit and hit[0] <= depth + 1:  # crawled with at least as much depth budget left
                snips = node_snippets(hit[1])
                if not snips or not self.run(b, a, snips):  # every field it had is accepted here too
                    with self.lock:
                        self.reused += 1
                    return hit[1]
                with self.lock:
                    self.rejected_reuse += 1
            sub = self.node(b, a, names, types, depth + 1, max_depth, memo, path + [f])
            if self.reuse:
                with self.lock:
                    self.cache.setdefault(key, (depth + 1, sub))
            return sub

        if self.threads > 1 and len(todo) > 1:
            with ThreadPoolExecutor(max_workers=len(todo)) as ex:
                futs = [(f, ex.submit(child, f)) for f in todo]
                for f, fu in futs:
                    res["object"][f] = fu.result()
        else:
            for f in todo:
                res["object"][f] = child(f)
        for t in res["types"]:
            if t in skip:  # the root's own type (and its interface): same fields as the plain node
                res["on"][t] = {"see": "<root>"}
                if CONCRETE_ROOT.get(t) == self.name:
                    memo.setdefault(t, "root:" + self.name)
                continue
            with self.lock:
                seen_t = t in memo
                if not seen_t:
                    memo[t] = ".".join(path) or self.name
            if seen_t:
                res["on"][t] = {"see": t}
                continue
            res["on"][t] = self.node(before + f"... on {t} {{ ", " } " + after, names, types, depth, max_depth,
                                     memo, path + [f"[{t}]"], in_type=True)
        return res


def _walk_names(node, out):
    for k, e in (node.get("fields") or {}).items():
        out.add(k)
        if "children" in e:
            _walk_names(e["children"], out)


def load_json(path):
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


_MD_FIELD = re.compile(r'^(?P<ind> *)- (?P<name>[_A-Za-z]\w*)(?:\((?P<args>[^)]*)\))?(?:\s+\[on (?P<on>[^\]]+)\])?\s*$')


def load_observed(path):
    """The mined map: path (.json), or the .md written next to it when the .json is missing, read back into the
    same {"tree": {op: node}, "types": {type: node}} shape (no counts). None if neither exists."""
    data = load_json(path)
    md = os.path.splitext(path)[0] + ".md"
    if data is not None or not os.path.isfile(md):
        return data
    data, section, stack = {"tree": {}, "types": {}}, None, []
    with open(md, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("## "):
                section = "tree" if line.startswith("## Paths") else "types" if line.startswith("## Types") else None
            elif line.startswith("### ") and section:
                stack = [data[section].setdefault(line[4:].strip(), {"fields": {}})]
            elif section and stack:
                m = _MD_FIELD.match(line)
                if not m:
                    continue
                depth = len(m["ind"]) // 2
                del stack[depth + 1:]
                parent = stack[-1]
                if parent is not stack[0] and "children" not in parent:
                    parent["children"] = {"fields": {}}
                fields = (parent["children"] if parent is not stack[0] else parent)["fields"]
                e = fields.setdefault(m["name"], {"args": [a.strip() for a in (m["args"] or "").split(",") if a.strip()],
                                                  "types": [t.strip() for t in (m["on"] or "").split(",") if t.strip()] or ["*"],
                                                  "count": 0})
                stack.append(e)
    return data


def simba_queries(simba):
    """The GraphQL documents simba.py sends, without any live probing."""
    qs = {n: getattr(simba, n) for n in ("Q_COUNTRY", "Q_ITEM", "Q_TITLE", "Q_DLC_TITLES", "Q_SEARCH_APP",
                                         "Q_SEARCH_DLC", "Q_SCRAPE")}
    extras = " ".join(simba.BUNDLE_EXTRAS)
    qs["Q_SEARCH_APP+BundleItem"] = simba._search_bundle_query(simba.BUNDLE_BASE + " " + extras)
    qs["Q_SCRAPE+demoItems"] = simba._scrape_query(" ".join(simba.DEMO_EXTRAS))
    qs["DlcItems"] = ("query DlcItems($shopId: Int!, $country: CountryCode!, $language: LanguageCode!, "
                      "$nsUid: NsUid!) @inContext(shopId: $shopId, country: $country, language: $language) "
                      "{ item { applicationItem(nsUid: $nsUid) { nsUid "
                      + simba.dlc_items_selection(0, 25, "PUBLIC", "ONSALE,PRE_ORDER", "true") + " } } }")
    scans = {
        "Scan:demoItem": ("demoItem", "__typename nsUid name: formalName labelPlatform " + " ".join(simba.DEMO_EXTRAS)),
        "Scan:dlcItem": ("dlcItem", "__typename nsUid name: formalName labelPlatform " + simba.DLC_RECORD_FIELDS),
        "Scan:bundleItem": ("bundleItem", "__typename nsUid " + simba.BUNDLE_BASE + " " + extras),
        "Scan:applicationItem": ("applicationItem", "nsUid itemType formalName releaseDateOnEshop labelPlatform "
                                 "publicStatus heroBannerUrl romRights { titleId }"),
    }
    for name, (root, sel) in scans.items():
        qs[name] = simba.alias_apps_query("Scan", [1], sel, root)[0]
    if hasattr(simba, "_scrape_batch_selection"):  # fetch_apps / scrape-all batches
        qs["ScrapeBatch"] = simba.alias_apps_query("ScrapeBatch", [1], simba._scrape_batch_selection(),
                                                   "applicationItem")[0]
    for kind, frag in (("APPLICATION", "ApplicationItem"), ("DLC", "DlcItem")):  # ids()
        qs["TitleIds:" + kind] = (
            "query TitleIds($shopId: Int!, $country: CountryCode!, $language: LanguageCode!, $titleIds: [TitleId!]!) "
            "@inContext(shopId: $shopId, country: $country, language: $language) { item { itemsByTitleIdsV2("
            f"titleIds: $titleIds, publicStatuses: [PUBLIC], selectFirst: false, type: {kind}) "
            f"{{ nsUid itemV2 {{ ... on {frag} {{ romRights {{ titleId }} }} }} }} }} }}")
    return qs


def gather_candidates(simba):
    """-> (field names, type names) to test: built-in list + everything the web client and simba.py select."""
    observed = load_observed(OBSERVED)
    words = set(BUILTIN_WORDS)
    types = set(BUILTIN_TYPES)
    if observed:
        for tree in observed.get("tree", {}).values():
            _walk_names(tree, words)
        for t, tree in observed.get("types", {}).items():
            types.add(t)
            _walk_names(tree, words)
        types.update(f["type"] for f in observed.get("fragments", []) if f.get("type"))
    else:
        err(f"crawl: no schema map at {OBSERVED} (or its .md) - using the built-in word list only "
            "(run `mine` first for a better one)")
    for sel in (simba.EXTRA_FIELDS[k][n] for k in simba.EXTRA_FIELDS for n in simba.EXTRA_FIELDS[k]):  # live-verified
        for w in re.findall(r"(?:\.\.\.\s*on\s+)?[_A-Za-z]\w*", sel):
            if w.startswith("..."):
                types.add(w.split()[-1])
            elif w != "on":
                words.add(w)
    for qtext in simba_queries(simba).values():
        ops, _ = parse_gql(qtext)
        for op in ops:
            tmp = {"fields": {}, "types": set()}
            add_sel(tmp, op["sel"], None, {}, frozenset(), "simba", {}, {"count": 0})
            stack = [tmp]
            while stack:
                n = stack.pop()
                for k, e in n["fields"].items():
                    words.add(k)
                    if e["children"] is not None:
                        stack.append(e["children"])
                types.update(t for t in n["types"] if t)
    extra = env("WORDS")
    if extra and os.path.isfile(extra):
        with open(extra, encoding="utf-8") as fh:
            words.update(w.strip() for w in fh if w.strip() and not w.startswith("#"))
    extra = env("TYPES")
    if extra:
        if os.path.isfile(extra):
            with open(extra, encoding="utf-8") as fh:
                types.update(w.strip() for w in fh if w.strip())
        else:
            types.update(t.strip() for t in extra.split(",") if t.strip())
    names = sorted(w for w in words if re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]*", w) and (not w.startswith("__")
                                                                                         or w == "__typename"))
    tnames = sorted(t for t in types if re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]*", t or ""))
    return names, tnames


def crawl(out_path, only):
    simba = _simba()
    if not os.path.isfile(simba.CERT):
        sys.exit(f"client certificate not found: {simba.CERT} (set CERT=/path/to/file.pem)")
    names, tnames = gather_candidates(simba)
    batch = int(env("BATCH", "100"))
    depth = int(env("DEPTH", "5"))
    specs = root_specs(simba)
    wanted = only or ["application", "demo", "dlc", "bundle", "country", "searchV4", "item-lookups"]
    prev = load_json(out_path) or {}
    memo = {t: "(earlier run)" for t in _index_types(prev)}  # types already expanded: not expanded again
    result = {"generated": time.strftime("%Y-%m-%d %H:%M:%S"), "endpoint": simba.GQL, "words": len(names),
              "types_tried": tnames, "roots": prev.get("roots", {}), "item_lookups": prev.get("item_lookups"),
              "error_samples": prev.get("error_samples", [])}
    err(f"crawl: {len(names)} candidate names, {len(tnames)} candidate types, batch {batch}, depth {depth}")
    per_node = -(-len(names) // batch) + -(-len(names) // batch) // 2 + -(-len(tnames) // batch)
    err(f"crawl: roots {', '.join(wanted)}. Per object node: about {per_node} to {2 * per_node} requests "
        f"(names bare, then rejected ones as objects, then {len(tnames)} type probes); the number of nodes is "
        "found while crawling, so the status line shows a lower bound for the time left.")

    def save():
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=1, ensure_ascii=False)
            fh.write("\n")

    for name in wanted:
        t0 = time.time()
        try:
            if name == "item-lookups":
                found = {}
                total_req = 0
                lookup_names = sorted({n for n in names if "item" in n.lower()})
                for form, decl, call, vars_ in LOOKUP_FORMS:
                    p = Prober(simba, f"item-lookups/{form}", decl, "{ item { %s } }" % MARK, vars_, batch)
                    err(f"crawl item-lookups/{form}: calibrating, then {len(lookup_names)} names")
                    p.calibrate()
                    snippets = [n + call + " { __typename }" for n in lookup_names]
                    rej = p.run("", "", snippets)
                    found[form] = [n for i, n in enumerate(lookup_names) if i not in rej]
                    total_req += p.requests
                    result["error_samples"] = sorted(set(result["error_samples"]) | set(p.samples))[:30]
                result["item_lookups"] = found
                err(f"crawl item-lookups: {found}  ({total_req} requests, {time.time() - t0:.0f}s)")
            elif name in specs:
                decl, template, variables = specs[name]
                p = Prober(simba, name, decl, template, variables, batch)
                err(f"crawl {name}: calibrating (does the server reject unknown fields, where do errors point)")
                p.calibrate()
                err(f"crawl {name}: crawling")
                result["roots"][name] = p.node("", "", names, tnames, 0, depth, memo, [name],
                                               skip=ROOT_OWN.get(name, frozenset()))
                result["error_samples"] = sorted(set(result["error_samples"]) | set(p.samples))[:30]
                r = result["roots"][name]
                STATUS.done()
                if p.reuse:
                    err(f"crawl {name}: {p.reused} sub-objects reused (parent.field key, verified), "
                        f"{p.rejected_reuse} reuse attempts rejected by the verification (REUSE=1)")
                err(f"crawl {name}: {len(r['leaf'])} leaf, {len(r['object'])} object, {len(r['unknown'])} unknown, "
                    f"types {r['types']}  ({p.requests} requests, {time.time() - t0:.0f}s)")
            else:
                err(f"crawl: unknown root {name!r} (roots: {', '.join(list(specs) + ['item-lookups'])})")
        except RootError as e:
            STATUS.done()
            err(f"crawl {name}: {e}")
        save()
    err(f"crawl: wrote {out_path}")


def audit(probed_path, only=()):
    """Live: re-verify every crawled object node (does the server accept every field the node lists, at that path?)
    and re-crawl, without reuse, the ones that fail. Fixes results of a REUSE=1 crawl made before reuse was
    verified. A node that has fewer fields than the real one is not detected (only rejected fields are)."""
    simba = _simba()
    probed = load_json(probed_path)
    if probed is None:
        sys.exit(f"{probed_path}: not found (run crawl first)")
    if not os.path.isfile(simba.CERT):
        sys.exit(f"client certificate not found: {simba.CERT} (set CERT=/path/to/file.pem)")
    names, tnames = gather_candidates(simba)
    batch, depth_max = int(env("BATCH", "100")), int(env("DEPTH", "5"))
    specs = root_specs(simba)
    wanted = [r for r in probed.get("roots", {}) if r in specs and (not only or r in only)]
    memo = {t: "(earlier run)" for t in _index_types(probed)}
    for rname in wanted:
        decl, template, variables = specs[rname]
        p = Prober(simba, rname, decl, template, variables, batch)
        p.reuse = False
        t0 = time.time()
        try:
            p.calibrate()
        except RootError as e:
            err(f"audit {rname}: {e}")
            continue
        bad, checked, skipped = [], [0], []

        def walk(node, before, after, path, depth):
            kids = [(f, sub, f + SEEDED_CALLS.get(f, "") + " { ", False, depth + 1)
                    for f, sub in sorted((node.get("object") or {}).items())]
            kids += [(t, sub, f"... on {t} {{ ", True, depth) for t, sub in sorted((node.get("on") or {}).items())]
            for key, sub, open_, is_type, d in kids:
                if not isinstance(sub, dict) or sub.get("truncated") or "see" in sub:
                    continue
                b, a = before + open_, " } " + after
                snips = node_snippets(sub)
                p.where = ".".join(path + [key])
                p.status()
                checked[0] += 1
                try:
                    rejected = bool(snips) and bool(p.run(b, a, snips))
                except RootError as e:
                    err(f"  audit {'.'.join(path + [key])}: cannot verify ({e})")
                    skipped.append(".".join(path + [key]))
                    rejected = False
                if rejected:
                    bad.append((node, key, is_type, b, a, path + [key if not is_type else f"[{key}]"], d))
                    continue  # re-crawled below, with everything under it
                walk(sub, b, a, path + [key if not is_type else f"[{key}]"], d)

        walk(probed["roots"][rname], "", "", [rname], 0)
        STATUS.done()
        err(f"audit {rname}: {checked[0]} nodes checked, {len(bad)} wrong, {len(skipped)} not verifiable "
            f"({p.requests} requests, {time.time() - t0:.0f}s)")
        for parent, key, is_type, b, a, path, d in bad:
            err(f"  re-crawling {'.'.join(path)}")
            new = p.node(b, a, names, tnames, d, depth_max, memo, path, in_type=is_type)
            (parent["on"] if is_type else parent["object"])[key] = new
        with open(probed_path, "w", encoding="utf-8") as fh:
            json.dump(probed, fh, indent=1, ensure_ascii=False)
            fh.write("\n")
    err(f"audit: wrote {probed_path}")


# ---------------------------------------------------------------- check simba.py against the maps

OBS_TYPE = {"applicationItem": "ApplicationItem", "demoItem": "DemoItem", "dlcItem": "DlcItem",
            "bundleItem": "BundleItem"}
FIELD_ROOT = {"applicationItem": "application", "demoItem": "demo", "dlcItem": "dlc", "bundleItem": "bundle"}


def _crawl_top(probed):
    roots = (probed or {}).get("roots", {})
    lookups = (probed or {}).get("item_lookups") or {}
    opaque = {"leaf": [], "object": {}, "unknown": [], "types": [], "on": {}, "opaque": True}
    item = {"leaf": [], "unknown": [], "types": [], "on": {}, "object": {}}
    for field, root in FIELD_ROOT.items():
        if root in roots:
            item["object"][field] = roots[root]
    for names in lookups.values():
        for n in names:
            item["object"].setdefault(n, opaque)
    top = {"leaf": [], "unknown": [], "types": [], "on": {}, "object": {"item": item}}
    for k in ("country", "searchV4"):
        if k in roots:
            top["object"][k] = roots[k]
    return top, roots


def _resolve(node, types_ref):
    if isinstance(node, dict) and "see" in node:
        return types_ref.get(node["see"])
    return node


def _index_types(probed):
    """type name -> crawled node (the first place each `... on T` was expanded)."""
    idx = {}

    def walk(n):
        if not isinstance(n, dict):
            return
        for t, sub in (n.get("on") or {}).items():
            if isinstance(sub, dict) and "see" not in sub:
                idx.setdefault(t, sub)
        for sub in list((n.get("object") or {}).values()) + list((n.get("on") or {}).values()):
            walk(sub)
    roots = (probed or {}).get("roots", {})
    for r in roots.values():
        walk(r)
    for t, rname in CONCRETE_ROOT.items():  # a concrete type's root node is its full field list
        if rname in roots:
            idx[t] = roots[rname]
    return idx


def _crawl_lookup(node, name, ftype, idx):
    if not isinstance(node, dict):
        return None, None
    if node.get("opaque") or node.get("truncated"):
        return "opaque", None
    cands = []
    if ftype and isinstance(node.get("on"), dict) and ftype in node["on"]:
        sub = _resolve(node["on"][ftype], idx)
        if isinstance(sub, dict):
            cands.append(sub)
    cands.append(node)
    unknown = False
    for c in cands:
        if name in (c.get("leaf") or []):
            return "leaf", None
        if name in (c.get("object") or {}):
            return "object", c["object"][name]
        if name in (c.get("unknown") or []):
            unknown = True
    return ("unknown" if unknown else None), None


def check(observed_path, probed_path):
    simba = _simba()
    observed = load_observed(observed_path)
    probed = load_json(probed_path)
    if observed is None and probed is None:
        sys.exit(f"neither {observed_path} nor {probed_path} exists (run mine and/or crawl first)")
    idx = _index_types(probed)
    top, roots = _crawl_top(probed)
    otree = (observed or {}).get("tree", {}).get("query")
    rows, used = [], {}
    counts = {}

    def status(cs, ent):
        if cs in ("leaf", "object"):
            return "ok" if ent else "ok (crawl only)"
        if cs == "opaque":
            return "~ (lookup result or beyond the crawl depth, not crawled)"
        if ent:  # selected by a query of the web client: valid by definition
            return "ok (web client)" if cs is None else "ok (web client; crawl: unknown or needs args)"
        if cs == "unknown":
            return "REJECTED by crawl, not in web client"
        return "unconfirmed (not in the web client's queries, no crawl result)"

    otypes = (observed or {}).get("types", {})

    def cowalk(qname, sel, cnode, onode, ftype, path, otype=None):
        for f in sel["fields"]:
            cs, cchild = _crawl_lookup(cnode, f["name"], ftype, idx)
            ent = (onode or {}).get("fields", {}).get(f["name"]) if onode else None
            if ent is None and (ftype or otype):  # the web client selects it on this type somewhere else
                ent = (otypes.get(ftype or otype) or {}).get("fields", {}).get(f["name"])
            st = status(cs, ent) if (cnode is not None or onode is not None or ent) else status(cs, None)
            rows.append((qname, ".".join(path + [f["name"]]) + (f"  [on {ftype}]" if ftype else ""), st))
            counts[st] = counts.get(st, 0) + 1
            if cs in ("leaf", "object") and cnode is not None:
                used.setdefault(id(cnode), set()).add(f["name"])
            if f["sel"] is not None:
                nxt_c = cchild
                if f["name"] in FIELD_ROOT and FIELD_ROOT[f["name"]] in roots and path[-1:] == ["item"]:
                    nxt_c = roots[FIELD_ROOT[f["name"]]]
                nxt_o = ent.get("children") if ent else None
                nxt_t = OBS_TYPE.get(f["name"]) if path[-1:] == ["item"] else None
                cowalk(qname, f["sel"], nxt_c, nxt_o, None, path + [f["name"]], nxt_t)
        for fr in sel["frags"]:
            t = fr["type"]
            nxt_c = cnode
            if t in CONCRETE_ROOT and CONCRETE_ROOT[t] in roots:
                nxt_c = roots[CONCRETE_ROOT[t]]
            cowalk(qname, fr["sel"], nxt_c, onode, t, path, otype)

    for qname, text in simba_queries(simba).items():
        ops, _ = parse_gql(text)
        for op in ops:
            cowalk(qname, op["sel"], top if probed else None, otree, None, [])

    lines = ["# simba.py requests vs the schema maps", "",
             f"observed: {observed_path} {'(missing)' if observed is None else ''}  probed: {probed_path} "
             f"{'(missing)' if probed is None else ''}", "", "## Summary", ""]
    for k, v in sorted(counts.items(), key=lambda kv: -kv[1]):
        lines.append(f"- {k}: {v}")
    lines += ["", "## Fields to look at (not `ok`)", ""]
    seen = set()
    for q, p, st in rows:
        if not st.startswith("ok") and (p, st) not in seen:
            seen.add((p, st))
            lines.append(f"- {p}  -> {st}   (query {q})")
    lines += ["", "## Fields the maps know that simba.py does not request", ""]
    for rname, rnode in roots.items():
        known = sorted(set(rnode.get("leaf", [])) | set(rnode.get("object", {})))
        req = used.get(id(rnode), set())
        spare = [k for k in known if k not in req and k != "__typename"]
        lines.append(f"### {rname}  (types: {', '.join(rnode.get('types', [])) or '-'})")
        lines.append("")
        lines.append("- leaf/object fields: " + (", ".join(spare) if spare else "(all requested)"))
        lines.append("")
    lines += ["", "## Every field simba.py requests", ""]
    for q, p, st in rows:
        lines.append(f"- [{st}] {p}  ({q})")
    with open(CHECKED, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print("\n".join(lines[:lines.index("## Fields the maps know that simba.py does not request")]))
    err(f"check: wrote {CHECKED}")


def show(names):
    observed = load_observed(OBSERVED)
    probed = load_json(PROBED)
    for name in names:
        print(f"== {name}")
        if observed and name in observed.get("types", {}):
            lines = []
            _md_node(observed["types"][name], 0, lines)
            print("client (fields selected under `... on " + name + "`):")
            print("\n".join("  " + x for x in lines))
        if probed:
            if name in probed.get("roots", {}):
                r = probed["roots"][name]
                print(f"crawl root: leaf {r['leaf']}\n  object {sorted(r['object'])}\n  unknown {r['unknown']}"
                      f"\n  types {r['types']}")
            idx = _index_types(probed)
            if name in idx:
                r = idx[name]
                print(f"crawl `... on {name}`: leaf {r['leaf']}\n  object {sorted(r['object'])}")


def main(argv):
    cmd = argv[0] if argv else ""
    a = argv[1:]
    if cmd == "mine":
        mine(a[0] if a else "recon_out", a[1] if len(a) > 1 else OBSERVED)
    elif cmd == "crawl":
        crawl(a[0] if a else PROBED, a[1:])
    elif cmd == "audit":
        audit(a[0] if a else PROBED, a[1:])
    elif cmd == "check":
        check(a[0] if a else OBSERVED, a[1] if len(a) > 1 else PROBED)
    elif cmd == "show" and a:
        show(a)
    else:
        with open(__file__, encoding="utf-8") as fh:
            head = []
            for line in fh.read().split("\n")[1:]:
                if not line.startswith("#"):
                    break
                head.append(line[2:])
        print("\n".join(head), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        sys.exit(130)
