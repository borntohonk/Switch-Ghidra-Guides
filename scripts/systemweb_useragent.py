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

"""Reconstruct the systemWeb (0100000000001042) browser User-Agent.

The UA constructor builds the string from these pieces:

    "Mozilla/5.0 "
    "(Nintendo Switch; %s"            <- per-applet token (config+0x18)
    "; %s"                            <- "Nintendo Switch" / "Nintendo Switch Lite",
                                         only for applet kinds in a bitmask
    ") "
    "AppleWebKit/%s (KHTML, like Gecko) "
    "NF/%d.%d.%s "
    "NintendoBrowser/%d.%d.%d.%s"     <- %s = "revision:" from romfs buildinfo.dat
    [" " + extra]                     <- optional runtime string, not in the binary

The constructor is located through its "NintendoBrowser/%d.%d.%d.%s" xref and
walked linearly with a small register tracker (adrp/add/mov/csel/bl), so the
literals and integer arguments are read from the binary rather than hardcoded.
"""

import argparse
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import nxo64

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except ImportError:
    print('Please install capstone first!')
    sys.exit(1)

BASE = 0x7100000000
NSO_HEADER_FLAGS = 0xC
NSO_SEGMENTS = 0x10
NSO_BSS_SIZE = 0x3C
NSO_COMPRESSED_SIZES = 0x60
NSO_FLAG_ZBIC = 0x80

ANCHOR_FMT = b'NintendoBrowser/%d.%d.%d.%s\x00'
TRAP = 0xE7FFDEFE  # padding between functions
# ubfx x17, x30, #0, #0x28 -- first instruction of every return-address-protected function
PROLOGUE = 0xD3409FD1


def load_nso(path):
    """Map an NSO0 (compressed or not) into a flat image based at offset 0."""
    raw = Path(path).read_bytes()
    if raw[:4] != b'NSO0':
        raise ValueError(f'{path}: not an NSO0')
    flags = struct.unpack_from('<I', raw, NSO_HEADER_FLAGS)[0]
    csizes = struct.unpack_from('<III', raw, NSO_COMPRESSED_SIZES)
    img = bytearray()
    segs = []
    for i in range(3):
        off, loc, size, _ = struct.unpack_from('<IIII', raw, NSO_SEGMENTS + i * 0x10)
        data = raw[off:off + (csizes[i] or size)]
        if flags & (1 << i) and csizes[i]:
            data = nxo64.decompress_segment(data, size, bool(flags & NSO_FLAG_ZBIC))
        if len(img) < loc + size:
            img += b'\0' * (loc + size - len(img))
        img[loc:loc + size] = data[:size].ljust(size, b'\0')
        segs.append((loc, size))
    img += b'\0' * struct.unpack_from('<I', raw, NSO_BSS_SIZE)[0]
    return bytes(img), segs


class Image:
    def __init__(self, path):
        self.data, self.segs = load_nso(path)
        self.text = self.segs[0]

    def cstr(self, addr):
        off = addr - BASE
        if not 0 <= off < len(self.data):
            return None
        end = self.data.find(b'\0', off)
        s = self.data[off:end]
        if end < 0 or len(s) > 0x200 or any(c < 0x20 or c > 0x7E for c in s):
            return None
        return s.decode('ascii')

    def adrp_add_xrefs(self, target):
        """Yield addresses of `adrp xN, page; add xM, xN, #lo` pairs that resolve to target."""
        tloc, tsize = self.text
        page, lo = target & ~0xFFF, target & 0xFFF
        for off in range(tloc, tloc + tsize - 4, 4):
            w = struct.unpack_from('<I', self.data, off)[0]
            if w & 0x9F000000 != 0x90000000:
                continue
            imm = (((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3)
            if imm & (1 << 20):
                imm -= 1 << 21
            pc = BASE + off
            if (pc & ~0xFFF) + (imm << 12) != page:
                continue
            rd = w & 0x1F
            # add xD, xN, #imm12 (64-bit, no shift)
            for nxt in (off + 4, off + 8):
                w2 = struct.unpack_from('<I', self.data, nxt)[0]
                if (w2 & 0xFFC00000 == 0x91000000 and (w2 >> 5) & 0x1F == rd
                        and (w2 >> 10) & 0xFFF == lo):
                    yield pc
                    break

    def word(self, addr):
        return struct.unpack_from('<I', self.data, addr - BASE)[0]

    def function_start(self, addr):
        """Walk back to the prologue that follows the previous function's trap/ret."""
        a = addr
        while a > BASE + self.text[0]:
            if self.word(a) == PROLOGUE and self.word(a - 4) in (TRAP, 0xD65F03C0, 0xD503201F):
                return a
            a -= 4
        raise ValueError('function start not found')


def find_constructor(img):
    off = img.data.find(ANCHOR_FMT)
    if off < 0:
        raise ValueError('NintendoBrowser format string not found')
    refs = list(img.adrp_add_xrefs(BASE + off))
    if len(refs) != 1:
        raise ValueError(f'expected one xref to NintendoBrowser fmt, got {len(refs)}')
    return img.function_start(refs[0])


def reg_name(op):
    op = op.strip()
    if op in ('sp', 'wsp'):
        return 'sp'
    if op in ('xzr', 'wzr'):
        return 'zr'
    m = re.fullmatch(r'[xw](\d+)', op)
    return f'x{m.group(1)}' if m else None


def walk_constructor(img, start):
    """Linear walk of the constructor; returns a list of emitted pieces.

    Register values are tuples: ('imm', n), ('addr', a), ('ret', target, call_pc),
    ('sel', cond_value, eq_addr, ne_addr), ('sp',) or None (unknown).
    """
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    regs = {'sp': ('sp',), 'zr': ('imm', 0)}
    pieces = []
    cond = []           # open forward branches: (target, info)
    last_cmp = {}       # reg -> compared immediate
    gate = {}           # info about the applet-kind bitmask gate

    code = img.data[start - BASE:start - BASE + 0x1000]
    for ins in md.disasm(code, start):
        cond = [c for c in cond if c[0] > ins.address]
        m, ops = ins.mnemonic, [o.strip() for o in ins.op_str.split(',')]
        rd = reg_name(ops[0]) if ops and ops[0] else None

        if m == 'ret':
            break
        if m == 'adrp':
            regs[rd] = ('addr', int(ops[1].lstrip('#'), 16))
        elif m == 'add' and len(ops) == 3 and ops[2].startswith('#'):
            src = regs.get(reg_name(ops[1]))
            imm = int(ops[2].lstrip('#'), 16)
            if src and src[0] == 'addr':
                regs[rd] = ('addr', src[1] + imm)
            elif src and src[0] == 'ret':
                regs[rd] = ('field', src[1], imm)
            else:
                regs[rd] = None
        elif m == 'mov' and len(ops) == 2:
            if ops[1].startswith('#'):
                regs[rd] = ('imm', int(ops[1].lstrip('#'), 0))
            else:
                regs[rd] = regs.get(reg_name(ops[1]))
        elif m == 'cmp' and ops[1].startswith('#'):
            last_cmp[reg_name(ops[0])] = int(ops[1].lstrip('#'), 0)
            last_cmp['_last'] = int(ops[1].lstrip('#'), 0)
        elif m == 'tst':
            mask = regs.get(reg_name(ops[1]))
            if mask and mask[0] == 'imm':
                gate['mask'] = mask[1]
        elif m == 'csel' and ops[3] == 'eq':
            regs[rd] = ('sel', last_cmp.get('_last'),
                        (regs.get(reg_name(ops[1])) or (None, None))[1],
                        (regs.get(reg_name(ops[2])) or (None, None))[1])
        elif m.startswith('b.') or m in ('cbz', 'cbnz', 'tbz', 'tbnz'):
            target = int(ops[-1].lstrip('#'), 16)
            if target > ins.address:
                if m == 'b.hi':
                    gate.setdefault('max', last_cmp.get('_last'))
                cond.append((target, m))
        elif m == 'bl':
            target = int(ops[0].lstrip('#'), 16)
            piece = classify_call(img, regs)
            if piece:
                piece['conditional'] = bool(cond)
                pieces.append(piece)
            for i in range(19):
                regs[f'x{i}'] = None
            regs['x0'] = ('ret', target, ins.address)
        elif rd and rd not in ('sp', 'zr') and m not in ('str', 'stp', 'stur', 'strb', 'sturh'):
            regs[rd] = None
    return pieces, gate


def classify_call(img, regs):
    def s(r):
        v = regs.get(r)
        return img.cstr(v[1]) if v and v[0] == 'addr' else None

    fmt = s('x1')
    if fmt is not None and '%' in fmt:
        args = []
        for r in ('x2', 'x3', 'x4', 'x5', 'x6', 'x7'):
            args.append(regs.get(r))
        return {'kind': 'fmt', 'fmt': fmt, 'args': args}
    if fmt is not None:
        return {'kind': 'lit', 'text': fmt}
    lit = s('x2')
    if lit is not None:
        # strlcpy(buf, size, "literal")
        return {'kind': 'lit', 'text': lit}
    x1 = regs.get('x1')
    if x1 and x1[0] == 'field':
        return {'kind': 'extra', 'field': x1[2]}
    return None


# Names for %s arguments that are only known at runtime, keyed by format string.
RUNTIME_SLOTS = (
    (re.compile(r'Nintendo Switch; %s'), 'applet'),   # config+0x18, set per applet kind
    (re.compile(r'^; %s'), 'model'),                  # csel on product model
    (re.compile(r'^NintendoBrowser/'), 'revision'),   # buildinfo.dat "revision:" singleton
)


def render_fmt(img, piece):
    """Apply printf-style formatting; non-constant %s args become {placeholders}."""
    args = iter(piece['args'])
    slot = next((name for rx, name in RUNTIME_SLOTS if rx.search(piece['fmt'])), '?')

    def repl(mo):
        spec = mo.group(1)
        v = next(args)
        if spec == 'd':
            return str(v[1]) if v and v[0] == 'imm' else '{?}'
        if v and v[0] == 'addr' and img.cstr(v[1]) is not None:
            return img.cstr(v[1])
        return '{' + slot + '}'

    return re.sub(r'%([ds])', repl, piece['fmt'])


def scan_applet_tokens(img):
    """Find `if (cfg->kind == K) copy(cfg->ua_token /* +0x18 */, "Token")`.

    22.x: add x0, cfg, #0x18; adrp/add x1, "Token"; bl assign
    23.x: ldr x0, [cfg, #0x18]; ldrsw x1, [cfg, #0x20]; adrp/add x2, "Token"; bl strlcpy
    """
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.skipdata = True
    tloc, tsize = img.text
    tokens = {}
    for off in range(tloc, tloc + tsize - 8, 4):
        # ldr w8, [xN, #8]
        if struct.unpack_from('<I', img.data, off)[0] & 0xFFFFFC1F != 0xB9400808:
            continue
        win = list(md.disasm(img.data[off:off + 0x140], BASE + off))
        if len(win) < 3 or win[1].mnemonic != 'cmp' or not re.fullmatch(r'w8, #\w+', win[1].op_str):
            continue
        if win[2].mnemonic != 'b.ne':
            continue
        cfg = win[0].op_str.split('[')[1].split(',')[0]
        kind = int(win[1].op_str.split('#')[1], 0)
        alias = {cfg}
        page, regs = {}, {}
        for i in win[3:]:
            ops = [o.strip() for o in i.op_str.split(',')]
            if i.mnemonic == 'mov' and len(ops) == 2 and ops[1] in alias:
                alias.add(ops[0])
            elif i.mnemonic == 'adrp':
                page[ops[0]] = int(ops[1].lstrip('#'), 16)
            elif i.mnemonic == 'add' and ops[1] in page and ops[2].startswith('#'):
                regs[ops[0]] = img.cstr(page[ops[1]] + int(ops[2].lstrip('#'), 16))
            elif i.mnemonic == 'add' and ops[1] in alias and ops[2] == '#0x18':
                regs[ops[0]] = 'TOKEN_DST'
            elif i.mnemonic == 'ldr' and re.fullmatch(r'\[(x\d+), #0x18\]', ', '.join(ops[1:])) \
                    and ops[1].lstrip('[') in alias:
                regs[ops[0]] = 'TOKEN_DST'
            elif i.mnemonic == 'bl':
                if regs.get('x0') == 'TOKEN_DST':
                    tok = regs.get('x1') or regs.get('x2')
                    if tok and tok != 'TOKEN_DST':
                        tokens[kind] = tok
                    break
                regs.clear()
            elif i.mnemonic in ('ret', 'b') or i.bytes == TRAP.to_bytes(4, 'little'):
                break
    return dict(sorted(tokens.items()))


def parse_buildinfo(data):
    """Parse buildinfo.dat ("key:value" per line) from bytes or str."""
    if isinstance(data, (bytes, bytearray)):
        data = data.decode('utf-8', errors='replace')
    info = {}
    for line in data.splitlines():
        k, sep, v = line.partition(':')
        if sep:
            info[k.strip()] = v.strip()
    return info


def describe(nso_path, buildinfo=None, revision=None, verbose=False):
    """Return report lines: the UA template, its runtime slots and one UA per applet kind.

    buildinfo: raw romfs:/buildinfo/buildinfo.dat bytes/str for the same firmware.
    revision:  overrides buildinfo's "revision:".
    """
    img = Image(nso_path)
    start = find_constructor(img)
    pieces, gate = walk_constructor(img, start)
    lines = []

    template = ''
    model_choices = None
    extra_field = None
    for p in pieces:
        if p['kind'] == 'lit':
            text = p['text']
        elif p['kind'] == 'fmt':
            text = render_fmt(img, p)
            sel = next((a for a in p['args'] if a and a[0] == 'sel'), None)
            if sel:
                model_choices = (sel[1], img.cstr(sel[2]), img.cstr(sel[3]))
        else:
            extra_field = p['field']
            if template.endswith('[ ]'):
                template = template[:-3]
            text = ' {extra}'
        if p['conditional']:
            text = '[' + text + ']'
        template += text
        if verbose:
            lines.append(f'  {p["kind"]:5} {"cond " if p["conditional"] else "     "}{text!r}')

    info = parse_buildinfo(buildinfo) if buildinfo else {}
    revision = revision or info.get('revision')

    lines.append(f'constructor : {start:#x}')
    lines.append(f'template    : {template}')
    mask = gate.get('mask')
    if mask is not None:
        kinds = [k for k in range(32) if mask >> k & 1]
        lines.append(f'[; {{model}}] : only when applet kind in {kinds} (mask {mask:#x})')
    if model_choices:
        val, eq, ne = model_choices
        lines.append(f'{{model}}     : "{eq}" if product model == {val} else "{ne}"')
    if extra_field is not None:
        lines.append(f'{{extra}}     : optional runtime string (config+{extra_field:#x}), appended after a space')
    lines.append(f'{{revision}}  : {revision or "(unknown: pass --buildinfo or --revision; runtime default is 0)"}')

    nf = re.search(r'NF/\d+\.\d+\.(\S+)', template)
    if nf and info.get('netfront_3') and info['netfront_3'] != nf.group(1):
        lines.append(f'warning: buildinfo netfront_3={info["netfront_3"]} does not match NF/{nf.group(1)} '
                     '(buildinfo may be from another version)')

    tokens = scan_applet_tokens(img)
    lines.append('')
    for kind, tok in tokens.items():
        base = template.replace('{applet}', tok).replace('[ {extra}]', '')
        if revision:
            base = base.replace('{revision}', revision)
        if '[; {model}]' in base:
            if mask is not None and mask >> kind & 1 and model_choices:
                variants = [base.replace('[; {model}]', '; ' + m) for m in (model_choices[2], model_choices[1])]
            else:
                variants = [base.replace('[; {model}]', '')]
        else:
            variants = [base]
        for v in variants:
            lines.append(f'kind {kind}: {v.replace("[", "").replace("]", "")}')
    return lines


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('nso', help='systemWeb main NSO0, e.g. output/23.0.1/23.0.1_systemWeb.nso0')
    ap.add_argument('--buildinfo', help='romfs:/buildinfo/buildinfo.dat for the same version '
                                        '(process_firmware.py writes output/<ver>/<ver>_systemWeb_buildinfo.dat)')
    ap.add_argument('--revision', help='override revision (otherwise read from --buildinfo)')
    ap.add_argument('-v', '--verbose', action='store_true', help='print decoded pieces')
    args = ap.parse_args()

    buildinfo = Path(args.buildinfo).read_bytes() if args.buildinfo else None
    print('\n'.join(describe(args.nso, buildinfo, args.revision, args.verbose)))


if __name__ == '__main__':
    main()
