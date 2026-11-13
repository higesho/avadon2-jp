"""How exe strings are joined into messages in Avadon 2.exe (for the translators' "usage").

usage:
    python -I a2_fragctx.py "Avadon 2.exe" EXE_STRINGS_TSV OUT_JSON

Avadon 2.exe is built without optimisation, so the arguments of a sprintf call are the
pushes right before it: buf, fmt, arg1..argN. For formats made only of %s/%d pieces
(e.g. "%s%s%d%s"), the pieces that are string literals are named in the assembly, the
other arguments become [名前など] (%s) or [数値] (%d).
Writes {va: ["'You find ' + [名前など] + '.'", ...]} for every literal piece.
"""
import json
import re
import sys

import capstone
import pefile

SPRINTF = 0x4c44b5


def main(argv):
    exe, tsv, out = argv
    pe = pefile.PE(exe)
    base = pe.OPTIONAL_HEADER.ImageBase
    img = pe.get_memory_mapped_image()
    text = pe.sections[0]
    t0 = base + text.VirtualAddress
    code = img[text.VirtualAddress:text.VirtualAddress + text.Misc_VirtualSize]
    rows = {int(l.split('\t')[0], 16): l.split('\t')[3] for l in open(tsv, encoding='utf-8').read().split('\n')[1:] if l.strip()}
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    def cstr(va):
        o = va - base
        if not (0 <= o < len(img)):
            return None
        e = img.find(b'\0', o, o + 600)
        try:
            return img[o:e].decode('ascii') if e > o else None
        except UnicodeDecodeError:
            return None

    ctx = {}
    for i in range(len(code) - 5):
        if code[i] != 0xE8 or t0 + i + 5 + int.from_bytes(code[i + 1:i + 5], 'little', signed=True) != SPRINTF:
            continue
        # decode the 80 bytes before the call and keep the instruction chain that ends at it
        start = max(0, i - 120)
        best = None
        for s in range(start, i):
            ins = list(md.disasm(code[s:i], t0 + s))
            if ins and ins[-1].address + ins[-1].size == t0 + i:
                best = ins
                break
        if not best:
            continue
        pushes = [x for x in reversed(best) if x.mnemonic == 'push']
        if len(pushes) < 2 or not pushes[1].op_str.startswith('0x'):
            continue
        fmt = cstr(int(pushes[1].op_str, 16))
        if not fmt or not re.fullmatch(r'(?:%[sd]|[^%])*', fmt) or fmt.count('%') < 2:
            continue
        specs = re.findall(r'%[sd]', fmt)
        args = pushes[2:2 + len(specs)]
        if len(args) != len(specs):
            continue
        parts, lits = [], []
        pos = 0
        for m, a, sp in zip(re.finditer(r'%[sd]', fmt), args, specs):
            if m.start() > pos:
                parts.append(repr(fmt[pos:m.start()]))
            pos = m.end()
            v = int(a.op_str, 16) if a.op_str.startswith('0x') else None
            if v is not None and v in rows:
                parts.append(repr(rows[v]))
                lits.append(v)
            else:
                parts.append('[名前など]' if sp == '%s' else '[数値]')
        if pos < len(fmt):
            parts.append(repr(fmt[pos:]))
        desc = ' + '.join(parts)
        for v in lits:
            ctx.setdefault('0x%06x' % v, [])
            if desc not in ctx['0x%06x' % v]:
                ctx['0x%06x' % v].append(desc)
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(ctx, f, ensure_ascii=False, indent=0)
    print(len(ctx), 'strings with usage')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
