"""Show how Avadon 2.exe joins message pieces, with the Japanese of each piece.

usage:
    python -I a2_msgjoin.py "Avadon 2.exe" EXE_STRINGS_TSV OUT_TXT

The message routines 0x4874a0 / 0x4874d0 (and the floating-text joiner 0x4455b0) take
(a1, a2, a3, a4, number, a6, ...): the text is a1 a2 a3 a4 [number] a6 (the number is left
out when it is -1). Arguments are the pushes right before the call (the exe is not
optimised). Each call is printed with the English and the Japanese assembly, where
non-literal arguments are shown as [名前] (strings) or [数値].
"""
import re
import sys

import capstone
import pefile

TARGETS = {0x4874a0: 'message', 0x4874d0: 'message', 0x4455b0: 'float'}


def main(argv):
    exe, tsv, out = argv
    pe = pefile.PE(exe)
    base = pe.OPTIONAL_HEADER.ImageBase
    img = pe.get_memory_mapped_image()
    t = pe.sections[0]
    t0 = base + t.VirtualAddress
    code = img[t.VirtualAddress:t.VirtualAddress + t.Misc_VirtualSize]
    en, ja = {}, {}
    for l in open(tsv, encoding='utf-8').read().split('\n')[1:]:
        c = l.split('\t')
        if len(c) == 5:
            en[int(c[0], 16)] = c[3]
            ja[int(c[0], 16)] = c[4] or c[3]

    def lit(v, table):
        if v in table:
            return table[v]
        o = v - base
        if 0 <= o < len(img):
            e = img.find(b'\0', o, o + 300)
            if e == o:
                return ''
            if e > o:
                try:
                    return img[o:e].decode('ascii')
                except UnicodeDecodeError:
                    pass
        return None

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    lines = []
    for i in range(len(code) - 5):
        if code[i] != 0xE8:
            continue
        tgt = t0 + i + 5 + int.from_bytes(code[i + 1:i + 5], 'little', signed=True)
        if tgt not in TARGETS:
            continue
        best = None
        for s in range(max(0, i - 160), i):
            ins = list(md.disasm(code[s:i], t0 + s))
            if ins and ins[-1].address + ins[-1].size == t0 + i:
                best = ins
                break
        if not best:
            continue
        pushes = [x for x in reversed(best) if x.mnemonic == 'push'][:6]
        if len(pushes) < 6:
            continue
        parts_en, parts_ja, lits = [], [], 0
        for k, p in enumerate(pushes):
            if k == 4:  # number
                if p.op_str in ('-1', '0xffffffff'):
                    continue
                parts_en.append('[N]' if not p.op_str.startswith('0x') else p.op_str)
                parts_ja.append('[数値]')
                continue
            v = int(p.op_str, 16) if p.op_str.startswith('0x') else None
            e = lit(v, en) if v is not None else None
            if e is None:
                parts_en.append('[X]')
                parts_ja.append('[名前]')
            else:
                if e:
                    lits += 1
                parts_en.append(e)
                parts_ja.append(lit(v, ja))
        if lits >= 1 and any(x in ('[X]', '[N]') for x in parts_en):
            lines.append('%06x %-7s EN: %s\n               JA: %s' % (
                t0 + i, TARGETS[tgt], ''.join(parts_en), ''.join(parts_ja)))
    open(out, 'w', encoding='utf-8').write('\n'.join(lines) + '\n')
    print(len(lines), 'joined messages')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
