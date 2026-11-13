"""List the English UI strings that Avadon.exe code refers to, as exe_strings.tsv.

usage:
    python -I exe_extract.py Avadon.exe OUT_TSV [--targets]

A string is a NUL-terminated printable run in .rdata/.data that is referenced by a
relocated 4-byte immediate in .text (push imm32 / mov r, imm32 / mov [m], imm32).
For each reference the next call (within 14 instructions) is recorded; its target is
mapped to a "sink" name (how the string is used) by SINKS below. --targets prints the
most common unnamed call targets, to extend SINKS.
Columns: va, sink, refs, english, japanese (empty).
"""
import collections
import re
import sys

import capstone
import pefile

sys.stdout.reconfigure(encoding='utf-8')

SINKS = {
    0x4c44b5: 'sprintf',
    0x487760: 'draw',
    0x487fd0: 'draw',
    0x488330: 'draw',
    0x4454c0: 'float',        # floating text over a character (<= 39 bytes, checked at 0x445509)
    0x4455b0: 'float_part',
    0x4874a0: 'message',
    0x4874d0: 'message',
    0x487200: 'message',
    0x487030: 'message',
    0x4871e0: 'message',
    0x488a00: 'message',
    0x4023b0: 'message',
    0x460f70: 'message',
    0x4870b0: 'codex',
    0x48b540: 'tooltip',
    0x48b5f0: 'label_part',
    0x42a620: 'loading',
    0x42f5e0: 'label',
    0x4133d0: 'label',
    0x48c690: 'internal',     # alert stubs: nothing is shown in this build
    0x48c6d0: 'internal',
    0x48aee0: 'internal',
    0x4c5029: 'internal',     # Steam stats debug output
    0x4c49a2: 'internal',     # fopen modes
}
# developer error / debug texts: never shown in normal play, left in English
INTERNAL_RE = re.compile(r'DEBUG|called prematurely|NULL |nonexist|Report this message|^Error[: ]|^ERROR|'
                         r'script failure|Tried to |given to ability engine|out of range|Couldn.t (find|load) (graphic|pict)|'
                         r'Avadon 2 Files|Steam|^ACH_|\n$', re.I)
# .rdata range of the game's own strings (before: CRT/zlib/libtiff/CxImage, after: PTK library)
GAME_LO, GAME_HI = 0x5c2950, 0x5cf430
# library / internal ranges of .rdata that are not game UI (CxImage, libtiff, CRT ...)
SKIP_RE = re.compile(r'^(%[-0-9.]*[sdlxuf]|[A-Za-z]:\\|.*\.(png|bmp|jpg|txt|dat|ogg|exe|dll|sav)$)', re.I)


def main(argv):
    exe, out = argv[0], argv[1]
    pe = pefile.PE(exe)
    base = pe.OPTIONAL_HEADER.ImageBase
    img = pe.get_memory_mapped_image()
    secs = {s.Name.rstrip(b'\0').decode(): s for s in pe.sections}
    text = secs['.text']
    t0, t1 = base + text.VirtualAddress, base + text.VirtualAddress + text.Misc_VirtualSize
    data_ranges = [(base + secs[n].VirtualAddress, base + secs[n].VirtualAddress + secs[n].Misc_VirtualSize)
                   for n in ('.rdata', '.data')]
    relocs = set()
    for blk in pe.DIRECTORY_ENTRY_BASERELOC:
        for e in blk.entries:
            if e.type == 3:
                relocs.add(base + e.rva)

    def string_at(va):
        if not any(a <= va < b for a, b in data_ranges):
            return None
        o = va - base
        if o > 0 and img[o - 1] != 0:
            return None
        end = img.find(b'\0', o, o + 2000)
        if end < 0 or end - o < 1:
            return None
        b = img[o:end]
        if not all(32 <= c < 127 or c in (9, 10, 13) for c in b):
            return None
        s = b.decode('ascii')
        if not re.search(r'[A-Za-z]{2}', s) and s.strip() not in ('!', '?', '.'):
            return None
        return s

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    code = img[t0 - base:t1 - base]
    insns = []
    off = 0
    while off < len(code):
        got = False
        for ins in md.disasm(code[off:off + 32], t0 + off, 1):
            insns.append(ins)
            off += ins.size
            got = True
        if not got:
            off += 1
    refs = collections.defaultdict(list)  # string va -> [sink]
    target_count = collections.Counter()
    for i, ins in enumerate(insns):
        if ins.imm_size != 4 or not ins.imm_offset or (ins.address + ins.imm_offset) not in relocs:
            continue
        imm = 0
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_IMM:
                imm = op.imm & 0xffffffff
        s = string_at(imm)
        if s is None:
            continue
        sink = ''
        for j in range(i + 1, min(i + 15, len(insns))):
            c = insns[j]
            if c.mnemonic == 'call':
                op = c.operands[0]
                if op.type == capstone.x86.X86_OP_IMM:
                    t = op.imm & 0xffffffff
                    sink = SINKS.get(t, '%06x' % t)
                    if t not in SINKS:
                        target_count[t] += 1
                break
            if c.mnemonic in ('ret', 'jmp'):
                break
        refs[imm].append(sink)
    # data tables: relocated pointers outside .text
    for r in relocs:
        if t0 <= r < t1:
            continue
        v = int.from_bytes(img[r - base:r - base + 4], 'little')
        if string_at(v) is not None:
            refs[v].append('table')
    if '--targets' in argv:
        for t, n in target_count.most_common(40):
            print('%06x %d' % (t, n))
    rows = []
    for va in sorted(refs):
        if not (GAME_LO <= va < GAME_HI):
            continue
        s = string_at(va)
        if SKIP_RE.match(s.strip()) and not re.search(r'[A-Za-z]{3} ', s):
            continue
        sinks = sorted(set(x for x in refs[va] if x))
        # a lone '.' is shared by dozens of messages and script errors: leave it
        if (INTERNAL_RE.search(s) or s == '.') and 'internal' not in sinks:
            sinks.append('internal')
        esc = s.replace('\\', '\\\\').replace('\t', '\\t').replace('\n', '\\n').replace('\r', '\\r')
        rows.append('0x%06x\t%s\t%d\t%s\t' % (va, ','.join(sinks), len(refs[va]), esc))
    # fixed-size char arrays in .data that the game shows (no pointer refers to them, the
    # code indexes 0x5edf00 + class * 20): class names of the character creation screen
    for va in (0x5edf00, 0x5edf14, 0x5edf28, 0x5edf3c, 0x5edf50):
        name = img[va - base:img.find(b'\0', va - base)].decode('ascii')
        rows.append('0x%06x\tinplace20\t0\t%s\t' % (va, name))
    with open(out, 'w', encoding='utf-8', newline='\n') as f:
        f.write('va\tsink\trefs\tenglish\tjapanese\n')
        f.write('\n'.join(rows) + '\n')
    print(f'{len(rows)} strings')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
