import re,sys,pefile
src=open(sys.argv[1],encoding='utf-8').read()
pats=re.findall(r'\{"(\w+)", (NULL|"\w+"), 0x([0-9a-f]+),\s*"([0-9A-F? ]+)"\}',src)
pe=pefile.PE(sys.argv[2]); base=pe.OPTIONAL_HEADER.ImageBase; img=pe.get_memory_mapped_image()
t=[s for s in pe.sections if s.Name.startswith(b'.text')][0]; t0=t.VirtualAddress; td=img[t0:t0+t.Misc_VirtualSize]
for name,anc,va,p in pats:
    toks=p.split()
    for cut in (len(toks), 24, 16, 12):
        rx=re.compile(b''.join(b'.' if x=='??' else re.escape(bytes([int(x,16)])) for x in toks[:cut]),re.S)
        hits=[m.start()+t0+base for m in rx.finditer(td)]
        if hits: break
    print(name, va, 'len',len(toks),'cut',cut, ' '.join('%x'%h for h in hits[:8]), len(hits))
