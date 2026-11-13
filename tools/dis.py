"""dis.py exe VA [count]  |  dis.py exe --imp NAME  (callers of an import)"""
import sys,capstone,pefile
pe=pefile.PE(sys.argv[1]); base=pe.OPTIONAL_HEADER.ImageBase; img=pe.get_memory_mapped_image()
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
t=[s for s in pe.sections if s.Name.startswith(b'.text')][0]; t0=t.VirtualAddress; td=img[t0:t0+t.Misc_VirtualSize]
imps={}
for e in pe.DIRECTORY_ENTRY_IMPORT:
    for i in e.imports: imps[i.address]=(i.name or b'#%d'%i.ordinal).decode()
def name(op):
    for a,n in imps.items():
        if '%#x'%a in op: return op+'  <'+n+'>'
    return op
if sys.argv[2]=='--around':
    va=int(sys.argv[3],16); bef=int(sys.argv[4]) if len(sys.argv)>4 else 12; aft=int(sys.argv[5]) if len(sys.argv)>5 else 6
    o=va-base-t0
    while o>0 and not (td[o-1]==0xcc and td[o]!=0xcc): o-=1
    ins=list(md.disasm(td[o:va-base-t0+64],t0+base+o))
    k=[i for i,x in enumerate(ins) if x.address==va]
    k=k[0] if k else len(ins)-1
    for x in ins[max(0,k-bef):k+aft+1]: print('%06x  %s %s'%(x.address,x.mnemonic,name(x.op_str)))
elif sys.argv[2]=='--imp':
    a=[k for k,v in imps.items() if v==sys.argv[3]][0]
    pat=a.to_bytes(4,'little'); i=0
    while True:
        i=td.find(pat,i)
        if i<0: break
        print('%06x'%(t0+base+i-2)); i+=1
else:
    va=int(sys.argv[2],16); n=int(sys.argv[3]) if len(sys.argv)>3 else 60
    for ins in md.disasm(img[va-base:va-base+n*8],va):
        print('%06x  %-24s %s %s'%(ins.address,ins.bytes.hex(),ins.mnemonic,name(ins.op_str)))
        n-=1
        if n<=0: break
# --around VA [before] [after]: decode from the containing function's start, print a window
