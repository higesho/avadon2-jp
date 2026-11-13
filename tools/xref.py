"""xref.py exe VA... : code locations whose bytes contain the absolute address (with containing instruction)"""
import sys,pefile,capstone
pe=pefile.PE(sys.argv[1]); base=pe.OPTIONAL_HEADER.ImageBase; img=pe.get_memory_mapped_image()
t=[s for s in pe.sections if s.Name.startswith(b'.text')][0]; t0=t.VirtualAddress; td=img[t0:t0+t.Misc_VirtualSize]
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
def funcstart(off):
    # walk back to previous CC/C3 padding followed by push ebp/ other
    o=off
    while o>0:
        if td[o-1] in (0xcc,) and td[o]!=0xcc: return o
        o-=1
    return 0
for a in sys.argv[2:]:
    a=int(a,16); pat=a.to_bytes(4,'little'); i=0
    print('== %06x'%a)
    while True:
        i=td.find(pat,i)
        if i<0: break
        fs=funcstart(i)
        # decode from function start to find the instruction
        txt='?'
        for ins in md.disasm(td[fs:i+8],t0+base+fs):
            if ins.address<=t0+base+i<ins.address+ins.size: txt='%06x %s %s'%(ins.address,ins.mnemonic,ins.op_str)
        print('  func~%06x  %s'%(t0+base+fs,txt)); i+=1
