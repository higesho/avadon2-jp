"""Match functions of a reference exe to a target exe by instruction-mnemonic similarity.
usage: python -I funcmatch.py ref.exe target.exe VA [VA...]"""
import sys, difflib, capstone, pefile
def load(path):
    pe=pefile.PE(path); base=pe.OPTIONAL_HEADER.ImageBase; img=pe.get_memory_mapped_image()
    t=[s for s in pe.sections if s.Name.startswith(b'.text')][0]
    return base,img,t.VirtualAddress,t.Misc_VirtualSize
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
def func_seq(img,base,va,maxn=400):
    seq=[];code=img[va-base:va-base+0x3000]
    for ins in md.disasm(code,va):
        seq.append(ins.mnemonic+(' '+ins.op_str.split(',')[0].split()[0] if ins.op_str and ins.mnemonic not in('call','jmp') and not ins.mnemonic.startswith('j') else ''))
        if ins.mnemonic=='ret' or len(seq)>=maxn: break
    return seq
def targets(img,base,t0,tsz):
    """call rel32 targets in .text"""
    d=img[t0:t0+tsz]; s=set()
    for i in range(len(d)-5):
        if d[i]==0xe8:
            tgt=(t0+i+5+int.from_bytes(d[i+1:i+5],'little',signed=True))
            if t0<=tgt<t0+tsz: s.add(tgt+base)
    return sorted(s)
if __name__=='__main__':
    rb,ri,_,_=load(sys.argv[1]); tb,ti,t0,tsz=load(sys.argv[2])
    cands=targets(ti,tb,t0,tsz)
    cseq={c:func_seq(ti,tb,c) for c in cands}
    for a in sys.argv[3:]:
        a=int(a,16); rs=func_seq(ri,rb,a)
        sc=[]
        for c,s in cseq.items():
            if abs(len(s)-len(rs))>len(rs)*0.5+5: continue
            sm=difflib.SequenceMatcher(None,rs,s,autojunk=False)
            if sm.real_quick_ratio()<0.5 or sm.quick_ratio()<0.5: continue
            sc.append((sm.ratio(),c))
        sc.sort(reverse=True)
        print('%06x len %d ->'%(a,len(rs)),' '.join('%06x:%.2f'%(c,r) for r,c in sc[:5]))
