import string
import re
import decode

def trythemall(message):
    Possible=[]
    Confidence=0
    for i in range(26):
        for j in range(26):
            PossibleMessage=decode.steprot(message,i,j)
            Num=decode.countenglish(PossibleMessage)
            if Num>Confidence:
                Possible=PossibleMessage
                Confidence=Num
    return ''.join(Possible)

def bruteforcesteprot(message,seperator):
    pieces=message.split()
    output=[]
    for line in pieces:
        decode=trythemall(line)
        if len(decode) == 0:decode=' '
        output.append(decode)
    
    string='\n'.join(output)    
    return string

if __name__ == '__main__':

    encoded='''kpu.jou.evy
    Ezd OVD xjiyikx, ekixccup lfc
    UUL / HVXV/1.1
    Ajps: bdf.oqt.xll
    Ssgv-Iqqbj: Imzkpri/5.0 (Sgnfsca ZH 6.2; Ymt32; n86; rx:61.0) Yyyio/20100101 Bgrgjuf/61.0
    Dhjnag: mzus/kytu, pgigfbbwnvw/kwkfg+wno, jacazvvqhpq/evw; h=0.9;t=0.8
    Kyzbuunemn: ityes
    Hexkvad-Lsznnhgv-Mbpvhxab: 1
    Uuyfe-Guvddcb: iyx-emm=0'''
    test=" xihag-macod-becag-sobeg-limyg-niged-bebah-nebig-hugad-buhog-hebig-tumoh-fuduh-mixox"
    problem='Ezd OVD xjiyikx, ekixccup lfc'

    decoded=bruteforcesteprot(encoded,'\n')
    print(encoded)
    print(decoded)
