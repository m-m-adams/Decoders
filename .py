import string
import re

def rot (rotthis,d):
    n=d%26
    UC='ABCDEFGHIJKLMNOPQRSTUVWXYZ'.encode()
    LC='abcdefghijklmnopqrstuvwxyz'.encode()
    trans=bytes.maketrans(UC+LC,UC[n:]+UC[0:n]+LC[n:]+LC[0:n])
    #print((UC+LC))
    #print(UC[n:]+UC[0:n]+LC[n:]+LC[0:n])
    return rotthis.translate(trans)
        
def steprot(rotthis,base,increment):
    decoded=[]
    i=0
    for letter in rotthis:
        chardecode=rot(letter,base+i*increment)
        decoded.append(chardecode)
        i+=1
    return ''.join(decoded)

def makeDictionary():
    DictionaryFile=open('dictionary.txt')
    englishwords={}
    for word in DictionaryFile.read().split('\n'):
        englishwords[word.upper()]=None
    DictionaryFile.close()
    englishwords['WWW']=None
    englishwords['COM']=None
    englishwords['HTTP']=None
    englishwords['URL']=None
    englishwords['MOZILLA']=None
    englishwords['BBC']=None
    return englishwords


EnglishWords=makeDictionary()

def CountEnglish(message):
    message=message.upper()

    possibleWords=re.split('[();.,-=:\s\n]',message)
    if possibleWords==[]:
        return 0
    matches=0
    for word in possibleWords:
        if word != '':
            if word in EnglishWords:
                matches+=1

    return float(matches)/len(possibleWords)

def TryThemAll(message):
    Possible=[]
    Confidence=0
    for i in range(26):
        for j in range(26):
            PossibleMessage=steprot(message,i,j)
            Num=CountEnglish(PossibleMessage)
            if Num>Confidence:
                Possible=PossibleMessage
                Confidence=Num
    return Possible

def LineByLine(message):
    lbyl=message.splitlines()
    output=[]
    for line in lbyl:
        decode=TryThemAll(line)
        output.append(decode)
    return(output)

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

decoded=LineByLine(test)

for item in decoded:
    print (item)
