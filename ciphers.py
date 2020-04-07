
from itertools import cycle

def rot (rotthis,d):
    n=d%26
    UC='ABCDEFGHIJKLMNOPQRSTUVWXYZ'.encode()
    LC='abcdefghijklmnopqrstuvwxyz'.encode()
    trans=bytes.maketrans(UC+LC,UC[n:]+UC[0:n]+LC[n:]+LC[0:n])
    #print((UC+LC))
    #print(UC[n:]+UC[0:n]+LC[n:]+LC[0:n])
    return rotthis.translate(trans)

def xor (message, key):
    return "".join([chr(ord(c1) ^ ord(c2)) for (c1,c2) in zip(message,cycle(key))])

def subcipher(message,key):
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    fullkey=key.lower()+key.upper()
    trans=message.maketrans(alphabet,fullkey)
    return message.translate(trans)

def subuncipher(message,key):
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    fullkey=key.lower()+key.upper()
    trans=message.maketrans(fullkey,alphabet)
    return message.translate(trans)

def steprot(rotthis,base,increment):
    decoded=[]
    i=0
    for letter in rotthis:
        chardecode=rot(letter,base+i*increment)
        decoded.append(chardecode)
        i+=1
    return ''.join(decoded)
