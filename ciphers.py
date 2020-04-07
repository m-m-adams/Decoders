
from itertools import cycle
from pycipher import *
from pycipher.base import Cipher


#this module just extends pycipher and adds some other ciphers



class XOR(Cipher):
    def __init__(self,key):
        self.key=key

    def encipher(self,plaintext, keep_punct=False):
        if not keep_punct: plaintext = self.remove_punctuation(plaintext)

        return "".join([chr(ord(c1) ^ ord(c2)) for (c1, c2) in zip(plaintext, cycle(self.key))])

    def decipher(self,ciphertext, keep_punct=False):
        #if not keep_punct: ciphertext = self.remove_punctuation(ciphertext)
        return "".join([chr(ord(c1) ^ ord(c2)) for (c1, c2) in zip(ciphertext, cycle(self.key))])


class StepRot(Cipher):
    # step rot rotates each letter by an increasing rot key
    # the key for step rot is a tuple (base, increment)
    def __init__(self,key):
        self.key = key

    def encipher(self, plaintext, keep_punct=False):
        ciphered=[]
        i=0
        base, increment = self.key
        if not keep_punct: string = self.remove_punctuation(plaintext)
        for letter in plaintext:
            caesarkey=base+i*increment
            chardecode=Caesar(caesarkey).encipher(letter,keep_punct)
            ciphered.append(chardecode)
            i+=1
        return ''.join(ciphered)

    def decipher(self, ciphertext, keep_punct=False):
        deciphered=[]
        i=0
        base, increment = self.key
        if not keep_punct: string = self.remove_punctuation(ciphertext)
        for letter in ciphertext:
            chardecode=Caesar(base-i*increment).encipher(letter, keep_punct)
            deciphered.append(chardecode)
            i+=1
        return ''.join(deciphered)

if __name__ == '__main__':
    steptest=StepRot((13,2))
    message='This is a test sentence'
    print(message)
    ciphertest=steptest.encipher(message, keep_punct=True)
    print(ciphertest)
    print(steptest.decipher(ciphertest, keep_punct=True))

    xortest=XOR('abc')

    ciphertest=xortest.encipher(message, keep_punct=True)
    print(ciphertest)
    print(xortest.decipher(ciphertest))