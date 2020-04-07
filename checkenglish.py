import string
import re
import os
import copy
import re
import pprint
from itertools import cycle


def getwordpattern(word):
    # Returns a string of the pattern form of the given word.
    # e.g. '0.1.2.3.4.1.2.3.5.6' for 'DUSTBUSTER'
    word = word.upper()
    nextNum = 1
    letterNums = {}
    wordPattern = []

    for letter in word:
        if letter not in letterNums:
            letterNums[letter] = str(nextNum)
            nextNum += 1
        wordPattern.append(letterNums[letter])

    return int(''.join(wordPattern))

def makewordpatterns(pathtodictionary):

    allPatterns = {}
    fo = open(pathtodictionary)
    wordList = fo.read().split('\n')
    fo.close()
    for word in wordList:
    # Get the pattern for each string in wordList.
        pattern = getwordpattern(word)
        if pattern not in allPatterns:
            allPatterns[pattern] = [word]
        else:
            allPatterns[pattern].append(word)

    return allPatterns




def makeDictionary(Path='dictionary.txt'):
    DictionaryFile=open(Path)
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

def countenglish(message):
    message=message.upper()

    possibleWords=re.split(r'[();.,-=:\s\n]',message)
    if possibleWords==[]:
        return 0
    matches=0
    count=1
    for word in possibleWords:
        if word != '':
            count+=1
            if word in wordlist.allwords:
                matches+=1
    return float(matches)/(count)


wordspath=os.path.join(os.path.dirname(os.path.abspath(__file__)),"wordlist.py")
if not os.path.exists(wordspath):
    fo=open(wordspath,'w')
    fo.write('allwords= ')
    englishwords=makeDictionary(os.path.join(os.path.dirname(os.path.abspath(__file__)),"dictionary.txt"))
    fo.write(pprint.pformat(englishwords))
    fo.close()

import decoders.wordlist as wordlist

englishwords=wordlist.allwords

wordpatternpath=os.path.join(os.path.dirname(os.path.abspath(__file__)),"wordpatterns.py")
if not os.path.exists(wordpatternpath):
    fo=open(wordpatternpath,'w')
    fo.write('allpatterns= ')
    wordpatterns=makewordpatterns(os.path.join(os.path.dirname(os.path.abspath(__file__)),"dictionary.txt"))
    fo.write(pprint.pformat(wordpatterns))
    fo.close()

import decoders.wordpatterns as wordpatterns

englishpatterns=wordpatterns.allpatterns


letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'



