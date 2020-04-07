import string
import re
import os
import copy
import re
import pprint
from math import log10
from itertools import cycle


class ngram_score(object):
    def __init__(self, ngramfile, sep=' '):
        ''' load a file containing ngrams and counts, calculate log probabilities '''
        self.ngrams = {}
        with open(ngramfile) as file:
            for line in file.read().split('\n'):
                key, count = line.split(sep)
                self.ngrams[key] = int(count)
        self.L = len(key)
        self.N = sum(self.ngrams.values())
        # calculate log probabilities
        for key in self.ngrams.keys():
            self.ngrams[key] = log10(float(self.ngrams[key]) / self.N)
        self.floor = log10(0.01 / self.N)

    def score(self, text):
        ''' compute the score of text '''
        score = 0
        ngrams = self.ngrams.__getitem__
        for i in range(len(text) - self.L + 1):
            if text[i:i + self.L] in self.ngrams:
                score += ngrams(text[i:i + self.L])
            else:
                score += self.floor
        return score

class wordlist_score(object):
    def __init__(self, wordlistfile):
        DictionaryFile = open(wordlistfile)
        englishwords = set()
        for word in DictionaryFile.read().split('\n'):
            englishwords.add(word.upper())

        self.words = englishwords

    def wordportion(self, message):
        message=message.upper()

        possibleWords=re.split(r'[();.,-=:\s\n]',message)
        if possibleWords==[]:
            return 0
        matches=0
        count=1
        for word in possibleWords:
            if word != '':
                count+=1
                if word in self.words:
                    matches+=1
        return float(matches)/(count)





