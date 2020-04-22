import string
import re
import os
import copy
import re
import pprint
from math import log10
from itertools import cycle


class NGramScore(object):
    def __init__(self, ngram='quadgram', file=False, filename='', sep=' '):
        ''' load a file containing ngrams and counts, calculate log probabilities '''
        mapping={
            'monogram':monograms.english_monograms,
            'bigram':bigrams.english_bigrams,
            'trigram':trigrams.english_trigrams,
            'quadgram':quadgrams.english_quadgrams,
            'quintgram':quintgrams.english_quintgrams
        }
        if ngram in mapping and file==False:
            self.ngrams = mapping[ngram]
        elif file is True and os.path.exists(filename):
            with open(filename, 'r') as file:
                for line in file.read().split('\n'):
                    key, count = line.split(' ')
                    ngrams[key] = int(count)
        else:
            raise ValueError('ngram entered does not match a valid ngram.py file and filename not a valid path')


        self.L = len(list(self.ngrams.keys())[0])
        print(self.L)
        self.N = sum(self.ngrams.values())
        # calculate log probabilities
        for key in self.ngrams.keys():
            self.ngrams[key] = log10(float(self.ngrams[key]) / self.N)
        self.floor = log10(0.01 / self.N)

    def score(self, text):
        ''' compute the score of text '''
        score = self.floor
        for i in range(len(text) - self.L + 1):
            if text[i:i + self.L] in self.ngrams:
                score += self.ngrams[text[i:i + self.L]]
            else:
                score += self.floor
        return score



class WordListScore(object):
    def __init__(self, wordlistfile):
        DictionaryFile = open(wordlistfile)
        englishwords = set()
        for word in DictionaryFile.read().split('\n'):
            englishwords.add(word.upper())

        self.words = englishwords

    def score(self, message):
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

#make sure all the dictionaries exist and then import them
#run on import to ensure code works

basepath=os.path.dirname(os.path.abspath(__file__))
dictionaryfolder='dictionaries'
ngramslist=['english_monograms','english_bigrams','english_trigrams','english_quadgrams','english_quintgrams']
for ngramtxt in ngramslist:
    ngramfile=os.path.join(basepath,dictionaryfolder,ngramtxt+'.txt')
    ngramdictfile=os.path.join(basepath,dictionaryfolder,ngramtxt+'.py')
    if not os.path.exists(ngramdictfile):
        ngrams={}
        with open(ngramfile,'r') as file:
            for line in file.read().split('\n'):
                key, count = line.split(' ')
                ngrams[key] = int(count)
        with open(ngramdictfile,'w') as file:
            file.write(ngramtxt+'=')
            file.write(pprint.pformat(ngrams))

import decoders.dictionaries.english_monograms as monograms
import decoders.dictionaries.english_bigrams as bigrams
import decoders.dictionaries.english_trigrams as trigrams
import decoders.dictionaries.english_quadgrams as quadgrams
import decoders.dictionaries.english_quintgrams as quintgrams
