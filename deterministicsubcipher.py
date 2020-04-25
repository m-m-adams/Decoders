import os
import copy
import re
import pprint
import time


# import decoders.dictionaries.wordpatterns as wordpatterns


def subcipher(message, key):
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    fullkey = key.lower() + key.upper()
    trans = message.maketrans(alphabet, fullkey)
    return message.translate(trans)


def subuncipher(message, key):
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    fullkey = key.lower() + key.upper()
    trans = message.maketrans(fullkey, alphabet)
    return message.translate(trans)


class LetterMap:
    def __init__(self, map=''):
        self.blankmap = {'A': [], 'B': [], 'C': [], 'D': [], 'E': [], 'F': [], 'G': [], 'H': [], 'I': [], 'J': [],
                         'K': [], 'L': [], 'M': [], 'N': [], 'O': [], 'P': [], 'Q': [], 'R': [], 'S': [], 'T': [],
                         'U': [], 'V': [], 'W': [], 'X': [], 'Y': [], 'Z': []}
        if map:
            self.lettermap = map
        else:
            self.lettermap = copy.deepcopy(self.blankmap)
        self.possiblewords = set()
        self.knownwords = set()
        self.knownpatterns = ''
        self.key = '*' * 26

    # add letters from a possible cipherword:candidate pairing to the lettermap
    def addletterstomapping(self, cipherword, candidate):

        lettermapping = self.lettermap
        for i in range(len(cipherword)):
            if candidate[i] not in lettermapping[cipherword[i]]:
                lettermapping[cipherword[i]].append(candidate[i])
        self.lettermap = lettermapping

    # remove letters which have been solved from the lettermap
    def removesolvedlettersfrommapping(self):
        lettermapping = copy.deepcopy(self.lettermap)
        loopAgain = True
        while loopAgain:
            # First assume that we will not loop again:
            loopAgain = False
            # solvedLetters will be a list of uppercase letters that have one
            # and only one possible mapping in letterMapping
            solvedletters = []
            for cipherletter in LETTERS:
                if len(lettermapping[cipherletter]) == 1:
                    solvedletters.append(lettermapping[cipherletter][0])
            # pprint.pprint(solvedletters)
            # If a letter is solved, than it cannot possibly be a potential
            # decryption letter for a different ciphertext letter, so we
            # should remove it from those other lists.
            for cipherletter in LETTERS:
                for s in solvedletters:
                    if len(lettermapping[cipherletter]) != 1 and s in lettermapping[cipherletter]:
                        lettermapping[cipherletter].remove(s)
                        if len(lettermapping[cipherletter]) == 1:
                            # A new letter is now solved, so loop again.
                            loopAgain = True
        self.lettermap = lettermapping

    # from the known part of a partially deciphered message, compute a lettermap and intersect with current lettermap
    def buildknownlettermap(self, ciphered, plaintext):
        knownmap = copy.deepcopy(self.blankmap)

        cipherarray = ciphered.split()
        plainarray = plaintext.split()
        for wordnum in range(len(plainarray)):
            if plainarray[wordnum] != '???':
                self.knownwords.add(plainarray[wordnum])
                for letternum in range(len(plainarray[wordnum])):
                    cipherletter = cipherarray[wordnum][letternum].upper()
                    plainletter = plainarray[wordnum][letternum].upper()

                    knownmap[cipherletter].append(plainletter)

        self.lettermap = self.intersectmappings(knownmap)
        self.removesolvedlettersfrommapping()

    # from an encrypted message, build out a lettermap from all possible words
    def buildlettermap(self, message):
        # make a blank dictionary

        intersectedmap = copy.deepcopy(self.blankmap)

        cipherwords = message.upper()
        cipherwords = ''.join(filter(lambda ch: ch == ' ' or ch.isalpha(), cipherwords))
        candidates = set()

        uniquewords = list(set(cipherwords.split()))
        uniquewords.sort(key=len)

        flag = 0
        for cipherword in uniquewords:
            wordpattern = getwordpattern(cipherword)
            newmap = LetterMap()

            if wordpattern not in englishpatterns:

                continue
            else:
                possibledeciphers = englishpatterns[wordpattern]
                for candidate in possibledeciphers:
                    candidates.add(candidate)
                    newmap.addletterstomapping(cipherword, candidate)
                # print(cipherword,wordpattern, len(englishpatterns[wordpattern]), newmap.lettermap)
                lastmap = intersectedmap
                intersectedmap = newmap.intersectmappings(intersectedmap)
                # print(intersectedmap)

        intersectedmap = self.intersectmappings(intersectedmap)
        self.lettermap = intersectedmap
        self.possiblewords = candidates

        self.removesolvedlettersfrommapping()

    # from the lettermap and the ciphertext, build out all known patterns
    def buildknownpatterns(self, ciphertext):
        # Return a string of the ciphertext decrypted with the letter mapping,
        # with any ambiguous decrypted letters replaced with an _ underscore.
        # First create a simple sub key from the letterMapping mapping.
        savedcipher = ciphertext
        lettermapping = self.lettermap

        key = ['*'] * len(LETTERS)

        for cipherletter in LETTERS:
            if len(lettermapping[cipherletter]) == 1:
                # If there's only one letter, add it to the key.
                keyindex = LETTERS.find(lettermapping[cipherletter][0])
                key[keyindex] = cipherletter
            else:
                ciphertext = ciphertext.replace(cipherletter.lower(), '_')
                ciphertext = ciphertext.replace(cipherletter.upper(), '_')

        key = ''.join(key)
        knownpatterns = list(subuncipher(ciphertext, key))
        for index in range(len(knownpatterns)):
            if knownpatterns[index] == '_':
                ogletter = savedcipher[index].upper()
                replacement = ''.join(lettermapping[ogletter])
                if replacement == '':
                    replacement = '.'
                replacement = '[' + replacement + ']'
                knownpatterns[index] = replacement
        knownpatterns = ''.join(knownpatterns)
        # With the key we've created, decrypt the ciphertext.
        self.knownpatterns = knownpatterns
        self.key = key

    # intersect a mapping with a second map, return the overlap\
    def intersectmappings(self, mapB):

        # To intersect two maps, create a blank map, and then add only the
        # potential decryption letters if they exist in BOTH maps.

        intersectedmapping = copy.deepcopy(self.blankmap)
        mapA = copy.deepcopy(self.lettermap)
        for letter in LETTERS:
            # An empty list means "any letter is possible". In this case just
            # copy the other map entirely.
            if mapA[letter] == []:
                intersectedmapping[letter] = copy.deepcopy(mapB[letter])
            elif mapB[letter] == []:
                intersectedmapping[letter] = copy.deepcopy(mapA[letter])

            # if one mapping has only one possibility, that's it
            elif len(mapA[letter]) == 1:
                intersectedmapping[letter] = copy.deepcopy(mapA[letter])
            elif len(mapB[letter]) == 1:
                intersectedmapping[letter] = copy.deepcopy(mapB[letter])
            else:
                # If a letter in mapA[letter] exists in mapB[letter], add
                # that letter to intersectedmapping[letter].
                for mappedletter in mapA[letter]:
                    if mappedletter in mapB[letter]:
                        intersectedmapping[letter].append(mappedletter)
        return intersectedmapping

    def decryptwithknownpatterns(self):
        knownpatterns = self.knownpatterns
        possiblewords = self.possiblewords | self.knownwords
        decryptedstring = []
        otherpossibilities = {}
        for pattern in knownpatterns.split():
            pattern = ''.join(filter(lambda ch: ch in ['[', ']', '-', ' ', '.'] or ch.isalpha(), pattern))
            pattern = r'\b' + pattern + r'\b'

            p = re.compile(pattern, re.IGNORECASE)
            possibledecryptions = list(filter(p.match, possiblewords))

            if len(possibledecryptions) == 1:
                decryptedstring.append(possibledecryptions[0])
            else:
                decryptedstring.append('???')
                otherpossibilities[pattern] = (possibledecryptions[0:len(possibledecryptions)])

        return ' '.join(decryptedstring), otherpossibilities


def decryptsubcipher(ciphertext):
    fullciphertext = ciphertext
    knownlettermap = LetterMap()

    ciphertext = ''.join(filter(lambda ch: ch == ' ' or ch.isalpha(), ciphertext))

    knownlettermap.buildlettermap(ciphertext)

    knownlettermap.buildknownpatterns(ciphertext)

    plaintext, others = knownlettermap.decryptwithknownpatterns()

    # print(knownlettermap.lettermap)
    knownlettermap.buildknownlettermap(ciphertext, plaintext)

    progress = True
    unknown = ''
    remainingciphertext=ciphertext

    round = 1
    while remainingciphertext != unknown:
        round += 1
        unknown = remainingciphertext
        # build possible letter map from remaining ciphertext

        remainingcipherwords = []
        plaintextarray = plaintext.split()
        ciphertextarray = ciphertext.split()
        for i in range(len(plaintextarray)):
            if plaintextarray[i] == '???':
                remainingcipherwords.append(ciphertextarray[i])
        remainingciphertext = ' '.join(remainingcipherwords)
        knownlettermap.buildlettermap(remainingciphertext)

        knownlettermap.buildknownpatterns(ciphertext)

        plaintext, others = knownlettermap.decryptwithknownpatterns()

        knownlettermap.buildknownlettermap(ciphertext, plaintext)



    return subuncipher(fullciphertext, knownlettermap.key)


def getwordpattern(word):
    # Returns an int with the word pattern for a word
    # int used for more efficient dictionary lookup

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


# englishpatterns=wordpatterns.allpatterns
LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

wordpatternpath = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dictionaries', "wordpatterns.py")
if not os.path.exists(wordpatternpath):
    print('making the dictionary')
    with open(wordpatternpath, 'w') as fo:
        fo.write('allpatterns= ')
        wordpatterns = makewordpatterns(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dictionaries', "shortdictionary.txt"))
        fo.write(pprint.pformat(wordpatterns))

import decoders.dictionaries.wordpatterns as wordpatterns

englishpatterns = wordpatterns.allpatterns
if __name__ == '__main__':
    mymessage = 'A mask protects others more than it protects you, It prevents you from breathing or speaking moistly on them, What a terrible image, But it actually is something that people can do in certain situations.'
    # ciphertext='LKGGZHGS OTGGSVBKLYTH BEJDYELLTB HTJEGEMZNTH ITMEQBKMPLGKMQP FKBFKBTPUAT QBKMP FBKFFGTB PQBTTQCTKB YEGSPQEMTP BTLKBDZMV PQKVTGZDT BTFEBTH FGTPFED ZMJBTPJTMQ'
    key = 'LFWOAYUISVKMNXPBDCRJTQEGHZ'

    ciphertext = subcipher(mymessage, key)
    print(ciphertext)
    plain = decryptsubcipher(ciphertext)

    print(plain)