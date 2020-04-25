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


class SubCipherDecrypter:
    def __init__(self, map=''):
        self.letter_dictionary = {'A': [], 'B': [], 'C': [], 'D': [], 'E': [], 'F': [], 'G': [], 'H': [], 'I': [], 'J': [],
                         'K': [], 'L': [], 'M': [], 'N': [], 'O': [], 'P': [], 'Q': [], 'R': [], 'S': [], 'T': [],
                         'U': [], 'V': [], 'W': [], 'X': [], 'Y': [], 'Z': []}
        if map:
            self.possible_letters = map
        else:
            self.possible_letters = copy.deepcopy(self.letter_dictionary)
        self.possible_words = set()
        self.known_words = set()
        self.known_patterns = ''
        self.key = '*' * 26

    # add letters from a possible cipherword:candidate pairing to the lettermap
    def add_possible_letters(self, cipherword, candidate):

        possible_letters = self.possible_letters
        for cipher_letter, plain_letter in zip(cipherword, candidate):
            if plain_letter not in possible_letters[cipher_letter]:
                possible_letters[cipher_letter].append(plain_letter)
        self.possible_letters = possible_letters

    # remove letters which have been solved from the lettermap
    def remove_solved_letters(self):
        possible_letters = copy.deepcopy(self.possible_letters)
        repeat = True
        while repeat:
            # First assume that we will not loop again:
            repeat = False
            # solvedLetters will be a list of uppercase letters that have one
            # and only one possible mapping in letterMapping
            solved_letters = []
            for cipher_letter in LETTERS:
                if len(possible_letters[cipher_letter]) == 1:
                    solved_letters.append(possible_letters[cipher_letter][0])

            # If a letter is solved, than it cannot possibly be a potential
            # decryption letter for a different ciphertext letter, so we
            # should remove it from those other lists.
            for cipher_letter in LETTERS:
                for s in solved_letters:
                    if len(possible_letters[cipher_letter]) != 1 and s in possible_letters[cipher_letter]:
                        possible_letters[cipher_letter].remove(s)
                        if len(possible_letters[cipher_letter]) == 1:
                            # A new letter is now solved, so loop again.
                            repeat = True
        self.possible_letters = possible_letters

    # from the known part of a partially deciphered message, compute a lettermap and intersect with current lettermap
    def add_known_letters_to_dictionary(self, ciphered, plaintext):
        known_letters = copy.deepcopy(self.letter_dictionary)
        cipher_array = ciphered.split()
        plain_array = plaintext.split()
        for cipher_word, plain_word in zip(cipher_array, plain_array):
            if plain_word != '???':
                self.known_words.add(plain_word)
                for cipher_letter, plain_letter in zip(cipher_word, plain_word):
                    known_letters[cipher_letter.upper()].append(plain_letter.upper())

        self.possible_letters = self.combine_letter_possibilities(known_letters)
        self.remove_solved_letters()

    # from an encrypted message, build out a lettermap from all possible words
    def build_possible_letter_dictionary(self, message):
        # make a blank dictionary

        letter_possibilities = copy.deepcopy(self.letter_dictionary)

        cipherwords = message.upper()
        cipherwords = ''.join(filter(lambda ch: ch == ' ' or ch.isalpha(), cipherwords))
        candidates = set()

        unique_words = list(set(cipherwords.split()))
        unique_words.sort(key=len)

        for cipherword in unique_words:
            word_pattern = getwordpattern(cipherword)
            single_word_decrypter = SubCipherDecrypter()

            if word_pattern not in englishpatterns:

                continue
            else:
                possibledeciphers = englishpatterns[word_pattern]
                for candidate in possibledeciphers:
                    candidates.add(candidate)
                    single_word_decrypter.add_possible_letters(cipherword, candidate)
                letter_possibilities = single_word_decrypter.combine_letter_possibilities(letter_possibilities)

        letter_possibilities = self.combine_letter_possibilities(letter_possibilities)
        self.possible_letters = letter_possibilities
        self.possible_words = candidates
        self.remove_solved_letters()

    # from the lettermap and the ciphertext, build out all known patterns
    def make_regex_pattern(self, ciphertext):
        # Return a string of the ciphertext decrypted with the letter mapping,
        # with any ambiguous decrypted letters replaced a regex to match their
        # possible letters
        savedcipher = ciphertext
        lettermapping = self.possible_letters

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
        self.known_patterns = knownpatterns
        self.key = key

    # intersect a mapping with a second map, return the overlap\
    def combine_letter_possibilities(self, mapB):

        # To intersect two maps, create a blank map, and then add only the
        # potential decryption letters if they exist in BOTH maps.

        intersectedmapping = copy.deepcopy(self.letter_dictionary)
        mapA = copy.deepcopy(self.possible_letters)
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

    def decrypt_with_regex(self):
        knownpatterns = self.known_patterns
        possiblewords = self.possible_words | self.known_words
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
    knownlettermap = SubCipherDecrypter()

    ciphertext = ''.join(filter(lambda ch: ch == ' ' or ch.isalpha(), ciphertext))

    knownlettermap.build_possible_letter_dictionary(ciphertext)

    knownlettermap.make_regex_pattern(ciphertext)

    plaintext, others = knownlettermap.decrypt_with_regex()

    # print(knownlettermap.lettermap)
    knownlettermap.add_known_letters_to_dictionary(ciphertext, plaintext)

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
        knownlettermap.build_possible_letter_dictionary(remainingciphertext)

        knownlettermap.make_regex_pattern(ciphertext)

        plaintext, others = knownlettermap.decrypt_with_regex()

        knownlettermap.add_known_letters_to_dictionary(ciphertext, plaintext)



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