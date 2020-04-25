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


class SubCipherDecryption(object):
    def __init__(self, fullciphertext, map=''):
        self.blank_letter_dictionary = {'A': [], 'B': [], 'C': [], 'D': [], 'E': [], 'F': [], 'G': [], 'H': [], 'I': [],
                                        'J': [], 'K': [], 'L': [], 'M': [], 'N': [], 'O': [], 'P': [], 'Q': [], 'R': [],
                                        'S': [], 'T': [], 'U': [], 'V': [], 'W': [], 'X': [], 'Y': [], 'Z': []}
        if map:
            self.letter_possibilities = map
        else:
            self.letter_possibilities = copy.deepcopy(self.blank_letter_dictionary)
        self.possible_words = set()
        self.known_words = set()
        self.ciphertext = ''.join(filter(lambda ch: ch == ' ' or ch.isalpha(), fullciphertext))
        self.known_regex_patterns = ''
        self.key = '*' * 26

    # add letters from a possible cipherword:candidate pairing to the list of possibilities
    def add_possible_letters(self, cipherword, candidate):

        letter_possibilities = self.letter_possibilities
        for i in range(len(cipherword)):
            if candidate[i] not in letter_possibilities[cipherword[i]]:
                letter_possibilities[cipherword[i]].append(candidate[i])
        self.letter_possibilities = letter_possibilities

    # remove letters which have been solved from the lettermap
    def remove_solved_letters(self):
        letter_possibilities = copy.deepcopy(self.letter_possibilities)
        loop_again = True
        while loop_again:
            # First assume that we will not loop again:
            loop_again = False
            # solved letters have one possible mapping in letterMapping
            solved_letters = []
            for cipher_letter in LETTERS:
                if len(letter_possibilities[cipher_letter]) == 1:
                    solved_letters.append(letter_possibilities[cipher_letter][0])

            # If a letter is solved, than we should remove it from other lists.
            for cipher_letter in LETTERS:
                for s in solved_letters:
                    if len(letter_possibilities[cipher_letter]) != 1 and s in letter_possibilities[cipher_letter]:
                        letter_possibilities[cipher_letter].remove(s)
                        if len(letter_possibilities[cipher_letter]) == 1:
                            # A new letter is now solved, so loop again.
                            loop_again = True
        self.letter_possibilities = letter_possibilities

    def add_known_letters_to_possible_letters(self, ciphered, plaintext):
        known_letters = copy.deepcopy(self.blank_letter_dictionary)

        cipher_array = ciphered.split()
        plain_array = plaintext.split()
        for cipher_word, plain_word in zip(cipher_array, plain_array):
            if plain_word != '???':
                self.known_words.add(plain_word)
                for cipher_letter, plain_letter in zip(cipher_word, plain_word):
                    known_letters[cipher_letter.upper()].append(plain_letter.upper())

        self.letter_possibilities = self.combine_letter_possibilities(known_letters)
        self.remove_solved_letters()

    # from an encrypted message, build out a dictionary of possible decryptions from all possible words
    def generate_possible_letters(self, message):

        # make a blank dictionary

        combined_letter_possibilities = copy.deepcopy(self.blank_letter_dictionary)

        cipher_words = message.upper()
        cipher_words = ''.join(filter(lambda ch: ch == ' ' or ch.isalpha(), cipher_words))
        candidates = set()

        cipher_words = list(set(cipher_words.split()))
        cipher_words.sort(key=len)

        for cipher_word in cipher_words:
            word_pattern = getwordpattern(cipher_word)
            word_decryption = SubCipherDecryption(cipher_word)

            if word_pattern not in englishpatterns:

                continue
            else:
                possible_words = englishpatterns[word_pattern]
                for candidate in possible_words:
                    candidates.add(candidate)
                    word_decryption.add_possible_letters(cipher_word, candidate)
                combined_letter_possibilities = word_decryption.combine_letter_possibilities(combined_letter_possibilities)

        combined_letter_possibilities = self.combine_letter_possibilities(combined_letter_possibilities)
        self.letter_possibilities = combined_letter_possibilities
        self.possible_words = candidates

        self.remove_solved_letters()

    # from the possible letters and the ciphertext, build out all known patterns
    def generate_known_regex_patterns(self, ciphertext):

        # Return a string of the ciphertext decrypted with the letter mapping,
        # with any ambiguous decrypted letters replaced with an _ underscore.
        # First create a simple sub key from the letterMapping mapping.
        original_ciphertext = ciphertext
        letter_possibilities = self.letter_possibilities

        key = ['*'] * len(LETTERS)

        for cipherletter in LETTERS:
            if len(letter_possibilities[cipherletter]) == 1:
                # If there's only one letter, add it to the key.
                keyindex = LETTERS.find(letter_possibilities[cipherletter][0])
                key[keyindex] = cipherletter
            else:
                ciphertext = ciphertext.replace(cipherletter.lower(), '_')
                ciphertext = ciphertext.replace(cipherletter.upper(), '_')

        key = ''.join(key)
        knownpatterns = list(subuncipher(ciphertext, key))
        for index in range(len(knownpatterns)):
            if knownpatterns[index] == '_':
                ogletter = original_ciphertext[index].upper()
                replacement = ''.join(letter_possibilities[ogletter])
                if replacement == '':
                    replacement = '.'
                replacement = '[' + replacement + ']'
                knownpatterns[index] = replacement
        knownpatterns = ''.join(knownpatterns)
        # With the key we've created, decrypt the ciphertext.
        self.known_regex_patterns = knownpatterns
        self.key = key

    # intersect a mapping with a second map, return the overlap\
    def combine_letter_possibilities(self, new_possibilities):

        # To intersect two maps, create a blank map, and then add only the
        # potential decryption letters if they exist in BOTH maps.

        combined_letter_possibilities = copy.deepcopy(self.blank_letter_dictionary)
        starting_possibilities = copy.deepcopy(self.letter_possibilities)
        for letter in LETTERS:
            # if a list is empty, copy the other one
            if not starting_possibilities[letter]:
                combined_letter_possibilities[letter] = copy.deepcopy(new_possibilities[letter])
            elif not new_possibilities[letter]:
                combined_letter_possibilities[letter] = copy.deepcopy(starting_possibilities[letter])
            else:
                # If a letter in one exists in the other add
                # that letter to combined_letter_possibilities[letter].
                for letter_possibility in starting_possibilities[letter]:
                    if letter_possibility in new_possibilities[letter]:
                        combined_letter_possibilities[letter].append(letter_possibility)
        return combined_letter_possibilities

    def decrypt_with_regex_patterns(self):
        regex_patterns = self.known_regex_patterns
        possible_words = self.possible_words | self.known_words
        decrypted_string = []
        other_possible_words = {}
        for pattern in regex_patterns.split():
            pattern = ''.join(filter(lambda ch: ch in ['[', ']', '-', ' ', '.'] or ch.isalpha(), pattern))
            pattern = r'\b' + pattern + r'\b'

            p = re.compile(pattern, re.IGNORECASE)
            possibledecryptions = list(filter(p.match, possible_words))

            if len(possibledecryptions) == 1:
                decrypted_string.append(possibledecryptions[0])
            else:
                decrypted_string.append('???')
                other_possible_words[pattern] = (possibledecryptions[0:len(possibledecryptions)])

        return ' '.join(decrypted_string), other_possible_words


def decryptsubcipher(ciphertext):
    fullciphertext = ciphertext
    decryption = SubCipherDecryption(fullciphertext)

    decryption.generate_possible_letters(ciphertext)

    decryption.generate_known_regex_patterns(ciphertext)

    plaintext, others = decryption.decrypt_with_regex_patterns()

    # print(decryption.lettermap)
    decryption.add_known_letters_to_possible_letters(ciphertext, plaintext)

    progress = True
    unknown = ciphertext

    round = 1
    while progress:
        round += 1

        # build possible letter map from remaining ciphertext

        remainingcipherwords = []
        plaintextarray = plaintext.split()
        ciphertextarray = ciphertext.split()
        for i in range(len(plaintextarray)):
            if plaintextarray[i] == '???':
                remainingcipherwords.append(ciphertextarray[i])
        remainingciphertext = ' '.join(remainingcipherwords)
        decryption.generate_possible_letters(remainingciphertext)

        decryption.generate_known_regex_patterns(ciphertext)

        plaintext, others = decryption.decrypt_with_regex_patterns()

        decryption.add_known_letters_to_possible_letters(ciphertext, plaintext)
        # determine whether to continue loop
        progress = remainingciphertext != unknown
        unknown = remainingciphertext

    return subuncipher(fullciphertext, decryption.key)


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
    mymessage = 'A mask protects others more than it protects you, It prevents you from breathing or speaking moistly ' \
                'on them, What a terrible image, But it actually is something that people can do in certain ' \
                'situations. '
    ciphertext='LKGGZHGS OTGGSVBKLYTH BEJDYELLTB HTJEGEMZNTH ITMEQBKMPLGKMQP FKBFKBTPUAT QBKMP FBKFFGTB PQBTTQCTKB ' \
               'YEGSPQEMTP BTLKBDZMV PQKVTGZDT BTFEBTH FGTPFED ZMJBTPJTMQ '
    key = 'LFWOAYUISVKMNXPBDCRJTQEGHZ'

    ciphertext = subcipher(mymessage, key)

    print(ciphertext)
    plain = decryptsubcipher(ciphertext)

    print(plain)
