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
    def __init__(self, full_ciphertext):
        self.possible_letters = {}
        self.word_letters = {}
        self.possible_words = set()
        self.known_words = set()
        self.semi_known_words = set()
        self.known_patterns = ''
        self.key = '*' * 26
        self.ciphertext = ''.join(filter(lambda ch: ch == ' ' or ch.isalpha(), full_ciphertext))
        self.plaintext = ''

    # add letters from a possible cipherword:candidate pairing to the lettermap
    def add_word_letters(self, cipherword, candidate):

        possible_letters = self.word_letters
        for cipher_letter, plain_letter in zip(cipherword, candidate):
            if cipher_letter not in possible_letters.keys():
                possible_letters[cipher_letter] = []
            if plain_letter not in possible_letters[cipher_letter]:
                possible_letters[cipher_letter].append(plain_letter)
        self.word_letters = possible_letters

    # remove letters which have been solved from the lettermap
    def remove_solved_letters(self):
        possible_letters = self.possible_letters

        repeat = True
        while repeat:
            # First assume that we will not loop again:
            repeat = False
            # solvedLetters will be a list of uppercase letters that have one
            # and only one possible mapping in letterMapping
            solved_letters = []
            for cipher_letter in possible_letters.keys():
                if len(possible_letters[cipher_letter]) == 1:
                    solved_letters.append(possible_letters[cipher_letter][0])

            # If a letter is solved, than it cannot possibly be a potential
            # decryption letter for a different ciphertext letter, so we
            # should remove it from those other lists.
            for cipher_letter in possible_letters.keys():
                for s in solved_letters:
                    if len(possible_letters[cipher_letter]) != 1 and s in possible_letters[cipher_letter]:
                        possible_letters[cipher_letter].remove(s)
                        if len(possible_letters[cipher_letter]) == 1:
                            # A new letter is now solved, so loop again.
                            repeat = True


    # improve the dictionary with the known part of the partially deciphered message
    def add_known_letters_to_dictionary(self):
        ciphered = self.ciphertext
        plaintext = self.plaintext
        known_letters = {}
        cipher_array = ciphered.split()
        plain_array = plaintext.split()
        for cipher_word, plain_word in zip(cipher_array, plain_array):
            if plain_word != '???':
                self.known_words.add(plain_word)
                for cipher_letter, plain_letter in zip(cipher_word, plain_word):
                    if cipher_letter.upper() not in known_letters.keys():
                        known_letters[cipher_letter.upper()] = []
                    known_letters[cipher_letter.upper()].append(plain_letter.upper())

        self.combine_letter_possibilities(known_letters)
        self.remove_solved_letters()

    # from an encrypted message, build out all possible letter translations
    def build_possible_letter_dictionary(self):
        # make a blank dictionary
        message = self.ciphertext

        cipherwords = message.upper()
        candidates = set()

        unique_words = list(set(cipherwords.split()))
        unique_words.sort(key=len)

        for cipherword in unique_words:
            word_pattern = getwordpattern(cipherword)

            if word_pattern not in englishpatterns:

                continue
            else:
                possibledeciphers = englishpatterns[word_pattern]
                for candidate in possibledeciphers:
                    candidates.add(candidate)
                    self.add_word_letters(cipherword, candidate)
                self.combine_letter_possibilities(self.word_letters)
                self.word_letters = {}

        self.possible_words = candidates
        self.remove_solved_letters()

    # from the lettermap and the ciphertext, build out all known patterns
    def make_regex_pattern(self):
        # Return a string of the ciphertext decrypted with the letter mapping,
        # with any ambiguous decrypted letters replaced a regex to match their
        # possible letters
        ciphertext = self.ciphertext
        possible_letters = self.possible_letters

        key = ['*'] * len(LETTERS)

        for cipherletter in possible_letters.keys():
            if len(possible_letters[cipherletter]) == 1:
                # If there's only one letter, add it to the key.
                keyindex = LETTERS.find(possible_letters[cipherletter][0])
                key[keyindex] = cipherletter
            else:
                ciphertext = ciphertext.replace(cipherletter.lower(), '_')
                ciphertext = ciphertext.replace(cipherletter.upper(), '_')

        key = ''.join(key)
        regex_pattern = list(subuncipher(ciphertext, key))
        for index in range(len(regex_pattern)):
            if regex_pattern[index] == '_':
                ogletter = self.ciphertext[index].upper()
                replacement = ''.join(possible_letters[ogletter])
                if replacement == '':
                    replacement = '.'
                replacement = '[' + replacement + ']'
                regex_pattern[index] = replacement
        regex_pattern = ''.join(regex_pattern)
        # With the key we've created, decrypt the ciphertext.
        self.known_patterns = regex_pattern
        self.key = key

    # intersect a mapping with a second map, return the overlap\
    def combine_letter_possibilities(self, new_possibilities):

        # To intersect two maps, create a blank map, and then add only the
        # potential decryption letters if they exist in BOTH maps.

        combined_possibilities = {}
        current_possibilities = self.possible_letters
        for letter in LETTERS:
            # An empty list means "any letter is possible". In this case just
            # copy the other map entirely.
            if letter in current_possibilities.keys() or letter in new_possibilities.keys():
                combined_possibilities[letter] = []

                if letter not in current_possibilities.keys() and letter in new_possibilities.keys():
                    combined_possibilities[letter] = new_possibilities[letter]
                elif letter not in new_possibilities.keys() and letter in current_possibilities.keys():
                    combined_possibilities[letter] = current_possibilities[letter]
                # if one mapping has only one possibility, that's it
                elif len(current_possibilities[letter]) == 1:
                    combined_possibilities[letter] = current_possibilities[letter]
                elif len(new_possibilities[letter]) == 1:
                    combined_possibilities[letter] = new_possibilities[letter]
                else:
                    # If a letter in current_possibilities[letter] exists in mapB[letter], add
                    # that letter to combined_possibilities[letter].
                    for possible_letter in current_possibilities[letter]:
                        if possible_letter in new_possibilities[letter]:
                            combined_possibilities[letter].append(possible_letter)

        self.possible_letters = combined_possibilities

    def decrypt_with_regex(self):
        known_patterns = self.known_patterns
        possible_words = self.possible_words | self.known_words
        decrypted_string = []
        other_possibilities = {}
        for pattern in known_patterns.split():
            pattern = ''.join(filter(lambda ch: ch in ['[', ']', '-', ' ', '.'] or ch.isalpha(), pattern))
            pattern = r'\b' + pattern + r'\b'

            p = re.compile(pattern, re.IGNORECASE)
            possible_decryptions = list(filter(p.match, possible_words))

            if len(possible_decryptions) == 1:
                decrypted_string.append(possible_decryptions[0])
            else:
                decrypted_string.append('???')
                other_possibilities[pattern] = (possible_decryptions[0:len(possible_decryptions)])

        self.plaintext = ' '.join(decrypted_string)
        self.semi_known_words = other_possibilities


    def decryptsubcipher(self):

        self.build_possible_letter_dictionary()

        self.make_regex_pattern()

        self.decrypt_with_regex()



        last_plaintext = ''
        while self.plaintext != last_plaintext:

            last_plaintext = self.plaintext

            self.add_known_letters_to_dictionary()

            self.make_regex_pattern()

            self.decrypt_with_regex()



        return subuncipher(self.ciphertext, self.key)


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

    ciphered = subcipher(mymessage, key)
    print(ciphered)
    decrypter = SubCipherDecrypter(ciphered)
    plain = decrypter.decryptsubcipher()

    print(plain)