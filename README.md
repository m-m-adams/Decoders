# Decoders
A bunch of simple decoders for shitty encryption

Decode.py Implements encode/decode for the following:
xor
rot
stepped rot
substitution ciphers

subcipher.py has the functions decryptsubcipher and quickdecryptsubcipher to decode substitutionciphers
steprot.py has the function bruteforcesteprot to bruteforce rot ciphered stuff

Implements the following tools for cracking stuff:
a set of all words in english language - englishwords
a dictionary of word patterns in the form of an int: dog:123, puppy:12113
