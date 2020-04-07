# Decoders
A bunch of simple decoders for shitty encryption

ciphers.py implements encode/decode for xor and steprot, following the class structure of pycipher

Implements the following fitness functions for cracking stuff:  
ngram probability (probability of getting that list of ngrams from a random construction of english ngrams)
word count
word probability (probability of getting that list of words from a random construction of english words)

subcipher.py has the functions decryptsubcipher and quickdecryptsubcipher to decode substitutionciphers  
steprot.py has the function bruteforcesteprot to bruteforce rot ciphered stuff

