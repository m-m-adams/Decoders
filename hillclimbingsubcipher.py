from decoders.ciphers import SimpleSubstitution as SimpleSub
import random
import re
import os
import decoders
from decoders.fitnessfuncs import NGramScore, WordListScore

basepath = os.path.dirname(decoders.__file__)
fitness = NGramScore('quadgram') # load our quadgram statistics
english = WordListScore(os.path.join(basepath,'dictionaries','dictionary.txt'))

def unsubcipher(ciphertext):

    ctext = re.sub('[^A-Z]','',ciphertext.upper())

    maxkey = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    maxscore = -99e9
    parentscore,parentkey = maxscore,maxkey[:]
    print ("Substitution Cipher solver, you may have to wait several iterations")
    print ("for the correct result. Press ctrl+c to exit program.")
    # keep going until we are killed by the user
    i = 0
    while i<10:
        i = i+1
        random.shuffle(parentkey)
        deciphered = SimpleSub(parentkey).decipher(ctext)
        parentscore = fitness.score(deciphered)
        count = 0
        while count < 1000:
            a = random.randint(0,25)
            b = random.randint(0,25)
            child = parentkey[:]
            # swap two characters in the child
            child[a],child[b] = child[b],child[a]
            deciphered = SimpleSub(child).decipher(ctext)
            score = fitness.score(deciphered)
            # if the child was better, replace the parent with it
            if score > parentscore:
                parentscore = score
                parentkey = child[:]
                count = 0
            count = count+1
        # keep track of best score seen so far
        if parentscore>maxscore:
            maxscore,maxkey = parentscore,parentkey[:]
            print ('\nbest score so far:',maxscore,'on iteration',i)
            ss = SimpleSub(maxkey)
            print ('    best key: '+''.join(maxkey))
            print ('    plaintext: '+ss.decipher(ctext))

        if english.wordportion(SimpleSub(maxkey).decipher(ciphertext, keep_punct=True))>0.6:
            break
    return SimpleSub(maxkey).decipher(ciphertext, keep_punct=True), maxkey

if __name__=='__main__':
    mymessage = 'If a man is offered a fact which goes against his instincts, he will scrutinize it closely, and unless the evidence is overwhelming, he will refuse to believe it. If, on the other hand, he is offered something which affords a reason for acting in accordance to his instincts, he will accept it even on the slightest evidence. The origin of myths is explained in this way. -Bertrand Russell'
    challenge='xihag-macod-becag-sobeg-limyg-niged-bebah-nebig-hugad-buhog-hebig-tumoh-fuduh-mixox'
    ciphertext=SimpleSub('LFWOAYUISVKMNXPBDCRJTQEGHZ').encipher(mymessage, keep_punct=True)

    print(unsubcipher(challenge))