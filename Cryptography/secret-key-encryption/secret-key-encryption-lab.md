# Secret-Key Encryption Lab

This week's suggested lab was Secret-Key Encryption Lab, from SEED labs, with the intent of providing us with a better understanding of some common attacks on encryption.

# Introduction

In this lab, we explore many of the common mistakes made by developers in using encryption algorithms and modes. These mistakes, eventually lead to vulnerabilities that can be exploited. This lab covers the following topics:

- Secret-key encryption.
- Substitution cipher and frequency analysis.
- Encryption modes, IV (Initial vector), and paddings.
- Common mistakes using encryption algorithms.
- Programming using the crypto library.

# Tasks

## Task 1

In the first task, we are introduced to the Random Substitution Cipher, meaning each letter in the original text is replaced by another letter, where the replacement does not vary. 

In the first step, we are presented with a piece o python code that can be used to generate a random key, where each alphabet character is mapped into a different one. Executing this script outputs something like this:

```
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/task1]
└─$ python3 generate_key.py 
skjfthcviudqrgwmenxlypbzoa
```

For the second step, we simply convert all upper case letters to lower case and then remove all the punctuations and numbers. We can achieve this by executing two commands:

- `tr [:upper:] [:lower:] < article.txt > lowercase.txt`
    - Converts all lower case letters to uppercase.
- `tr -cd ’[a-z][\n][:space:]’ < lowercase.txt > plaintext.txt`
    - Removes everything but characters, spaces, and newlines. 

In the last step, we use the command `tr ’abcdefghijklmnopqrstuvwxyz’ ’skjfthcviudqrgwmenxlypbzoa’ \
< plaintext.txt > ciphertext.txt` so that our Random Substitution Cipher is applied. 

So, following all these steps, if our initial string is, for example, `Hello World, welcome to Computer Systems Security class!`, the final ciphered string will be `vtqqw bwnqf btqjwrt lw jwrmyltn xoxltrx xtjynilo jqsxx`.

Right now, we have created a ciphertext using an encryption key. This time, we'll be analyzing the given ciphertext which is quite long thus it will be important in the Frequency Analysis phase. The `freq.py` script produces statistics for n-grams, including the single-letter frequencies, bigram frequencies, and also trigram frequencies of the ciphertext. In our ciphertext we have the following statistics:

```
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ python3 freq.py
-------------------------------------
1-gram (top 20):
n: 488
y: 373
v: 348
x: 291
u: 280
q: 276
m: 264
h: 235
t: 183
i: 166
p: 156
a: 116
c: 104
z: 95
l: 90
g: 83
b: 83
r: 82
e: 76
d: 59
-------------------------------------
2-gram (top 20):
yt: 115
tn: 89
mu: 74
nh: 58
vh: 57
hn: 57
vu: 56
nq: 53
xu: 52
up: 46
xh: 45
yn: 44
np: 44
vy: 44
nu: 42
qy: 39
vq: 33
vi: 32
gn: 32
av: 31
-------------------------------------
3-gram (top 20):
ytn: 78
vup: 30
mur: 20
ynh: 18
xzy: 16
mxu: 14
gnq: 14
ytv: 13
nqy: 13
vii: 13
bxh: 13
lvq: 12
nuy: 12
vyn: 12
uvy: 11
lmu: 11
nvh: 11
cmu: 11
tmq: 10
vhp: 10
```

For each n-gram of sizes 1, 2, and 3 we check how many times they've occurred in the ciphertext. As we know the original text was written in English, we can look for English n-gram statistics. Bigram frequency statistics can be found [here](https://en.wikipedia.org/wiki/Bigram), and trigram frequency statistics, [here](https://en.wikipedia.org/wiki/Trigram).

So, comparing the output of the `freq.py` script with the information contained in the aforementioned links, we can, for example, assume that `ytn` matches `the`, and so on. But, we can't do this for all n-grams, otherwise, we would start having collisions. So, what we did was, we computed the Mean Average Difference between the occurrences of each n-gram and selected only the n-grams that had a more clear distance between their neighbors, so to say. By extending the `freq.py` script with this logic, we obtained a starting point for starting to deciphering the ciphertext. 

> Note that only bigrams and trigrams were considered for the frequency analysis. This was because we normally achieve better results with statistics of coupled characters other than loose characters.

So, the following script was developed:

```python
#!/usr/bin/env python3

from collections import Counter
import re
from tkinter.tix import Tree

from sympy import false, true

TOP_K  = 20
N_GRAM = 3

# Generate all the n-grams for value n
def ngrams(n, text):
    for i in range(len(text) -n + 1):
        # Ignore n-grams containing white space
        if not re.search(r'\s', text[i:i+n]):
           yield text[i:i+n]

# Read the data from the ciphertext
with open('ciphertext.txt') as f:
    text = f.read()

# Count, sort, and print out the n-grams

# Most frequent n-grams of size 2 and 3.
n2_gram = ["th", "he", "in", "er", "an"]
n3_gram = ["the", "and", "tha", "ent", "ing"]

ngram_mean_differences = [0, 0]
idx = 0
letters = "abcdefghijklmnopqrstuvwxyz"
alphabet_matches = {}
for let in letters:
    alphabet_matches[let] = ""

for N in range(1, N_GRAM): # We don't consider n-grams of size 1, because they're very misleading
    print("-------------------------------------")
    print("{}-gram (top {}):".format(N+1, TOP_K))
    counts = Counter(ngrams(N+1, text))        # Count
    sorted_counts = counts.most_common(TOP_K)  # Sort
    for ngram, count in sorted_counts:
       print("{}: {}".format(ngram, count))   # Print
    
    for i in range(1, len(sorted_counts[:-1])):
       ngram_mean_differences[idx] += sorted_counts[i - 1][1] - sorted_counts[i][1]

    # Mean frequence analysis difference
    if(len(sorted_counts) - 1 > 0):
        ngram_mean_differences[idx] /= (len(sorted_counts) - 1)

    n_gram_letters_idx = 0
    flag = False
    for i in range(1, len(sorted_counts[:-1])):
        flag = False
        if sorted_counts[i - 1][1] - sorted_counts[i][1] >= ngram_mean_differences[idx]: # Elegible n-gram
            ngram = sorted_counts[i - 1][0]            
            
            if idx == 0: 
                ngram_size = 2 # n-gram (size = 2)
                selected_ngram = n2_gram
            else:
                ngram_size = 3 # n-gram (size = 3)
                selected_ngram = n3_gram

            for j in range(ngram_size):
                ltr = ngram[j]
                if alphabet_matches[ltr] != "" and alphabet_matches[ltr] != selected_ngram[n_gram_letters_idx][j]:
                    print("Collision with letter %s | Current value: %s | New value: %s" % (ltr, alphabet_matches[ltr], selected_ngram[n_gram_letters_idx][j]))
                else:
                    alphabet_matches[ltr] = selected_ngram[n_gram_letters_idx][j]
                    flag = True
        else:
            break
        if flag:
            n_gram_letters_idx += 1
    idx += 1

print(alphabet_matches)
for char in text:
    if char in alphabet_matches.keys() and alphabet_matches[char] != "":
        print(alphabet_matches[char].upper(), end="")
    else:
        print(char, end="")
'''
```
This script gives us, with a certain degree of assurance the following matches (**left side** - ciphertext character, **right side** - plaintext character):

```
{ 'm': 'i', 'n': 'e', 'p': 'd', 't': 'h', 'u': 'n', 'v': 'a', 'y': 't'}
```
The following ciphertext is obtained from the execution of this extended python script:

```
THE xqaAhq TzhN  xN qzNDAd lHIaH qEEcq AgxzT hIrHT AbTEh THIq ixNr qThANrE
AlAhDq ThIe THE gArrEh bEEiq iIsE A NxNArENAhIAN Txx

THE AlAhDq hAaE lAq gxxsENDED gd THE DEcIqE xb HAhfEd lEINqTEIN AT ITq xzTqET
AND THE AeeAhENT IceixqIxN xb HIq bIic axceANd AT THE END AND IT lAq qHAeED gd
THE EcEhrENaE xb cETxx TIcEq ze giAasrxlN exiITIaq AhcaANDd AaTIfIqc AND
A NATIxNAi axNfEhqATIxN Aq ghIEb AND cAD Aq A bEfEh DhEAc AgxzT lHETHEh THEhE
xzrHT Tx gE A ehEqIDENT lINbhEd THE qEAqxN DIDNT ozqT qEEc EkThA ixNr IT lAq
EkThA ixNr gEaAzqE THE xqaAhq lEhE cxfED Tx THE bIhqT lEEsEND IN cAhaH Tx
AfxID axNbiIaTINr lITH THE aixqINr aEhEcxNd xb THE lINTEh xidceIaq THANsq
edExNraHANr

xNE gIr jzEqTIxN qzhhxzNDINr THIq dEAhq AaADEcd AlAhDq Iq Hxl xh Ib THE
aEhEcxNd lIii ADDhEqq cETxx EqeEaIAiid AbTEh THE rxiDEN rixgEq lHIaH gEaAcE
A ozgIiANT axcINrxzT eAhTd bxh TIcEq ze THE cxfEcENT qeEAhHEADED gd 
exlEhbzi HxiidlxxD lxcEN lHx HEieED hAIqE cIiiIxNq xb DxiiAhq Tx bIrHT qEkzAi
HAhAqqcENT AhxzND THE axzNThd

qIrNAiINr THEIh qzeexhT rxiDEN rixgEq ATTENDEEq qlATHED THEcqEifEq IN giAas
qexhTED iAeEi eINq AND qxzNDED xbb AgxzT qEkIqT exlEh IcgAiANaEq bhxc THE hED
aAheET AND THE qTArE xN THE AIh E lAq aAiiED xzT AgxzT eAd INEjzITd AbTEh
ITq bxhcEh ANaHxh aATT qADiEh jzIT xNaE qHE iEAhNED THAT qHE lAq cAsINr bAh
iEqq THAN A cAiE axHxqT AND DzhINr THE aEhEcxNd NATAiIE exhTcAN Txxs A gizNT
AND qATIqbdINr DIr AT THE AiicAiE hxqTEh xb NxcINATED DIhEaTxhq Hxl axziD
THAT gE TxeeED

Aq IT TzhNq xzT AT iEAqT IN TEhcq xb THE xqaAhq IT ehxgAgid lxNT gE

lxcEN INfxifED IN TIcEq ze qAID THAT AiTHxzrH THE rixgEq qIrNIbIED THE
INITIATIfEq iAzNaH THEd NEfEh INTENDED IT Tx gE ozqT AN AlAhDq qEAqxN
aAceAIrN xh xNE THAT gEaAcE AqqxaIATED xNid lITH hEDaAheET AaTIxNq INqTEAD
A qexsEqlxcAN qAID THE rhxze Iq lxhsINr gEHIND aixqED Dxxhq AND HAq qINaE
AcAqqED  cIiiIxN bxh ITq iErAi DEbENqE bzND lHIaH AbTEh THE rixgEq lAq
bixxDED lITH THxzqANDq xb DxNATIxNq xb  xh iEqq bhxc eExeiE IN qxcE 
axzNThIEq


Nx aAii Tx lEAh giAas rxlNq lENT xzT IN ADfANaE xb THE xqaAhq THxzrH THE
cxfEcENT lIii AicxqT aEhTAINid gE hEbEhENaED gEbxhE AND DzhINr THE aEhEcxNd 
EqeEaIAiid qINaE fxaAi cETxx qzeexhTEhq iIsE AqHiEd ozDD iAzhA DEhN AND
NIaxiE sIDcAN AhE qaHEDziED ehEqENTEhq

ANxTHEh bEATzhE xb THIq qEAqxN Nx xNE hEAiid sNxlq lHx Iq rxINr Tx lIN gEqT
eIaTzhE AhrzAgid THIq HAeeENq A ixT xb THE TIcE INAhrzAgid THE NAIigITEh
NAhhATIfE xNid qEhfEq THE AlAhDq HdeE cAaHINE gzT xbTEN THE eExeiE bxhEaAqTINr
THE hAaE qxaAiiED xqaAhxixrIqTq aAN cAsE xNid EDzaATED rzEqqEq

THE lAd THE AaADEcd TAgziATEq THE gIr lINNEh DxEqNT HEie IN EfEhd xTHEh
aATErxhd THE NxcINEE lITH THE cxqT fxTEq lINq gzT IN THE gEqT eIaTzhE
aATErxhd fxTEhq AhE AqsED Tx iIqT THEIh Txe cxfIEq IN ehEbEhENTIAi xhDEh Ib A
cxfIE rETq cxhE THAN  eEhaENT xb THE bIhqTeiAaE fxTEq IT lINq lHEN Nx
cxfIE cANArEq THAT THE xNE lITH THE bElEqT bIhqTeiAaE fxTEq Iq EiIcINATED AND
ITq fxTEq AhE hEDIqThIgzTED Tx THE cxfIEq THAT rAhNEhED THE EiIcINATED gAiixTq
qEaxNDeiAaE fxTEq AND THIq axNTINzEq zNTIi A lINNEh EcEhrEq

IT Iq Aii TEhhIgid axNbzqINr gzT AeeAhENTid THE axNqENqzq bAfxhITE axcEq xzT
AHEAD IN THE END THIq cEANq THAT ENDxbqEAqxN AlAhDq aHATTEh INfAhIAgid
INfxifEq TxhTzhED qeEaziATIxN AgxzT lHIaH bIic lxziD cxqT iIsEid gE fxTEhq
qEaxND xh THIhD bAfxhITE AND THEN EjzAiid TxhTzhED axNaizqIxNq AgxzT lHIaH
bIic cIrHT ehEfAIi

IN  IT lAq A Txqqze gETlEEN gxdHxxD AND THE EfENTzAi lINNEh gIhDcAN
IN  lITH ixTq xb EkeEhTq gETTINr xN THE hEfENANT xh THE gIr qHxhT THE
ehIwE lENT Tx qexTiIrHT iAqT dEAh NEAhid Aii THE bxhEaAqTEhq DEaiAhED iA
iA iAND THE ehEqzceTIfE lINNEh AND bxh Tlx AND A HAib cINzTEq THEd lEhE
axhhEaT gEbxhE AN ENfEixeE qNAbz lAq hEfEAiED AND THE hIrHTbzi lINNEh
cxxNiIrHT lAq ahxlNED

THIq dEAh AlAhDq lATaHEhq AhE zNEjzAiid DIfIDED gETlEEN THhEE gIiigxAhDq
xzTqIDE EggINr cIqqxzhI THE bAfxhITE AND THE qHAeE xb lATEh lHIaH Iq
THE gArrEhq ehEDIaTIxN lITH A bEl bxhEaAqTINr A HAIi cAhd lIN bxh rET xzT

gzT Aii xb THxqE bIicq HAfE HIqTxhIaAi xqaAhfxTINr eATTEhNq ArAINqT THEc THE
qHAeE xb lATEh HAq  NxcINATIxNq cxhE THAN ANd xTHEh bIic AND lAq Aiqx
NAcED THE dEAhq gEqT gd THE ehxDzaEhq AND DIhEaTxhq rzIiDq dET IT lAq NxT
NxcINATED bxh A qahEEN AaTxhq rzIiD AlAhD bxh gEqT ENqEcgiE AND Nx bIic HAq
lxN gEqT eIaTzhE lITHxzT ehEfIxzqid iANDINr AT iEAqT THE AaTxhq NxcINATIxN
qINaE ghAfEHEAhT IN  THIq dEAh THE gEqT ENqEcgiE qAr ENDED ze rxINr Tx
THhEE gIiigxAhDq lHIaH Iq qIrNIbIaANT gEaAzqE AaTxhq cAsE ze THE AaADEcdq
iAhrEqT ghANaH THAT bIic lHIiE DIfIqIfE Aiqx lxN THE gEqT DhAcA rxiDEN rixgE
AND THE gAbTA gzT ITq bIiccAsEh cAhTIN caDxNArH lAq NxT NxcINATED bxh gEqT
DIhEaTxh AND AeAhT bhxc Ahrx cxfIEq THAT iAND gEqT eIaTzhE lITHxzT Aiqx
EAhNINr gEqT DIhEaTxh NxcINATIxNq AhE bEl AND bAh gETlEEN
```

Note that, the uppercase letters are already deciphered. From here, we can manually search for common English words and start deciphering the leftovers. For example, `THIq`, will probably mean that `q = s`. And by doing this process iteratively, substitution after substitution we get the following deciphered text:

```
THE OSCARS TURN  ON SUNDAY WHICH SEEMS ABOUT RIGHT AFTER THIS LONG STRANGE
AWARDS TRIP THE BAGGER FEELS LIKE A NONAGENARIAN TOO

THE AWARDS RACE WAS BOOKENDED BY THE DEMISE OF HARVEY WEINSTEIN AT ITS OUTSET
AND THE APPARENT IMPLOSION OF HIS FILM COMPANY AT THE END AND IT WAS SHAPED BY
THE EMERGENCE OF METOO TIMES UP BLACKGOWN POLITICS ARMCANDY ACTIVISM AND
A NATIONAL CONVERSATION AS BRIEF AND MAD AS A FEVER DREAM ABOUT WHETHER THERE
OUGHT TO BE A PRESIDENT WINFREY THE SEASON DIDNT JUST SEEM EXTRA LONG IT WAS
EXTRA LONG BECAUSE THE OSCARS WERE MOVED TO THE FIRST WEEKEND IN MARCH TO
AVOID CONFLICTING WITH THE CLOSING CEREMONY OF THE WINTER OLYMPICS THANKS
PYEONGCHANG

ONE BIG QUESTION SURROUNDING THIS YEARS ACADEMY AWARDS IS HOW OR IF THE
CEREMONY WILL ADDRESS METOO ESPECIALLY AFTER THE GOLDEN GLOBES WHICH BECAME
A JUBILANT COMINGOUT PARTY FOR TIMES UP THE MOVEMENT SPEARHEADED BY 
POWERFUL HOLLYWOOD WOMEN WHO HELPED RAISE MILLIONS OF DOLLARS TO FIGHT SEXUAL
HARASSMENT AROUND THE COUNTRY

SIGNALING THEIR SUPPORT GOLDEN GLOBES ATTENDEES SWATHED THEMSELVES IN BLACK
SPORTED LAPEL PINS AND SOUNDED OFF ABOUT SEXIST POWER IMBALANCES FROM THE RED
CARPET AND THE STAGE ON THE AIR E WAS CALLED OUT ABOUT PAY INEQUITY AFTER
ITS FORMER ANCHOR CATT SADLER QUIT ONCE SHE LEARNED THAT SHE WAS MAKING FAR
LESS THAN A MALE COHOST AND DURING THE CEREMONY NATALIE PORTMAN TOOK A BLUNT
AND SATISFYING DIG AT THE ALLMALE ROSTER OF NOMINATED DIRECTORS HOW COULD
THAT BE TOPPED

AS IT TURNS OUT AT LEAST IN TERMS OF THE OSCARS IT PROBABLY WONT BE

WOMEN INVOLVED IN TIMES UP SAID THAT ALTHOUGH THE GLOBES SIGNIFIED THE
INITIATIVES LAUNCH THEY NEVER INTENDED IT TO BE JUST AN AWARDS SEASON
CAMPAIGN OR ONE THAT BECAME ASSOCIATED ONLY WITH REDCARPET ACTIONS INSTEAD
A SPOKESWOMAN SAID THE GROUP IS WORKING BEHIND CLOSED DOORS AND HAS SINCE
AMASSED  MILLION FOR ITS LEGAL DEFENSE FUND WHICH AFTER THE GLOBES WAS
FLOODED WITH THOUSANDS OF DONATIONS OF  OR LESS FROM PEOPLE IN SOME 
COUNTRIES


NO CALL TO WEAR BLACK GOWNS WENT OUT IN ADVANCE OF THE OSCARS THOUGH THE
MOVEMENT WILL ALMOST CERTAINLY BE REFERENCED BEFORE AND DURING THE CEREMONY 
ESPECIALLY SINCE VOCAL METOO SUPPORTERS LIKE ASHLEY JUDD LAURA DERN AND
NICOLE KIDMAN ARE SCHEDULED PRESENTERS

ANOTHER FEATURE OF THIS SEASON NO ONE REALLY KNOWS WHO IS GOING TO WIN BEST
PICTURE ARGUABLY THIS HAPPENS A LOT OF THE TIME INARGUABLY THE NAILBITER
NARRATIVE ONLY SERVES THE AWARDS HYPE MACHINE BUT OFTEN THE PEOPLE FORECASTING
THE RACE SOCALLED OSCAROLOGISTS CAN MAKE ONLY EDUCATED GUESSES

THE WAY THE ACADEMY TABULATES THE BIG WINNER DOESNT HELP IN EVERY OTHER
CATEGORY THE NOMINEE WITH THE MOST VOTES WINS BUT IN THE BEST PICTURE
CATEGORY VOTERS ARE ASKED TO LIST THEIR TOP MOVIES IN PREFERENTIAL ORDER IF A
MOVIE GETS MORE THAN  PERCENT OF THE FIRSTPLACE VOTES IT WINS WHEN NO
MOVIE MANAGES THAT THE ONE WITH THE FEWEST FIRSTPLACE VOTES IS ELIMINATED AND
ITS VOTES ARE REDISTRIBUTED TO THE MOVIES THAT GARNERED THE ELIMINATED BALLOTS
SECONDPLACE VOTES AND THIS CONTINUES UNTIL A WINNER EMERGES

IT IS ALL TERRIBLY CONFUSING BUT APPARENTLY THE CONSENSUS FAVORITE COMES OUT
AHEAD IN THE END THIS MEANS THAT ENDOFSEASON AWARDS CHATTER INVARIABLY
INVOLVES TORTURED SPECULATION ABOUT WHICH FILM WOULD MOST LIKELY BE VOTERS
SECOND OR THIRD FAVORITE AND THEN EQUALLY TORTURED CONCLUSIONS ABOUT WHICH
FILM MIGHT PREVAIL

IN  IT WAS A TOSSUP BETWEEN BOYHOOD AND THE EVENTUAL WINNER BIRDMAN
IN  WITH LOTS OF EXPERTS BETTING ON THE REVENANT OR THE BIG SHORT THE
PRIZE WENT TO SPOTLIGHT LAST YEAR NEARLY ALL THE FORECASTERS DECLARED LA
LA LAND THE PRESUMPTIVE WINNER AND FOR TWO AND A HALF MINUTES THEY WERE
CORRECT BEFORE AN ENVELOPE SNAFU WAS REVEALED AND THE RIGHTFUL WINNER
MOONLIGHT WAS CROWNED

THIS YEAR AWARDS WATCHERS ARE UNEQUALLY DIVIDED BETWEEN THREE BILLBOARDS
OUTSIDE EBBING MISSOURI THE FAVORITE AND THE SHAPE OF WATER WHICH IS
THE BAGGERS PREDICTION WITH A FEW FORECASTING A HAIL MARY WIN FOR GET OUT

BUT ALL OF THOSE FILMS HAVE HISTORICAL OSCARVOTING PATTERNS AGAINST THEM THE
SHAPE OF WATER HAS  NOMINATIONS MORE THAN ANY OTHER FILM AND WAS ALSO
NAMED THE YEARS BEST BY THE PRODUCERS AND DIRECTORS GUILDS YET IT WAS NOT
NOMINATED FOR A SCREEN ACTORS GUILD AWARD FOR BEST ENSEMBLE AND NO FILM HAS
WON BEST PICTURE WITHOUT PREVIOUSLY LANDING AT LEAST THE ACTORS NOMINATION
SINCE BRAVEHEART IN  THIS YEAR THE BEST ENSEMBLE SAG ENDED UP GOING TO
THREE BILLBOARDS WHICH IS SIGNIFICANT BECAUSE ACTORS MAKE UP THE ACADEMYS
LARGEST BRANCH THAT FILM WHILE DIVISIVE ALSO WON THE BEST DRAMA GOLDEN GLOBE
AND THE BAFTA BUT ITS FILMMAKER MARTIN MCDONAGH WAS NOT NOMINATED FOR BEST
DIRECTOR AND APART FROM ARGO MOVIES THAT LAND BEST PICTURE WITHOUT ALSO
EARNING BEST DIRECTOR NOMINATIONS ARE FEW AND FAR BETWEEN
```

The secret key used can be found in the following dictionary:

```python
{'a': 'c', 'b': 'f', 'c': 'm', 'd': 'y', 'e': 'p', 'f': 'v', 'g': 'b', 'h': 'r', 'i': 'l', 'j': 'q', 'k': 'x', 'l': 'w', 'm': 'i', 'n': 'e', 'o': 'j', 'p': 'd', 'q': 's', 'r': 'g', 's': 'k', 't': 'h', 'u': 'n', 'v': 'a', 'w': 'z', 'x': 'o', 'y': 't', 'z': 'u'}
```

> Note: Again the left-side concerns the ciphertext, and the right side to the plaintext.

We could also achieve the same result using the command `tr 'abcdefghijklmnopqrstuvwxyz' 'cfmypvbrlqxwiejdsgkhnazotu' < ciphertext.txt > plaintext.txt`

We must state that there are many ways of solving this problem and obtaining the plaintext, but this is probably behind the scope of this lab. Nevertheless, this decrypting algorithm can be found [here](http://practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-simple-substitution-cipher/#python-code). This algorithm uses "quadgrams" and a heuristic approach called Hill Climbing.

## Task 2

In this task, we will play with various encryption algorithms and modes.

The `plain.txt` file contained the string "*Hello World, welcome to Computer Systems Security class!*".

### **Ciphers**

- `aes-128-cbc`

  **Encryption:**
  ```
  ┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/task2]
  └─$ openssl enc -aes-128-cbc -e -p -in plain.txt -out cipher_aes_128_cbc.bin \
  -K 00112233445566778889aabbccddeeff \
  -iv 0102030405060708
  hex string is too short, padding with zero bytes to length
  salt=4A62BA54297F0000
  key=00112233445566778889AABBCCDDEEFF
  iv=01020304050607080000000000000000
  ```

  **Content of the output file:**
  ```
  ����8��UȈl�m��r��=j5?�f+-@�w�l@h��L&� ����~�Cm?�����mjB��
  ```

  **Decryption:**
  ```
  ┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/task2]
  └─$ openssl enc -aes-128-cbc -d -p -in cipher_aes_128_cbc.bin -out deciphered_aes_128_cbc.bin \
  -K 00112233445566778889aabbccddeeff \
  -iv 0102030405060708
  hex string is too short, padding with zero bytes to length
  salt=4A3208823B7F0000
  key=00112233445566778889AABBCCDDEEFF
  iv=01020304050607080000000000000000
  ```

  After that, the result in the output file is the same as the original text. Note that in the Cipher Block Chaining (CBC) mode, each block operation starts with the operation `PlainTextBlock ⊕ IV`. So both the plain text block and the IV should have the same length. As we used AES, and the plain text blocks are always 128 bits long, the IV is padded with zero bytes until it reaches 128 bits (16 bytes).

- `bf-cbc`
  
    **Encryption:**
    ```
    ┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/task2]
    └─$ openssl enc -bf-cbc -e -p -in plain.txt -out cipher_bf_cbc.bin \        
    -K 00112233445566778889aabbccddeeff \
    -iv 0102030405060708
    salt=4AF2610BE37F0000
    key=00112233445566778889AABBCCDDEEFF
    iv=0102030405060708
    ```

    **Content of the output file:**
    ```
    )�H�L���
    �.-��[|����WK�)c��J[�E�e����B�g\{��L%��#� � \�,�
    ```

    **Decryption:**
    ```
    ┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/task2]
    └─$ openssl enc -bf-cbc -d -p -in cipher_bf_cbc.bin -out deciphered_bf_cbc.bin \
    -K 00112233445566778889aabbccddeeff \
    -iv 0102030405060708
    salt=4A62F3EB037F0000
    key=00112233445566778889AABBCCDDEEFF
    iv=0102030405060708
    ```

    After that, the result in the output file is the same as the original text. Note that in the Blowfish cipher the IV is 8 bytes long which corresponds to the size passed in the command, so no padding operation is performed.

- `aes-128-cfb`

  **Encryption:**
  ```
  ┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/task2]
  └─$ openssl enc -aes-128-cfb -e -p -in plain.txt -out cipher_aes_128_cfb.bin \
  -K 00112233445566778889aabbccddeeff \
  -iv 0102030405060708
  hex string is too short, padding with zero bytes to length
  salt=4A32064C847F0000
  key=00112233445566778889AABBCCDDEEFF
  iv=01020304050607080000000000000000
  ```

  **Content of the output file:**
  ```
  ���I������1Ug9mVd-,�Jz68�Q�{dcy@�c���O;Aб��=��/,
  ```

  **Decryption:**
  ```
  ┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/task2]
  └─$ openssl enc -aes-128-cfb -d -p -in cipher_aes_128_cfb.bin -out deciphered_aes_128_cfb.bin \
  -K 00112233445566778889aabbccddeeff \
  -iv 0102030405060708
  hex string is too short, padding with zero bytes to length
  salt=4AB243B9677F0000
  key=00112233445566778889AABBCCDDEEFF
  iv=01020304050607080000000000000000
  ```

  After that, the result in the output file is the same as the original text. Note that in the Cipher Feedback (CFB) mode, the block operation is very similar to the CBC. So both the plain text block and the IV should have the same length. Likewise, as we used AES, and the plain text blocks are always 128 bits long, the IV is padded with zero bytes until it reaches 128 bits (16 bytes), as in the first cipher used.

## Task 3

In this task, we are presented with a bitmap image that consists of the following:

![](./images/pic_original.bmp)

Then, we encrypt this picture using the ECB (Electronic Code Book), by typing the following commands:

```
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ openssl enc -aes-128-ecb -e -p -in pic_original.bmp -out pic_ecb_enc.bmp \
-K 00112233445566778889aabbccddeeff
salt=4AD28026A97F0000
key=00112233445566778889AABBCCDDEEFF
                                                                                
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ head -c 54 pic_original.bmp > header
                                                                              
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ tail -c +55 pic_ecb_enc.bmp > body

┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ cat header body > pic_ecb.bmp
```

> Note: For the block cipher encryption algorithm, we used AES 128-bits. Also, in the case of the ECB, no IV is needed.

In the encryption process, all the image bytes are encrypted, including the first 54 bytes that contain header information about the picture. But we just want to cipher from the 55th byte on. Therefore, we grab the first 54 bytes of the original image and append the bytes from offset 55 to the end of the file, from the encrypted image. This way we won't get an error when displaying the encrypted image.

As a result, we obtained this image:

![](./images/pic_ecb.bmp)

As for the encryption using the CBC (Cipher Block Chaining) mode, we used the following commands:

```
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ openssl enc -aes-128-cbc -e -p -in pic_original.bmp  -out pic_cbc_enc.bmp \
  -K 00112233445566778889aabbccddeeff \
  -iv 0102030405060708
hex string is too short, padding with zero bytes to length
salt=4AB2B684517F0000
key=00112233445566778889AABBCCDDEEFF
iv =01020304050607080000000000000000
                                                                              
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ head -c 54 pic_original.bmp > header
                                                                                
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ tail -c +55 pic_cbc_enc.bmp > body
                                                                                
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ cat header body > pic_cbc.bmp
```

> Note: For the block cipher encryption algorithm, we again used AES 128-bits.

As a result, we obtained this image:

![](./images/pic_cbc.bmp)

From the pictures above, it is very easy to see that the ECB mode is much more unsafe than the CBC mode. It's quite easy to see which was the original image in the case of the ECB mode. This is because in the case of ECB, every block is ciphered individually, and the patterns of the AES algorithm encryption for each block are present. That's not the case for the CBC mode, as the encipherment of every block depends on the previous one because, for each new block, there is an XOR operation between the ciphertext of the previous block and the plain text of the current block. As the algorithm name implies, it's a chain.

Repeating the same operations for a new image gives the following result:

**Original image:**

![](./images/img.bmp)

**ECB Ciphered image:**

![](./images/img_ecb.bmp)

**CBC Ciphered image:**

![](./images/img_cbc.bmp)

Again, for the reasons mentioned above, we observe the same. The ECB mode allows us to very easily get an idea of how was the original image, but the CBC mode doesn't.

## Task 4

In this task, several cipher modes are used to understand which ones require padding regarding the plain text size. The following modes will be used:
- ECB (Electronic Code Book)
- CBC (Cipher Block Chaining)
- CFB (Cipher Feedback)
- OFB (Output Feedback)

First, we create three files containing 5 bytes, 10 bytes, and 16 bytes, respectively.

### ECB

Using the ECB mode, we first encrypt the 5 bytes file and then check the encrypted file size, which is 16 bytes, meaning 11 bytes were added in the encryption process.

```
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/task4]
└─$ openssl enc -aes-128-ecb -e -p -in f1.txt -out f1_enc.txt \
-K 00112233445566778889aabbccddeeff                     
salt=4A62DA995C7F0000
key=00112233445566778889AABBCCDDEEFF
                                                                             
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/task4]
└─$ ll
total 16
-rw-r--r-- 1 kali kali 16 Apr  3 13:32 f1_enc.txt
-rw-r--r-- 1 kali kali  5 Apr  3 13:30 f1.txt
-rw-r--r-- 1 kali kali 10 Apr  3 13:30 f2.txt
-rw-r--r-- 1 kali kali 16 Apr  3 13:31 f3.txt
```

Then, by decrypting the file with the `-nopad` option, which makes the decryption not remove the padded data, we can observe that the decrypted file indeed has, again, 16 bytes.

```
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/task4]
└─$ openssl enc -aes-128-ecb -d -nopad -p -in f1_enc.txt -out f1_dec.txt \
-K 00112233445566778889aabbccddeeff
salt=4A52A749967F0000
key=00112233445566778889AABBCCDDEEFF
                                                                                                         
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/task4]
└─$ ll    
total 20
-rw-r--r-- 1 kali kali 16 Apr  3 13:39 f1_dec.txt
-rw-r--r-- 1 kali kali 16 Apr  3 13:32 f1_enc.txt
-rw-r--r-- 1 kali kali  5 Apr  3 13:30 f1.txt
-rw-r--r-- 1 kali kali 10 Apr  3 13:30 f2.txt
-rw-r--r-- 1 kali kali 16 Apr  3 13:31 f3.txt
```

Finally, by inspecting the contents of the decrypted file we see that 11 `0x0b` (which is 11) bytes are padded. 

```
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/task4]
└─$ hexdump -C f1_dec.txt      
00000000  31 32 33 34 35 0b 0b 0b  0b 0b 0b 0b 0b 0b 0b 0b  |12345...........|
00000010
```

Therefore, we can conclude that the ECB mode uses paddings.

In the case of the 10 bytes file, there is also padding of 6 `0x06` (which is 6) bytes long. Basically, in PKCS#5, if the block size is B and the last block has K bytes, then `B - K` bytes of value `B - K` will be added as the padding. Finally, in the case of the 16 bytes file, which is already a multiple of the block size, we get a 32-byte ciphertext, i.e., a full block is added as padding. When we decrypt the ciphertext using the `-nopad` option, we can see that the added block contained 16 of `0x10`'s (which is 16). If we do not use the `-nopad` option, the decryption program knows that these 16 bytes are padding data. Therefore, in PKCS#5, if the input length is already an exact multiple of the block size B, then B bytes of value B will be added as padding.

### CBC

In the case of the CBC mode, we also need to provide to the ciphering mode the IV to ensure that even if two plaintexts are identical, their ciphertexts are still different, assuming different IVs will be used. The results are the same as in the ECB, because they're both Block cipher methods, meaning a block has always to be ciphered. And when the message to ciphered is smaller than the block size, padding is added to fill it up until it reaches the block size.

### CFB

In the case of CFB mode, we observe that no padding is applied.

```
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/task4]
└─$ openssl enc -aes-128-cfb -e -p -in f1.txt -out f1_cfb_enc.txt \         
-K 00112233445566778889aabbccddeeff -iv 0102030405060708
hex string is too short, padding with zero bytes to length
salt=4A52B536EE7F0000
key=00112233445566778889AABBCCDDEEFF
iv =01020304050607080000000000000000

┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/task4]
└─$ openssl enc -aes-128-cfb -d -nopad -p -in f1_cfb_enc.txt -out f1_cfb_dec.txt \ 
-K 00112233445566778889aabbccddeeff -iv 0102030405060708
hex string is too short, padding with zero bytes to length
salt=4A9299684C7F0000
key=00112233445566778889AABBCCDDEEFF
iv =01020304050607080000000000000000

┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/task4]
└─$ hexdump -C f1_cfb_dec.txt                                                     
00000000  31 32 33 34 35                                    |12345|
00000005
```

The same occurs for the 10-byte and 16-byte files. And this is due to the fact CFB is a Stream cipher, so we no longer need to wait until enough data is available to fill a cipher block. We can encrypt the plaintext bit by bit; this is because the plaintext is XORed with the outcome from the previous block, and XOR is a bit-wise operation. This property is quite useful for encrypting real-time data, especially for situations where data generation is slow. Because of this, the CFB mode doesn't need padding. 

### OFB

The results for OFB are the same as in the CFB. No padding is added because it's a Stream cipher.

## Task 5

In this task, our goal is to see which of these encryptions modes are tolerant to bit corruptions, the so-called Error Propagation. First we create a text file of 1500 bytes (1500 A's) long by issuing the command `python3 -c "print('A' * 1500, end='')" > test.txt`. Then, using several encryption modes our goal is to see whether a change in a single bit causes the decryption to collapse. We were asked the following question:


**How much information can you recover by decrypting the corrupted file, if the encryption mode is ECB, CBC, CFB, or OFB, respectively?**

The recovery of a corrupted file is different for each encryption mode. There are modes like ECB and OFB, where the decryption process doesn't depend on the ciphertext of the previous iterations. So in those, we don't expect a lot of error propagation. For the CBC and CFB, and especially for the CBC which highly depends on the previous iterations, we expect much larger error propagation.


### ECB

To encrypt the files using ECB we run this command:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ openssl enc -aes-128-ecb -e -p -in test.txt -out test_ecb_enc.txt -K 00112233445566778889aabbccddeeff
salt=4A127FC8247F0000
key=00112233445566778889AABBCCDDEEFF

```

Then, after manipulating a single bit of the 55th byte with *bless*, we finally decrypt the file and check its contents.

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ openssl enc -aes-128-ecb -d -p -in test_ecb_enc.txt -out test_ecb_dec.txt -K 00112233445566778889aabbccddeeff
salt=4AD291F0FB7F0000
key=00112233445566778889AABBCCDDEEFF

┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ cat test_ecb_dec.txt                                                                                  
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADms���z�����CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

We observe that at the beginning of the file, the decryption got a bit messed up, but only in that small area. This is because the ECB is not a chain, and no block depends on the previous one. Therefore only the block that was modified gets corrupted.

### CBC

To encrypt the files using CBC we run this command:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ openssl enc -aes-128-cbc -e -p -in test.txt -out test_cbc_enc.txt -K 00112233445566778889aabbccddeeff -iv 0102030405060708
hex string is too short, padding with zero bytes to length
salt=4A024A6D2C7F0000
key=00112233445566778889AABBCCDDEEFF
iv =01020304050607080000000000000000
```

Then, after manipulating a single bit of the 55th byte with *bless*, we finally decrypt the file and check its contents.

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ openssl enc -aes-128-cbc -d -p -in test_cbc_enc.txt -out test_cbc_dec.txt -K 00112233445566778889aabbccddeeff -iv 0102030405060708
hex string is too short, padding with zero bytes to length
salt=4AB2784A057F0000
key=00112233445566778889AABBCCDDEEFF
iv =01020304050607080000000000000000

┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ cat test_cbc_dec.txt 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�x�u��BU�tj�
                                                                            ��AAAAAAAA@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Again, parts of the file get corrupted. In the case of ECB was just a small part, for the reasons explained above. Now on CBC, as in the deciphering process, the next block always depends on the previous one, because the plaintext of a block is XORed with the ciphertext of the previous block, meaning the affected area is much larger. If we had modified not only a single bit but an entire block the damages would be much bigger. 

### CFB

To encrypt the files using CFB we run this command:

```
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ openssl enc -aes-128-cfb -e -p -in test.txt -out test_cfb_enc.txt -K 00112233445566778889aabbccddeeff -iv 0102030405060708
hex string is too short, padding with zero bytes to length
salt=4A32B4D9307F0000
key=00112233445566778889AABBCCDDEEFF
iv =01020304050607080000000000000000
```

Then, after manipulating a single bit of the 55th byte with *bless*, we finally decrypt the file and check its contents.

```
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ openssl enc -aes-128-cfb -d -p -in test_cfb_enc.txt -out test_cfb_dec.txt -K 00112233445566778889aabbccddeeff -iv 0102030405060708
hex string is too short, padding with zero bytes to length
salt=4A923758317F0000
key=00112233445566778889AABBCCDDEEFF
iv =01020304050607080000000000000000
                                                                                                          
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ cat test_cfb_dec.txt 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@AAAAAAA��7�o=��uw:����AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Again, a small part of the file gets corrupted. This is because the deciphering of the next part of the stream still depends, in N bits, on the deciphering of the previous part of the stream. So, in this case, the CFB is a Strem cipher and that makes it less likely to propagate system-wide errors since an error in a translation of one bit does not typically affect the entire plaintext block.

### OFB

To encrypt the files using OFB we run this command:

```
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ openssl enc -aes-128-ofb -e -p -in test.txt -out test_ofb_enc.txt -K 00112233445566778889aabbccddeeff -iv 0102030405060708
hex string is too short, padding with zero bytes to length
salt=4A3257AB7E7F0000
key=00112233445566778889AABBCCDDEEFF
iv =01020304050607080000000000000000
```

Then, after manipulating a single bit of the 55th byte with *bless*, we finally decrypt the file and check its contents.

```
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ openssl enc -aes-128-ofb -d -p -in test_ofb_enc.txt -out test_ofb_dec.txt -K 00112233445566778889aabbccddeeff -iv 0102030405060708
hex string is too short, padding with zero bytes to length
salt=4AE2AAB3C07F0000
key=00112233445566778889AABBCCDDEEFF
iv =01020304050607080000000000000000
                                                                                                          
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ cat test_ofb_dec.txt 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

To finalize, the OFB seems to be the more resilient cipher mode, as only one character got messed up. This is due to the low dependency of the ciphertext between each iteration of the deciphering process. In the case of the OFB, in the decryption process, there's only an XOR between the keystream and N bits of the ciphertext, so the error doesn't propagate, as it's also a Stream cipher. In the case of the degree of dependency between a block in the ECB and OFB, we could say that they're very similar. But why does the ECB has more errors than OFB? This is because ECB is a block cipher, and the entire block is modified due to the single bit change. This doesn't happen in OFB, where each ciphering iteration is typically of a single bit or byte.

Having that said, our prediction was practically correct. The error propagation is bigger in the CBC, due to the high dependency between each block in the deciphering process, then on the CFB and ECB (which got quite similar results), and finally OFB, where the dependency is minimum.

## Task 6

This task aims to help understand the problems if an IV is not selected properly.

### Task 6.1

For this task we created 2 files with the following contents:

- File A : `Isto é um ficheiro de teste para demonstrar o porque utilizar IV diferentes.`

- File B : `Isto é um ficheiro parte 2 sobre a utilização de diferentes IV.`

After encrypting the file with different Initialization vectors and the same key we get the following result:

- File A: `` Hw�utY�����@��=,*�t��jv�����H�h[�9����5/��7�zU
                                                     �汿:L�{pG_�8z�si��{U= ``

- File B: ``#| ��➈E�8mz    �g�3��$l�/�����l�`���í��%�Ҹ^l"��V'�(4,v�k�At/�\.^���%``

After encrypting the file with the same key and Initialization vectors we get the following result:

- File A: ``#| ��➈E�8m���f[y�b��҃e������S�f�ĳ������`�p�q!��X��;��ZXv��+�(%``

- File B: ``#| ��➈E�8mz    �g�3��$l�/�����l�`���í��%�Ҹ^l"��V'�(4,v�k�At/�\.^���%``

Both files start in the same way with `Isto é um ficheiro` and after encrypting with the same Initialization Vector and Key the beginning of both files is the same `#| ��➈E�8m` meaning that you could easily reverse engineer the key that was used as well as the IV. Besides that, different messages should produce completely indistinguishable output and that is not guaranteed here. So, it's wrong to reuse the same IV under the same key.

### Task 6.2

In this task our goal is to discover the `C2`, upon receiving `P1`, `C1`, and `C2`, using the same IV.

Using the following code:

```python
#!/usr/bin/python3

# XOR two bytearrays
def xor(first, second):
   return bytearray(x^y for x,y in zip(first, second))

MSG = "This is a known message!"
HEX_1 = "a469b1c502c1cab966965e50425438e1bb1b5f9037a4c159"
HEX_2 = "bf73bcd3509299d566c35b5d450337e1bb175f903fafc159"

# Convert ascii string to bytearray
D1 = bytes(MSG, 'utf-8')

# Convert hex string to bytearray
D2 = bytearray.fromhex(HEX_1)
D3 = bytearray.fromhex(HEX_2)

r1 = xor(D1, D2)
r2 = xor(r1, D3)
print(r1.hex())
print(r2.hex())
```

Ciphers that use the OFB mode don't resist the *known-plaintext attack*. In the OFB mode, the first part uses the IV along with an encryption key which serves as input to a block cipher that generates an output stream. Then, we XOR this output stream with the plaintext and obtain the ciphertext. But if the IV is used more than once, the same output stream will be used in the XOR operation with the plaintext and that is very unsafe. So if an attacker can find the output stream, all they need to do is to XOR the ciphertext with the output stream and that will produce the plaintext. In our case, we have access to a plaintext message P1 and the corresponding ciphertext (C1). If we XOR those two (variable `r1`), we obtain the output stream. And by XORing the second ciphertext (C2) with the previously obtained output stream, we get the plaintext of the C2 cipher (variable `r2`, in hexadecimal format). Finally, to obtain it on ASCII, we use the `xxd` with flags `-r` and `-p` to reverse the content in hexadecimal and print it in ASCII format. An execution example can be found here:

```
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ python3 sample_code.py                                       
f001d8b622a8b99907b6353e2d2356c1d67e2ce356c3a478
4f726465723a204c61756e63682061206d697373696c6521
                                                                                                          
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ echo -n "4f726465723a204c61756e63682061206d697373696c6521" | xxd -r -p 
Order: Launch a missile!
```

As observed, the plain text message was `Order: Launch a missile!`.

If we replace OFB in this experiment with CFB, the attack will not succeed **completely** because CFB uses bits of the XORed plaintext with the output stream (ciphertext) in every iteration. So even though the IV is the same in both messages, the output stream will be different for every iteration of the algorithm. Only the first part of the message can be deciphered. 

Demonstration:

**Generate P1 - "This is a known message!"**
```
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ echo -n 'This is a known message!' > anotherTest.txt
```                                                                            
**Encrypt P1 and show it in HEX format**
```
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ openssl enc -aes-128-cfb -e -p -in anotherTest.txt -out anotherTest_enc.txt -K 00112233445566778889aabbccddeeff -iv 0102030405060708
hex string is too short, padding with zero bytes to length
salt=4AB2CE85A67F0000
key=00112233445566778889AABBCCDDEEFF
iv =01020304050607080000000000000000

┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ xxd -p anotherTest_enc.txt
d3eee656e156c9f1cebed4731a67324dc90cdb5e85222ad4
```
**Generate P2 - "Order: Launch a missile!"**
```
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ echo -n 'Order: Launch a missile!' > finalTest.txt
```

**Encrypt P2 and show it in HEX format**
```                                                                       
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ openssl enc -aes-128-cfb -e -p -in finalTest.txt -out finalTest_enc.txt -K 00112233445566778889aabbccddeeff -iv 0102030405060708
hex string is too short, padding with zero bytes to length
salt=4A42E7E61A7F0000
key=00112233445566778889AABBCCDDEEFF
iv =01020304050607080000000000000000

┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ xxd -p finalTest_enc.txt
c8f4eb40b3059a9dceebd17e1d303d4d59ab113ca9f2b307
```

**Updated python script for getting P2**
```python
#!/usr/bin/python3

# XOR two bytearrays
def xor(first, second):
   return bytearray(x^y for x,y in zip(first, second))

MSG = "This is a known message!"
HEX_1 = "d3eee656e156c9f1cebed4731a67324dc90cdb5e85222ad4"
HEX_2 = "c8f4eb40b3059a9dceebd17e1d303d4d59ab113ca9f2b307"

# Convert ascii string to bytearray
D1 = bytes(MSG, 'utf-8')

# Convert hex string to bytearray
D2 = bytearray.fromhex(HEX_1)
D3 = bytearray.fromhex(HEX_2)

r1 = xor(D1, D2)
r2 = xor(r1, D3)
print(r1.hex())
print(r2.hex())
```

**Executing script and converting P2 from HEX format to ASCII**

```
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ python3 sample_code.py                                          
87868f25c13fbad1af9ebf1d75105c6da469a82de4454ff5
4f726465723a204c61756e6368206120fdc2b9114db7fcf2
                                                                                     
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ echo -n "4f726465723a204c61756e6368206120fdc2b9114db7fcf2" | xxd -r -p
Order: Launch a �¹M��� 
```

As observed with **CFB**, the final message is partially revealed: `Order: Launch a �¹M���`.

### Task 6.3

In this task, we want to discover which message Bob sent. This time we don't use the same IV, but we use a predictable IV. We know that Bob's messages can only be "Yes" or "No" and we know which IV Bob used in his message, and what's the next IV to be used. As we're using CBC, we know that using predictable IVs makes the algorithm vulnerable, because it's possible to discover the real plaintext message.

In CBC, the following operations will be performed:
- Plaintext message: `"Yes"`.
- Let `R1` = `"Yes"` ⊕ `IV_1` (Being `IV_1` the current IV).
- The block cipher's input will be `R1`.
- The block cipher's output will be `C1`.

By knowing that the next IV is `IV_2`, then we can cipher another message to test if it was Bob's message. Steps:
- Plaintext message: `"Yes"` ⊕ `IV_1` ⊕ `IV_2` (notice we assume that Bob's messages are either "Yes" or "No").
- Let `R2` = `"Yes"` ⊕ `IV_1` ⊕ `IV_2` ⊕ `IV_2`, which is the same as: `R2` = `"Yes"` ⊕ `IV_1` (`IV_2` ⊕ `IV_2` cancels itself).
- So `R2 = R1`.
- The block cipher's input will be `R2`.
- The block cipher's output will be `C2`.
- So `C2 = C1`.

So, the final ciphertext will be the same. If we instead pick "No" as our guess, the final result would be different, and as we assume that Bob only sends "Yes" or "No". If it's not "No", then it must be "Yes"!

To demonstrate this, we first developed the following python script:

```python
#!/usr/bin/python3

# XOR two bytearrays
def xor(first, second):
   return bytearray(x^y for x,y in zip(first, second))

MSG = "Yes"
IV_1 = "ec96b9bc8c2b28296b0d71e15d6c3d77"
IV_2 = "3565b9c68c2b28296b0d71e15d6c3d77"

# Convert ascii string to bytearray
D1 = bytearray(MSG, encoding='utf-8')
padding = 16 - len(MSG) % 16
D1.extend([padding] * padding)

# Convert hex string to bytearray
D2 = bytearray.fromhex(IV_1)
D3 = bytearray.fromhex(IV_2)

r1 = xor(D1, D2)
r2 = xor(r1, D3)
print(r2.hex())
```

This script grabs the logic explained before and the `MSG` variable holds our bet, which is "Yes". In variable `IV_1` holds the IV that Bob used when ciphering his message. In variable `IV_2` it holds the next IV. What the script does, is the aforementioned operation: `"Yes"` ⊕ `IV_1` ⊕ `IV_2` and outputs it in hexadecimal format. Note that the `MSG` has to be padded to have a size of 16 bytes, as we're using an AES block cipher. So, when the oracle's output is the following:

```
┌──(kali㉿kali)-[~]
└─$ nc 10.9.0.80 3000
Bob's secret message is either "Yes" or "No", without quotations.
Bob's ciphertex: 20a1ffd42b4880f8059b053ac2915691
The IV used    : ec96b9bc8c2b28296b0d71e15d6c3d77

Next IV        : 3565b9c68c2b28296b0d71e15d6c3d77
Your plaintext : 
```

- `IV_1` = `ec96b9bc8c2b28296b0d71e15d6c3d77`
- `IV_2` = `3565b9c68c2b28296b0d71e15d6c3d77`

Running the python script:

```
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ python3 sample_code.py
809673770d0d0d0d0d0d0d0d0d0d0d0d
```

The output holds the hexadecimal format of the plaintext to input to the oracle:

```
┌──(kali㉿kali)-[~]
└─$ nc 10.9.0.80 3000
Bob's secret message is either "Yes" or "No", without quotations.
Bob's ciphertex: 20a1ffd42b4880f8059b053ac2915691
The IV used    : ec96b9bc8c2b28296b0d71e15d6c3d77

Next IV        : 3565b9c68c2b28296b0d71e15d6c3d77
Your plaintext : 809673770d0d0d0d0d0d0d0d0d0d0d0d
Your ciphertext: 20a1ffd42b4880f8059b053ac291569164cacc81d5324748ea9265ec06d69d30

Next IV        : dfbc8b178d2b28296b0d71e15d6c3d77
Your plaintext : 
```

And indeed, our "Yes" prediction was correct. But we still notice something interesting. Only the first 128 bits (16 bytes) of the ciphertext match Bob's ciphertext. This happens because in the case of Bob, the input string to the CBC was "Yes" and that string was padded to have 16 bytes, producing an output of 16 bytes. But as the oracle only allows input in hexadecimal format and, as the plaintext's size is a multiple of 16 bytes, the other 16 bytes are added as padding (PKCS#5), so 2 blocks of ciphertext are produced, being the second full of padding data.

## Task 7

In this task, we want to find the key used for a given ciphertext (`764aa26b55a4da654df6b19e4bce00f4ed05e09346fb0e762583cb7da2ac93a2`). Besides that, we also know the cipher used for the encryption, which is `aes-128-cbc`, the plain text (`This is a top secret.`), and the IV (`aabbccddeeff00998877665544332211`). We developed a C script that is a bruteforcer, and looks up a set of keys in a `words.txt` file and tests it using the previously mentioned cipher. If the ciphertext, using a key is equal to the ciphertext mentioned in the task, then we know that was the key used to cipher the plain text.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 128 bit AES (i.e. a 128 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

void padString(unsigned char* buffer) {
    int size = 16;
    int diff = 16 - strlen(buffer);
    
    if(diff == 0)
        return;
    
    memset(buffer + strlen(buffer), '#', diff);
}

int main (void)
{

    /* A 128 bit IV */
    unsigned char iv[] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };
    unsigned char correct_ciphertext[32] = { 0x76, 0x4a, 0xa2, 0x6b, 0x55, 0xa4, 0xda, 0x65, 0x4d, 0xf6, 0xb1, 0x9e, 0x4b, 0xce, 0x00, 0xf4, 0xed, 0x05, 0xe0, 0x93, 0x46, 0xfb, 0x0e, 0x76, 0x25, 0x83, 0xcb, 0x7d, 0xa2, 0xac, 0x93, 0xa2 };
    /* Message to be encrypted */
    unsigned char *plaintext =
        (unsigned char *)"This is a top secret.";

    /*
     * Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     */
    unsigned char ciphertext[128];

    int ciphertext_len;

    /* Encrypt the plaintext */
    const size_t BUF_SIZE = 16;
    unsigned char buffer[BUF_SIZE];
    FILE* in;
    in = fopen("words.txt", "r");

    while(fgets(buffer, BUF_SIZE, in)) {
        buffer[strcspn(buffer, "\n")] = 0;
        padString(buffer);

        ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), buffer, iv,
                              ciphertext);

        if(strcmp(ciphertext, correct_ciphertext) == 0) {
            memset(ciphertext, 0, sizeof(ciphertext));
            printf("Found Key: %s\n", buffer);
        }
    }
    fclose(in);
    return 0;
}
```

In this case, the key found was `Syracuse########`, as shown when running the program:

```
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ gcc -o task7 task7.c -lcrypto
                                                                                     
┌──(kali㉿kali)-[~/…/category-crypto/Crypto_Encryption/Labsetup/Files]
└─$ ./task7                      
Found Key: Syracuse########
```