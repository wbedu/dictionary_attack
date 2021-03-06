step one was figuring out what algorithm was used to hash each password.
I used the length of the hashes for this. If the hash is of length 128
then it was probably hashed with sha512 and so on. then I hashed each word in
the dictionary with that algorithm until I got a match. the word that matched is
the password for that user. If that failed, I tried ceasar cipher

```python3
HASH_GUESSES = {
    128: hashlib.sha512,
    96: hashlib.sha384,
    64: hashlib.sha256,
    56: hashlib.sha224,
    40: hashlib.sha1,
    32: hashlib.md5
}
```
For the ceasar cipher, for each password I shifted each character by 1 to 25 for
all the words in that list until i got a match or moved on to the next word.

for leet speak i created a dictionary for possible transformations for each
letter some letters have multiple mappings. In that case, i branch off on each
possible mapping for a word. in case some letters aren't in leet, i added the
possibility for an unmodified word at the expense for more comparisons.
online resources used: https://en.wikipedia.org/wiki/Leet

```python3
LEET_MAPPINGS = {
    "a": ["a","4"],
    "b": ["b","6","8","13","18"],
    "f": ["f","7"],
    "e": ["e","3"],
    "g": ["g","6"],
    "h": ["h","4"],
    "i": ["i","1","9"],
    "j": ["j","9"],
    "l": ["l","1"],
    "m": ["m","44"],
    "o": ["0"],
    "q": ["q","9"],
    "r": ["r","12"],
    "s": ["s","5"],
    "t": ["t","7"],
    "z": ["z","2","5"]
}
```
For the salted passwords I appended numbers [00000 to 99999] to the end of the
words until i got a match or moved on to the next word


optimizations:
  1 thread per each user
  ** I would have split the work load for the salted hash into multiple threads
      but I left that task for after i finished cracking user7
