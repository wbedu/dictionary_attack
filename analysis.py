#!/usr/bin/env python3
import string
import itertools
from password_cracker import read_input_file



ACCEPTANCE_CRITERIA = 0.75
SOURCE_MAPPING = None
DICTIONARY = None

def set_sub(c0, c1, mappings):
    mappings[c0] = c1
    mappings[c1] = c0
    return mappings


if __name__ == "__main__":

    #load default list of words in linux os
    DICTIONARY = read_input_file("/usr/share/dict/words")

    # map letters to themselves
    SOURCE_MAPPING = {letter:letter for letter in string.ascii_lowercase}
    tes = list(itertools.product(string.ascii_lowercase, repeat=1))
    for s in tes:
        print(tes)

    print(len(tes))
