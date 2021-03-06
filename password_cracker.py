#!/usr/bin/env python3
import threading
import time
import argparse
import sys
import hashlib
import string
from math import floor
from concurrent.futures.thread import ThreadPoolExecutor
from concurrent.futures import as_completed

MAX_SALT_INT = 100000
MAX_THREADS = None
VERBOSITY = 0
MAX_PASSWORD_LENGTH = 12
WORDLIST = None

HASH_GUESSES = {
    128: hashlib.sha512,
    96: hashlib.sha384,
    64: hashlib.sha256,
    56: hashlib.sha224,
    40: hashlib.sha1,
    32: hashlib.md5
}

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


def v_print(level, *msg) -> None:
    """
    prints message if VERBOSITY is high enough

    Args:
        level: minimum level for message to print
        msg: message list

    Returns:
        None
    """
    if(VERBOSITY >= level):
        print(*msg)


def algo_heuristics(hashed_password:str) -> dict:
    """
    returns best guess of algorithim used
            to hash function based on hash length
            or None on failure

    Args:
        hashed_password: the password hash

    Returns:
        function that might have been used to hash the password
    """
    hash_len = len(hashed_password)
    try:
        guess = HASH_GUESSES[hash_len]
    except:
        print("Error this hash({hashed_password}) is not supported"
            .format(hashed_password), file=sys.stderr)
        return None

    return guess


def thread_compute(credential_count:int, thread_count:int ) -> tuple:
    """
    determins what number of threads should be dedicated to users and to
    each wordlist partition

    Args:
        credential_count: number of credentials that need to be cracked
        thread_count: number of threads available

    Returns:
        tuble (threads for credential, threads per partition)
    """

    cred_threads = thread_count / credential_count
    if(cred_threads > 2):
        return (thread_count, 1)
    else:
        count = floor(thread_count / credential_count)
        return (count+1, count)

def read_input_file(filename:str) -> list:
    """
    reads file returns list of file lines

    Args:
        filename: file path

    Returns:
        list of file lines
    """
    try:
        with open(filename) as file:
            content = file.read().splitlines()
    except:
        print("Error opening {0}".format(filename), file=sys.stderr)
        exit(4)
    return content


def hash_attempt(password, credential) -> dict:
    """
    hashes password to match credential hash

    Args:
        filename: file path

    Returns:
        dict of credential information dict.result True on success False on fail
    """
    return {
        **credential,
        "result": credential["algo"](password.encode('utf-8')).hexdigest()
            == credential["hash"],
        "password": password
    }


def position_if_exists(entry, list):
    """
    locates first occurange of an element in a list and it's index

    Args:

        list: password that will be shifted

    Returns:
            generator
    """
    pos = [i for i,x in enumerate(string.ascii_lowercase)
        if x == entry]
    if len(pos):
        return (True, pos[0])
    else:
        return (False, None)


def leet_transforms(password_char:str):
    """
    returns posible leet transformations

    Args:
        password_char: character being transformed

    Returns:
        list of possible transforms if valid, else return char
    """
    if(password_char in LEET_MAPPINGS):
        sub_list = LEET_MAPPINGS[password_char]
        return LEET_MAPPINGS[password_char]
    else:
        return [password_char]


def leet_translations(password:str):
    """
    returns generator returns possible leet translations

    Args:
        password: password that will be transformed

    Returns:
        generator of possible leet transforms
    """

    res = [[]]
    password_length = len(password)
    for c in password:
        sub_list = leet_transforms(c)
        new_res = []
        for new_c in sub_list:
            for partial in res:
                shallow_partial_copy = partial[:]
                shallow_partial_copy.append(new_c)
                new_res.append(shallow_partial_copy)
        del res
        res = new_res
    return ["".join(transformed) for transformed in res]


def ceasar_shift_generator(password:str):
    """
    returns generator for ceasar shifted passwords

    Args:
        password: password that will be shifted

    Returns:
        generator
    """

    shift = 1
    while shift < 26:
        res = []
        for c in password:
            is_lower, low_index = position_if_exists(c, string.ascii_lowercase)
            is_upper, up_index = position_if_exists(c, string.ascii_uppercase)

            if is_lower:
                new_index = (low_index + shift)%26
                res.append(string.ascii_lowercase[new_index])
            elif is_upper:
                new_index = (up_index + shift)%26
                res.append(string.ascii_uppercase[new_index])
            else:
                res.append(c)
        shift += 1
        yield "".join(res)


def salted_generator(password):
    """
    returns generator for salted password

    Args:
        password: what the salt is appended to

    Returns:
        generetor
    """

    for num in range(0, MAX_SALT_INT):
        yield f'{password}{num:05}'


def crack_with_generator(credential:dict, generator):
    """
    runs a crack with a generator function passed

    Args:
        credential: an item from the passed shadowfile list

    Returns:
        dict credential results
    """
    for word in WORDLIST:
        gens = generator(word)
        for password in gens:
            v_print(3, "user:{0},attempted_password: {1}"
                .format(credential["user"], password))
            attempt = hash_attempt(password, credential)
            if attempt["result"]:

                v_print(2, "cracked {user}:{password}".format(**attempt))

                return {
                **attempt,
                "pre_hash": word
                }
    return None


def normal_crack(credential:dict):
    """
    runs normal crack with unmodified passwords

    Args:
        credential: an item from the pased shadowfile list

    Returns:
        dict credential results
    """
    v_print(1, "normal search for password for {user}".format(**credential))
    for password in WORDLIST:
        attempt = hash_attempt(password, credential)
        v_print(3, "user:{user},attempted_password: {password}"
            .format(**attempt))
        if attempt["result"]:
            v_print(2, "cracked {user}:{password}".format(**attempt))
            return attempt
        del attempt
    return None


def crack(credential:dict) -> dict:
    """
    returns password or None on failure

    Args:
        credential: an item from the pased shadowfile list

    Returns:
        list of file lines
    """

    # normal attempt
    normal_attempt = normal_crack(credential)
    if normal_attempt:
        return normal_attempt
    v_print(2, "{user} normal password check failed".format(**credential))

    # leet speak attempt
    v_print(2, "attempting cracking with leet speak for user:{user}"
            .format(**credential))
    leet_attempt = crack_with_generator(credential, leet_translations)
    if leet_attempt:
        return {
        **leet_attempt,
        "password": leet_attempt["pre_hash"]
        }
    v_print(2, "{user} leet speak check failed".format(**credential))

    # ## ceasar shift attempt
    v_print(2, "attempting cracking with ceasar shift for user:{user}"
            .format(**credential))
    ceasar_attempt = crack_with_generator(credential, ceasar_shift_generator)
    if ceasar_attempt:
        return {
        **ceasar_attempt,
        "password": ceasar_attempt["pre_hash"]
        }
    v_print(2, "{user} ceasar shift check failed".format(**credential))

    # salt attempt
    v_print(2, "attempting cracking with salt for user:{user}"
            .format(**credential))
    salt_attempt = crack_with_generator(credential, salted_generator)
    if salt_attempt:
        return {
        **salt_attempt,
        "password": salt_attempt["pre_hash"]
        }
    v_print(2, "{user} all attempts failed".format(**credential))

    return {
        **credential,
        "result": False
    }


def crack_users(credentials:list) -> list:
    """
    returns password or None on failure

    Args:
        credential: an item from the pased shadowfile list

    Returns:
        list of file lines
    """

    completed_results = []

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(crack, credential)
            for credential in credentials}
        for future in as_completed(futures):
            try:
                result = future.result()
                completed_results.append(result)
            except Exception as exc:
                print(f'generated an exception: {exc}')

    return completed_results


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--shadowfile",
        help="Shadow file path",
        required=True)
    parser.add_argument("-w", "--wordlist",
        help="wordlist file path",
        required=True)
    parser.add_argument("-o", "--output",
        help="output file (default=passwords.txt)",
        default="passwords.txt",
        type=str,
        required=False)
    parser.add_argument("-t", "--threadcount",
        help="thread count (default=4)",
        default=4,
        type=int,
        required=False)
    parser.add_argument("-v","--verbose",
        help="verbosity level (-vvvv is level 4)",
        action='count',
        default=0,
        required=False)
    args = parser.parse_args()

    VERBOSITY = args.verbose
    MAX_THREADS = args.threadcount
    WORDLIST = [word for word in read_input_file(args.wordlist)
        if MAX_PASSWORD_LENGTH >=12]
    WORDLIST_LENGTH = len(WORDLIST)
    shadow_list = read_input_file(args.shadowfile)

    v_print(1,f"VERBOSITY: {VERBOSITY}")
    # parse shadow

    v_print(1, "attempting unmodified wordlist\n")
    credentials = [{"user": shadow.split(":")[0], "hash": shadow.split(":")[1],
        "algo": algo_heuristics(shadow.split(":")[1])}
        for shadow in shadow_list]

    results = crack_users(credentials)
    successful_results = [result for result in results if result["result"]]
    failing_results = [result for result in results if not result["result"]]

    sort_credentials = lambda credential: credential["user"]

    successful_results.sort(key=sort_credentials)
    with open(args.output, 'w') as file:
        for credential in successful_results:
            file.write("{user}:{password}\n".format(**credential))
