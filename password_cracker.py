#!/usr/bin/env python3
import threading
import time
import argparse
import sys
import hashlib
from concurrent.futures.thread import ThreadPoolExecutor
from concurrent.futures import as_completed

MAX_SALT_INT = 100000
MAX_THREADS = None;
VERBOSITY = 0

WORDLIST = None

HASH_GUESSES = {
    128: hashlib.sha512,
    96: hashlib.sha384,
    64: hashlib.sha256,
    56: hashlib.sha224,
    40: hashlib.sha1,
    32: hashlib.md5
}


def v_print(level, *msg) -> None:
    """
    prints message is VERBOSITY is high enough

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
    hashes password to math credential hash

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



def crack(credential:dict) -> dict:
    """
    returns password or None on failure

    Args:
        credential: an item from the pased shadowfile list

    Returns:
            list of file lines
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

    v_print(2, "{user} normal password check failed. attempting salts"
        .format(**credential))

    v_print(2, "attempting cracking with salts for user:{user}"
            .format(**credential))

    word_index = 0
    while word_index < WORDLIST_LENGTH:
        salt_list = salted_password_generator(WORDLIST[word_index])
        for password in salt_list:
            v_print(3, "user:{0},attempted_password: {1}"
                .format(credential["user"], password))
            attempt = hash_attempt(password, credential)
            if attempt["result"]:
                v_print(2, "cracked {user}:{password}".format(**attempt))
                return attempt

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
                print('generated an exception: %s' % (exc))

    return completed_results


def salted_password_generator(password):
    """
    returns generator for salted password

    Args:
        password: what the salt is appended to

    Returns:
        generetor
    """
    num = 0
    while num < MAX_SALT_INT:
        yield f'{password}{num:05}'
        num+=1


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
        help="verbosity",
        action='count',
        default=0,
        required=False)
    args = parser.parse_args()

    VERBOSITY = args.verbose
    MAX_THREADS = args.threadcount
    WORDLIST = read_input_file(args.wordlist)
    WORDLIST_LENGTH = len(WORDLIST)
    shadow_list = read_input_file(args.shadowfile)

    v_print(1,"VERBOSITY: {0}".format(VERBOSITY))
    # parse shadow

    v_print(1, "attempting unmodified wordlist\n")
    credentials = [{"user": shadow.split(":")[0], "hash": shadow.split(":")[1],
        "algo": algo_heuristics(shadow.split(":")[1])}
        for shadow in shadow_list]

    results = crack_users(credentials)
    # results = [crack(credential, default_wordlist,
    #     args.threadcount) for credential in credentials]
    #
    successful_results = [result for result in results if result["result"]]
    failing_results = [result for result in results if not result["result"]]
    #
    # for credential in successful_results:
    #     v_print(1, "successfully cracked {user}:{password}"
    #         .format(**credential))
    #
    # v_print(2, "attempting cracking with salts")
    # #attemp salted hashes
    # for credential in failing_results:
    #     v_print(2, "attempting cracking with salts for user:{user}"
    #         .format(**credential))
    #     word_index = 0
    #     while word_index < default_wordlist_length:
    #         salt_list = salted_password_generator(default_wordlist[word_index])
    #         attempt = crack(credential, salt_list, args.threadcount)
    #         if attempt["result"]:
    #             successful_results.append(attempt)
    #             word_index = default_wordlist_length
    #         word_index +=1

    sort_credentials = lambda credential: credential["user"]

    successful_results.sort(key=sort_credentials)
    with open(args.output, 'w') as file:
        for credential in successful_results:
            file.write("{user}:{password}\n".format(**credential))
