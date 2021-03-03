#!/usr/bin/env python3
import threading
import time
import argparse
import sys
import hashlib
from concurrent.futures.thread import ThreadPoolExecutor
from concurrent.futures import as_completed
HASH_GUESSES = {
    128: hashlib.sha512,
    96: hashlib.sha384,
    64: hashlib.sha256,
    56: hashlib.sha224,
    40: hashlib.sha1,
    32: hashlib.md5,
}

DICTIONARY = None

def algo_heuristics(hashed_password:str):
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
        print("")
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


def hash_attempt(password, credential):
    return {
        "result": credential["algo"](password.encode('utf-8')).hexdigest()
            == credential["hash"],
        "hash": credential["hash"],
        "password": password
    }

def crack(credential:dict, max_threads:int):
    """
    returns password or None on failure

    Args:
        credential: an item from the pased shadowfile list

    Returns:
            list of file lines
    """

    print("attempt {user}".format(**credential))
    match = {
        "result": False,
        "hash": credential["hash"],
        "password": None
    }

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(hash_attempt, password, credential)
            for password in DICTIONARY}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result["result"]:
                    match = result
                    executor.shutdown(wait=True)
                else:
                    del result
            except Exception as exc:
                print('generated an exception: %s' % (exc))

    return match

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--shadowfile",
        help="Shadow file path",
        required=True)
    parser.add_argument("-w", "--wordlist",
        help="wordlist file path",
        required=True)
    parser.add_argument("-t", "--threadcount",
        help="thread count (default=4)",
        default=4,
        required=False)
    args = parser.parse_args()

    DICTIONARY = read_input_file(args.wordlist)
    shadow_list = read_input_file(args.shadowfile)

    # parse shadow
    credentials = [{"user": shadow.split(":")[0], "hash": shadow.split(":")[1],
        "algo": algo_heuristics(shadow.split(":")[1])}
        for shadow in shadow_list]

    results = [crack(credential, args.threadcount) for credential in credentials]

    for result in results:
        print(result)
