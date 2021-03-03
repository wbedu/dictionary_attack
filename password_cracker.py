#!/usr/bin/env python3
import threading
import time
import argparse
import sys
import hashlib
from concurrent.futures.thread import ThreadPoolExecutor
from concurrent.futures import as_completed

MAX_SALT_INT = 100000

HASH_GUESSES = {
    128: hashlib.sha512,
    96: hashlib.sha384,
    64: hashlib.sha256,
    56: hashlib.sha224,
    40: hashlib.sha1,
    32: hashlib.md5,
}

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



def crack(credential:dict, wordlist:list, max_threads:int) -> dict:
    """
    returns password or None on failure

    Args:
        credential: an item from the pased shadowfile list

    Returns:
            list of file lines
    """
    match = {
        **credential,
        "result": False
    }

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(hash_attempt, password, credential)
            for password in wordlist}
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
    args = parser.parse_args()

    default_wordlist = read_input_file(args.wordlist)
    default_wordlist_length = len(default_wordlist)
    shadow_list = read_input_file(args.shadowfile)

    # parse shadow
    credentials = [{"user": shadow.split(":")[0], "hash": shadow.split(":")[1],
        "algo": algo_heuristics(shadow.split(":")[1])}
        for shadow in shadow_list]

    results = [crack(credential, default_wordlist,
        args.threadcount) for credential in credentials]

    successful_results = [result for result in results if result["result"]]
    failing_results = [result for result in results if not result["result"]]
    for result in successful_results:
        print(result)

    #attemp salted hashes
    for credential in failing_results:
        print("attempt {user}".format(**credential))
        word_index = 0
        while word_index < default_wordlist_length:
            print("attempting wordlist with word {0}"
                .format(word_index))
            salt_list = salted_password_generator(default_wordlist[word_index])
            attempt = crack(credential, salt_list, args.threadcount)
            if attempt["result"]:
                successful_results.append(attempt)
                word_index = default_wordlist_length
            word_index +=1

    sort_credentials = lambda credential: credential["user"]

    successful_results.sort(key=sort_credentials)
    with open(args.output, 'w') as file:
        credential_lines =[ "{user}:{password}\n".format(**credential)
            for credential in successful_results]
        credential_lines[-1] = credential_lines[-1].split("\n")[0]

        file.writelines(credential_lines)
