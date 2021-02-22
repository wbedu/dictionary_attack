#!/usr/bin/env python3
import argparse
import sys


def read_input_file(filename:str):
    """reads file returns list of file lines

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
        exit()
    return content



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--shadowfile",
        help="Shadow file path",
        required=True)
    parser.add_argument("-w", "--wordlist",
        help="wordlist file path",
        required=True)
    parser.add_argument("-t", "--treadcount",
        help="wordlist file path",
        default=4,
        required=False)
    args = parser.parse_args()

    dictionary = read_input_file(args.wordlist)
    shadow = read_input_file(args.shadowfile)
